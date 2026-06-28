using Lumina.Excel;
using PlayerSync.Validation.Tmb;
using System;
using System.Collections.Generic;
using System.IO;

namespace PlayerSync.Validation.Pap;

/// <summary>
/// Static, game-independent structural validation for FFXIV animation (.pap) files.
/// </summary>
/// <remarks>
/// A .pap file is laid out as:
///   0x00 int32  magic ("pap ")
///   0x04 int32  version
///   0x08 int16  number of animations
///   0x0A int16  model id
///   0x0C byte   skeleton type (0 = human)
///   0x0D byte   variant
///   0x0E int32  info offset
///   0x12 int32  havok data offset (from start of file)
///   0x16 int32  footer/timeline offset (from start of file)
///   0x1A ...    per-animation info blocks
///   havok offset .. footer offset: embedded Havok (.hkx) data
///   footer offset .. EOF: one embedded TMB timeline per animation
/// The header parse mirrors <c>XivDataAnalyzer.GetBoneIndicesFromPap</c> and the embedded
/// layout mirrors VfxEditor's <c>PapFile</c>. Only checks that do not require the running
/// game live here; the live Havok bone-index check stays in the main PlayerSync project.
/// </remarks>
public static class PapValidation
{
    /// <summary>
    /// The sequence of starting bytes that identify a PAP file ("pap ").
    /// </summary>
    public const uint PapMagic = 0x20706170;

    /// <summary>Size of the fixed .pap header, in bytes (animation info blocks start here).</summary>
    private const int HeaderSize = 0x1A;

    public static readonly ValidationMessage PAP000A = new ValidationMessage(nameof(PAP000A), "PAP file invalid", "The PAP file is too small or its header could not be read.", MessageLevel.Crash);
    public static readonly ValidationMessage PAP001A = new ValidationMessage(nameof(PAP001A), "PAP bad magic", "The PAP file does not start with the expected 'pap ' magic bytes.", MessageLevel.Crash);
    public static readonly ValidationMessage PAP001B = new ValidationMessage(nameof(PAP001B), "PAP animation count invalid", "The PAP file declares a negative or implausible number of animations.", MessageLevel.Crash);
    public static readonly ValidationMessage PAP002A = new ValidationMessage(nameof(PAP002A), "PAP offsets invalid", "The PAP file's Havok/footer offsets are out of bounds or out of order, which can crash the game.", MessageLevel.Crash);
    public static readonly ValidationMessage PAP002B = new ValidationMessage(nameof(PAP002B), "PAP havok data missing", "The PAP file has no usable embedded Havok animation data.", MessageLevel.Warning);
    public static readonly ValidationMessage PAP003A = new ValidationMessage(nameof(PAP003A), "PAP embedded TMB invalid", "An embedded TMB timeline in the PAP file could not be located or read.", MessageLevel.Warning);

    /// <summary>
    /// Checks the given .pap file for structural problems and validates each embedded TMB timeline.
    /// </summary>
    /// <param name="excelModule">Game Excel data, used by embedded-TMB validation.</param>
    /// <param name="fileData">The contents of the .pap file.</param>
    /// <param name="validatePath">A callback used to determine whether a given game path exists.</param>
    public static IEnumerable<ValidationMessage> ValidatePapFile(ExcelModule excelModule, byte[] fileData, Func<string, bool>? validatePath)
    {
        var messages = new List<ValidationMessage>();

        if (fileData.Length < HeaderSize)
        {
            messages.Add(PAP000A);
            return messages;
        }

        using var stream = new MemoryStream(fileData);
        using var reader = new BinaryReader(stream);

        uint magic = reader.ReadUInt32();
        if (magic != PapMagic)
        {
            messages.Add(PAP001A);
            return messages;
        }

        reader.ReadInt32(); // version
        short numAnimations = reader.ReadInt16();
        reader.ReadInt16(); // model id
        reader.ReadByte();  // skeleton type
        reader.ReadByte();  // variant
        reader.ReadInt32(); // info offset
        int havokPosition = reader.ReadInt32();
        int footerPosition = reader.ReadInt32();

        // Havok block must sit after the header, the footer must sit after the havok block,
        // and the footer must lie within the file. Anything else is malformed and can crash.
        if (havokPosition < HeaderSize || havokPosition > fileData.Length
            || footerPosition < havokPosition || footerPosition > fileData.Length)
        {
            messages.Add(PAP002A);
            return messages;
        }

        // The per-animation info blocks live between the header and the Havok block. A negative
        // count, or one too large to fit even minimal (~37 byte) info blocks there, means corruption.
        if (numAnimations < 0 || (long)HeaderSize + (long)numAnimations * 37 > havokPosition)
        {
            messages.Add(PAP001B);
            return messages;
        }

        if (footerPosition - havokPosition <= 8)
        {
            messages.Add(PAP002B);
        }

        // Walk the embedded TMB timelines (one per animation, starting at the footer offset) and
        // reuse the existing TMB validator. The same crash-causing path entries that TmbValidation
        // catches in standalone .tmb files also live inside these embedded timelines.
        if (numAnimations > 0 && footerPosition < fileData.Length)
        {
            int customOffset = footerPosition % 4;
            int position = footerPosition;

            for (int i = 0; i < numAnimations; i++)
            {
                // Each embedded TMB begins with a TMLB magic + an int32 size covering the whole timeline.
                if (position + 8 > fileData.Length)
                {
                    messages.Add(PAP003A);
                    break;
                }

                uint tmbMagic = BitConverter.ToUInt32(fileData, position);
                int tmbSize = BitConverter.ToInt32(fileData, position + 4);

                if (tmbMagic != TmbValidation.TmbMagic || tmbSize <= 0 || position + tmbSize > fileData.Length)
                {
                    messages.Add(PAP003A);
                    break;
                }

                var tmbBytes = new byte[tmbSize];
                Array.Copy(fileData, position, tmbBytes, 0, tmbSize);
                try
                {
                    foreach (var msg in TmbValidation.ValidateTmbFile(excelModule, tmbBytes, validatePath))
                    {
                        // Embedded TMB issues are informational only — they don't block the PAP.
                        messages.Add(msg.Level == MessageLevel.Crash
                            ? msg with { Level = MessageLevel.Warning }
                            : msg);
                    }
                }
                catch (Exception)
                {
                    // Defensive: TMB parsing can throw if VfxEditor static state is unavailable (e.g. outside the game).
                    messages.Add(PAP003A);
                }

                position += tmbSize;
                position += Padding(position, i, numAnimations, customOffset);
            }
        }

        return messages;
    }

    /// <summary>
    /// Computes the inter-timeline padding used by the PAP footer, mirroring VfxEditor's PapFile.
    /// The last timeline is not padded.
    /// </summary>
    private static int Padding(long position, int itemIdx, int numItems, int customOffset)
    {
        if (numItems > 1 && itemIdx < numItems - 1)
        {
            var leftOver = (position - customOffset) % 4;
            return (int)(leftOver == 0 ? 0 : 4 - leftOver);
        }
        return 0;
    }
}
