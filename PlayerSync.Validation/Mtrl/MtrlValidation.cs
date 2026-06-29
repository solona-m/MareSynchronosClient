using Lumina.Excel;
using System;
using System.Collections.Generic;
using System.IO;

namespace PlayerSync.Validation.Mtrl;

/// <summary>
/// Structural validation for FFXIV material (.mtrl) files.
/// </summary>
/// <remarks>
/// MTRL header layout (16 bytes):
///   0x00 uint32  version
///   0x04 uint16  file size
///   0x06 uint16  dataSize  — color table + dye table bytes
///   0x08 uint16  stringSize
///   0x0A uint16  shaderOffset
///   0x0C uint8   textureCount
///   0x0D uint8   uvSetCount
///   0x0E uint8   colorSetCount
///   0x0F uint8   extraDataSize
/// After header: (textureCount + uvSetCount + colorSetCount) × 4-byte descriptors,
/// then stringSize bytes of strings, 4-byte alignment padding, extraDataSize bytes,
/// then dataSize bytes of color table data.
/// PrepareColorTable does a memcpy of exactly dataSize bytes from the computed table
/// start — if that region exceeds the file, the source pointer is unmapped and the
/// game crashes immediately.
/// </remarks>
public static class MtrlValidation
{
    private const int HeaderSize = 0x10;
    private const int DescriptorEntrySize = 4;

    // Maximum plausible color table + dye table: extended color (2048) + extended dye (128) = 2176.
    // Anything larger is corrupt data.
    private const int MaxDataSize = 4096;

    public static readonly ValidationMessage MTRL000A = new ValidationMessage(nameof(MTRL000A), "MTRL file too small", "The material file is too small to contain a valid header.", MessageLevel.Crash);
    public static readonly ValidationMessage MTRL001A = new ValidationMessage(nameof(MTRL001A), "MTRL color table out of bounds", "The material file's color table extends beyond the end of the file and will crash the game.", MessageLevel.Crash);
    public static readonly ValidationMessage MTRL001B = new ValidationMessage(nameof(MTRL001B), "MTRL color table implausibly large", "The material file declares a color table larger than any valid MTRL can contain.", MessageLevel.Crash);

    public static IEnumerable<ValidationMessage> ValidateMtrlFile(ExcelModule excelModule, byte[] fileData, Func<string, bool>? validatePath)
    {
        var messages = new List<ValidationMessage>();

        if (fileData.Length < HeaderSize)
        {
            messages.Add(MTRL000A);
            return messages;
        }

        using var stream = new MemoryStream(fileData);
        using var reader = new BinaryReader(stream);

        reader.ReadUInt32(); // version
        reader.ReadUInt16(); // file size (not reliable — game ignores it)
        var dataSize = reader.ReadUInt16();
        var stringSize = reader.ReadUInt16();
        reader.ReadUInt16(); // shader offset
        var textureCount = reader.ReadByte();
        var uvSetCount = reader.ReadByte();
        var colorSetCount = reader.ReadByte();
        var extraDataSize = reader.ReadByte();

        if (dataSize > MaxDataSize)
        {
            messages.Add(MTRL001B);
            return messages;
        }

        // Compute the position where color table data starts:
        //   header + descriptors + string table + 4-byte alignment padding + extra data
        long descriptorsEnd = HeaderSize + (long)(textureCount + uvSetCount + colorSetCount) * DescriptorEntrySize;
        long stringsEnd = descriptorsEnd + stringSize;
        long afterPadding = (stringsEnd + 3) & ~3L;
        long dataStart = afterPadding + extraDataSize;
        long dataEnd = dataStart + dataSize;

        if (dataEnd > fileData.Length)
        {
            messages.Add(MTRL001A);
        }

        return messages;
    }
}
