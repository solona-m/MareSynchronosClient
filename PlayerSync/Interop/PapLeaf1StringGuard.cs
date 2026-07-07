using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Dalamud.Utility.Signatures;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;

namespace MareSynchronos.Interop;

public sealed partial class PapLeaf1StringGuard : IHostedService, IDisposable
{
    [LibraryImport("Kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool IsBadReadPtr(nint address, nint length);

    private delegate nint Leaf1Delegate(nint table, nint cstr);

    [Signature("40 53 48 83 EC 20 83 79 50 00 48 8B D9 0F 84 C8 00 00 00 83 79 38 00 0F")]
    private readonly nint _entryAddr;

    private readonly Hook<Leaf1Delegate>? _leaf1Hook;
    private readonly ILogger<PapLeaf1StringGuard> _logger;
    private readonly nint _pinnedEmptyString;
    private long _caughtCount;

    public PapLeaf1StringGuard(ILogger<PapLeaf1StringGuard> logger, IGameInteropProvider gameInterop)
    {
        _logger = logger;
        _pinnedEmptyString = Marshal.AllocHGlobal(1);
        Marshal.WriteByte(_pinnedEmptyString, 0);

        try
        {
            gameInterop.InitializeFromAttributes(this);
            nint mid1 = FollowCall(_entryAddr + 0x76);
            nint mid2 = FollowCall(mid1 + 0x16);
            nint leaf1 = FollowCall(mid2 + 0x21);
            _leaf1Hook = gameInterop.HookFromAddress<Leaf1Delegate>(leaf1, Leaf1Detour);
            _logger.LogWarning("PapLeaf1StringGuard: resolved leaf-1 at 0x{addr:X} via call-chain from unique entry 0x{entry:X}; hook installed.", leaf1, _entryAddr);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PapLeaf1StringGuard: resolution failed (game patch?); INACTIVE.");
        }
    }

    private static nint FollowCall(nint callSiteAddr)
    {
        byte opcode = Marshal.ReadByte(callSiteAddr);
        if (opcode != 0xE8)
            throw new InvalidOperationException($"Expected E8 (call rel32) at 0x{callSiteAddr:X}, found 0x{opcode:X2} — game patch?");
        int rel32 = Marshal.ReadInt32(callSiteAddr + 1);
        return callSiteAddr + 5 + rel32;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _leaf1Hook?.Enable();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _leaf1Hook?.Disable();
        if (_caughtCount > 0)
            _logger.LogWarning("PapLeaf1StringGuard: caught {count} corrupt string-table read(s) this session — each one would plausibly have crashed without this guard.", _caughtCount);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _leaf1Hook?.Dispose();
        if (_pinnedEmptyString != nint.Zero) Marshal.FreeHGlobal(_pinnedEmptyString);
    }

    private nint Leaf1Detour(nint table, nint cstr)
    {
        if (cstr == nint.Zero || IsBadReadPtr(cstr, 1))
        {
            long n = Interlocked.Increment(ref _caughtCount);
            _logger.LogWarning("PapLeaf1StringGuard: [CAUGHT] corrupt string pointer 0x{cstr:X} in table 0x{table:X} — substituting empty string (count: {n}).",
                cstr, table, n);
            return _leaf1Hook!.Original(table, _pinnedEmptyString);
        }
        return _leaf1Hook!.Original(table, cstr);
    }
}
