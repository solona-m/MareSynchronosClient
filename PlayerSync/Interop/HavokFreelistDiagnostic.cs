using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Dalamud.Utility.Signatures;
using MareSynchronos.MareConfiguration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MareSynchronos.Interop;

public sealed class HavokFreelistDiagnostic : IHostedService, IDisposable
{
    private delegate nint FreelistPopDelegate(nint self, int size);
    private delegate void FreelistPushDelegate(nint self, nint ptr, int size);

    [Signature("4C 8B C1 81 FA 00 20 00 00 7F 56 81 FA 80 02 00 00 7F 14 8D 42 0F")]
    private readonly nint _popAddr;

    [Signature("4C 8B C9 48 85 D2 74 7E 41 81 F8 00 20 00 00 7F 6A 41 81 F8 80 02 00 00")]
    private readonly nint _pushAddr;

    private readonly Hook<FreelistPopDelegate>? _popHook;
    private readonly Hook<FreelistPushDelegate>? _pushHook;
    private readonly ILogger<HavokFreelistDiagnostic> _logger;
    private readonly MareConfigService _configService;

    private long _loggedCount;
    private const long MaxLogged = 5000;

    public HavokFreelistDiagnostic(ILogger<HavokFreelistDiagnostic> logger, IGameInteropProvider gameInterop, MareConfigService configService)
    {
        _logger = logger;
        _configService = configService;
        if (!_configService.Current.EnableHavokFreelistDiagnostic) return;

        try
        {
            gameInterop.InitializeFromAttributes(this);
            _popHook = gameInterop.HookFromAddress<FreelistPopDelegate>(_popAddr, PopDetour);
            _pushHook = gameInterop.HookFromAddress<FreelistPushDelegate>(_pushAddr, PushDetour);
            _logger.LogWarning("HavokFreelistDiagnostic: hooks resolved, freelist pop/push address logging active (96-256B band).");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "HavokFreelistDiagnostic: signature scan failed (game patch?); INACTIVE.");
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _popHook?.Enable();
        _pushHook?.Enable();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _popHook?.Disable();
        _pushHook?.Disable();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _popHook?.Dispose();
        _pushHook?.Dispose();
    }

    private nint PopDetour(nint self, int size)
    {
        nint result = _popHook!.Original(self, size);
        LogBucket("POP", self, size, result);
        return result;
    }

    private void PushDetour(nint self, nint ptr, int size)
    {
        LogBucket("PUSH", self, size, ptr);
        _pushHook!.Original(self, ptr, size);
    }

    private void LogBucket(string label, nint self, int size, nint ptr)
    {
        if (size < 96 || size > 256) return;
        if (Interlocked.Increment(ref _loggedCount) > MaxLogged) return;

        int bucketIdx = size <= 0x280 ? (size + 0xF) >> 4 : -1;

        _logger.LogDebug("HavokFreelistDiagnostic: [{label}] self=0x{self:X} size={size} bucketIdx={idx} ptr=0x{ptr:X}",
            label, self, size, bucketIdx, ptr);
    }
}
