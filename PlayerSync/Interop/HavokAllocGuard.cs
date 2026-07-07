using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Dalamud.Utility.Signatures;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace MareSynchronos.Interop;

public sealed class HavokAllocGuard : IHostedService, IDisposable
{
    private delegate nint HkLoaderLoad1Delegate(nint self, nint arg2, nint arg3, nint arg4);
    private delegate nint HkLoaderDtorDelegate(nint self, nint mode);

    // hkLoader::load1
    [Signature("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 70 48 8B E9 33")]
    private readonly nint _load1Addr;

    // hkLoader's OWN virtual destructor (vtable slot 0)
    [Signature("48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9 E8 8C 78 CB 01")]
    private readonly nint _dtorAddr;

    private readonly Hook<HkLoaderLoad1Delegate>? _load1Hook;
    private readonly Hook<HkLoaderDtorDelegate>? _dtorHook;
    private readonly ILogger<HavokAllocGuard> _logger;

    private readonly object _globalAllocatorLock = new();
    private nint _currentHolderSelf;
    private long _sameInstanceCollisionCount;
    private long _crossInstanceCollisionCount;

    public HavokAllocGuard(ILogger<HavokAllocGuard> logger, IGameInteropProvider gameInterop)
    {
        _logger = logger;

        try
        {
            gameInterop.InitializeFromAttributes(this);
            _logger.LogInformation("HavokAllocGuard: signature scan completed.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "HavokAllocGuard: signature scan failed to initialize (game patch?); hkLoader race guard INACTIVE.");
            return;
        }

        try
        {
            _load1Hook = gameInterop.HookFromAddress<HkLoaderLoad1Delegate>(_load1Addr, Load1Detour);
            _logger.LogInformation("HavokAllocGuard: hkLoader::load1 signature resolved at 0x{addr:X}, hook created.", _load1Addr);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "HavokAllocGuard: hkLoader::load1 signature did not resolve (game patch?); load1 side of the race guard is UNGUARDED.");
        }

        try
        {
            _dtorHook = gameInterop.HookFromAddress<HkLoaderDtorDelegate>(_dtorAddr, DtorDetour);
            _logger.LogInformation("HavokAllocGuard: hkLoader destructor signature resolved at 0x{addr:X}, hook created.", _dtorAddr);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "HavokAllocGuard: hkLoader destructor signature did not resolve (game patch?); destructor side of the race guard is UNGUARDED.");
        }

        if (_load1Hook is not null && _dtorHook is not null)
        {
            _logger.LogInformation("HavokAllocGuard: hkLoader race guard fully active (both hooks resolved).");
        }
        else
        {
            _logger.LogWarning("HavokAllocGuard: hkLoader race guard is only PARTIALLY active — locking one side of a race with the other unguarded provides no protection. Treat as INACTIVE until both signatures resolve again.");
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _load1Hook?.Enable();
        _dtorHook?.Enable();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _load1Hook?.Disable();
        _dtorHook?.Disable();
        if (_sameInstanceCollisionCount > 0)
        {
            _logger.LogWarning("HavokAllocGuard: prevented {count} same-instance load1/dtor collision(s) this session — each one would plausibly have crashed without this guard (plus {crossCount} unrelated-instance collision(s), harmless global-lock overlap).",
                _sameInstanceCollisionCount, _crossInstanceCollisionCount);
        }
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _load1Hook?.Dispose();
        _dtorHook?.Dispose();
    }

    private nint Load1Detour(nint self, nint arg2, nint arg3, nint arg4)
    {
        return EnterLockAndRun("LOAD1", self, () => _load1Hook!.Original(self, arg2, arg3, arg4));
    }

    private nint EnterLockAndRun(string label, nint self, Func<nint> callOriginal)
    {
        bool lockTaken = false;
        try
        {
            lockTaken = Monitor.TryEnter(_globalAllocatorLock, 0);
            if (!lockTaken)
            {
                nint holder = Volatile.Read(ref _currentHolderSelf);
                long waitStart = Stopwatch.GetTimestamp();
                Monitor.Enter(_globalAllocatorLock, ref lockTaken);
                double waitMs = (Stopwatch.GetTimestamp() - waitStart) * 1000.0 / Stopwatch.Frequency;

                if (holder == self)
                {
                    long n = Interlocked.Increment(ref _sameInstanceCollisionCount);
                    _logger.LogError("HavokAllocGuard: [SAME-INSTANCE COLLISION] {label} self=0x{self:X} waited {waitMs:F3}ms for another thread's in-flight load1/dtor on this EXACT instance — CRASH AVOIDED (count: {n}).",
                        label, self, waitMs, n);
                }
                else
                {
                    long n = Interlocked.Increment(ref _crossInstanceCollisionCount);
                    _logger.LogInformation("HavokAllocGuard: [cross-instance collision] {label} self=0x{self:X} waited {waitMs:F3}ms behind an unrelated instance 0x{holder:X} (global lock scope; not dangerous) (count: {n}).",
                        label, self, waitMs, holder, n);
                }
            }
            Volatile.Write(ref _currentHolderSelf, self);
            return callOriginal();
        }
        finally
        {
            if (lockTaken) Monitor.Exit(_globalAllocatorLock);
        }
    }

    private nint DtorDetour(nint self, nint mode)
    {
        return EnterLockAndRun("DTOR", self, () => _dtorHook!.Original(self, mode));
    }
}
