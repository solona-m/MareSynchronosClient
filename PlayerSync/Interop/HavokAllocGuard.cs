using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Dalamud.Utility.Signatures;
using Microsoft.Extensions.Logging;

namespace MareSynchronos.Interop;

/// <summary>
/// Havok skeleton-mapper buffer size clamping.
///
/// Skeleton retargeting allocates a bone-remap array sized for the source skeleton,
/// This overflows on big modded skeletons. Set the buffer size to 512 bytes.
/// </summary>
public sealed class HavokAllocGuard : IDisposable
{
    private delegate nint BufferAllocDelegate(nint self, nint oldPtr, nint oldSize, nint newSize);

    [Signature("48 89 5C 24 10 48 89 6C 24 18 57 41 56 41 57 48 83 EC 20 48 8B E9")]
    private readonly nint _bufferAllocAddr;

    private Hook<BufferAllocDelegate>? _bufferHook;
    private readonly ILogger<HavokAllocGuard> _logger;

    public HavokAllocGuard(ILogger<HavokAllocGuard> logger, IGameInteropProvider gameInterop)
    {
        _logger = logger;
        try
        {
            gameInterop.InitializeFromAttributes(this);
            _bufferHook = gameInterop.HookFromAddress<BufferAllocDelegate>(_bufferAllocAddr, BufferAllocDetour);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "HavokAllocGuard: bufferAlloc signature did not resolve (game patch?); buffer-size clamping INACTIVE");
        }
    }

    public void Dispose()
    {
        _bufferHook?.Dispose();
    }

    // Clamp bufferAlloc requests to minimum 512B for mapper-path allocations
    private nint BufferAllocDetour(nint self, nint oldPtr, nint oldSize, nint newSize)
    {
        // Clamp mapper-sized requests (128-511B) to 512B to handle large skeleton retargeting
        if ((uint)((int)newSize - 128) <= (511 - 128))
            newSize = 512;

        return _bufferHook!.Original(self, oldPtr, oldSize, newSize);
    }
}
