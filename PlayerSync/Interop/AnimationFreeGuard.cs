using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Dalamud.Utility.Signatures;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;

namespace MareSynchronos.Interop;

public sealed partial class AnimationFreeGuard : IHostedService, IDisposable
{
    [LibraryImport("Kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool IsBadReadPtr(nint address, nint length);

    private delegate void HkLargeBlockAllocatorFreeDelegate(nint largeBlockAllocator, nint memory);

    private readonly ILogger _logger;

    [Signature("48 85 D2 0F 84 ?? ?? ?? ?? 55 48 83 EC 20", DetourName = nameof(HkLargeBlockAllocatorFreeDetour))]
    private readonly Hook<HkLargeBlockAllocatorFreeDelegate>? _hkLargeBlockAllocatorFreeHook;

    public AnimationFreeGuard(ILogger<AnimationFreeGuard> logger, IGameInteropProvider gameInteropProvider)
    {
        _logger = logger;

        try
        {
            gameInteropProvider.InitializeFromAttributes(this);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to hook hkLargeBlockAllocator Free.");
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _hkLargeBlockAllocatorFreeHook?.Enable();
        return Task.CompletedTask;
    }

    private void HkLargeBlockAllocatorFreeDetour(nint largeBlockAllocator, nint memory)
    {
        bool isMemoryValid = !IsBadReadPtr(memory, 8);
        if (isMemoryValid)
        {
            _hkLargeBlockAllocatorFreeHook?.Original.Invoke(largeBlockAllocator, memory);
        }
        else
        {
            _logger.LogInformation("Caught invalid free of pointer 0x{addr:X}.", memory);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _hkLargeBlockAllocatorFreeHook?.Disable();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _hkLargeBlockAllocatorFreeHook?.Dispose();
    }
}
