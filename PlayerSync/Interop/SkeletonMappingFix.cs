using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;
using FFXIVClientStructs.Havok.Animation.Mapper;
using FFXIVClientStructs.Havok.Animation.Animation;
using FFXIVClientStructs.Havok.Common.Base.Container.Array;
using Dalamud.Utility.Signatures;

namespace PlayerSync.Interop;

internal unsafe class SkeletonMappingFix : IHostedService, IDisposable
{
    private readonly ILogger _logger;
    private readonly IGameInteropProvider _gameInteropProvider;

    // How to find: Look for the only usage of `hkaDefaultAnimationControlMapperData::`vftable'`, this will be the last function called there.
    private delegate void SetupSkeletonMappingDelegate(hkaSkeletonMapper* skeletonMapper, hkaAnimationBinding* animationBinding, hkArray<short>* srcBoneToTrackIndices, hkArray<short>* dstBoneToTrackIndices, hkArray<short>* dstTrackToBoneIndices);
    [Signature("4C 89 4C 24 ?? 4C 89 44 24 ?? 55 53 56", DetourName = nameof(SetupSkeletonMappingDetour))]
    private readonly Hook<SetupSkeletonMappingDelegate>? _setupSkeletonMappingHook;

    // How to find: This is `hkArrayUtil::_reserve`, which is in ClientStructs' data.yml despite not being added to the code.
    [Signature("48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 41 56 48 83 EC 20 8B 74 24 50 49 8B F8 45 8B 40 0C")]
    private readonly delegate* unmanaged<int*, void*, void*, int, int, void> _hkArrayUtilReserve;

    // How to find: this is the second parameter of almost all calls to `hkArrayUtil::_reserve` and the first to `hkArrayUtil::_reserveMore`.
    // Sig the `lea` instruction where it's used.
    private const string _globalHavokAllocatorSig = "48 8D 15 ?? ?? ?? ?? 45 8B CF 48 8D 4D 68";
    private readonly nint _globalHavokAllocator; // hkMemoryAllocator*

    // False when any signature missed. The hook stays disabled in that case: a resolved hook without a
    // resolved allocator/reserve would call through a null pointer, which is worse than doing nothing.
    private readonly bool _active;

    // A bad bone index could otherwise ask for an enormous allocation on the animation tick. Nothing
    // legitimate comes close: the largest skeleton seen in the wild (NOFF) is 170 bones.
    private const int MaxReasonableBoneCount = 4096;

    // How to find: hkaSkeletonMapperData's mapping arrays, read by raw offset rather than through
    // ClientStructs' structs. The game strides simple mappings by 0x40 (`shl rdx, 6` at
    // SetupSkeletonMapping+0x158, then BoneA at +0 and BoneB at +2), which is the 16-byte-aligned size of
    // {short, short, hkQsTransform}. Indexing through the declared struct drifts 12 bytes per element and
    // reads transform floats as bone indices. Array header layout is {data, int length, int capacity},
    // with capacity sharing its field with flags -- the game masks it the same way at +0x2bd before
    // deciding whether to reserve.
    private const int SimpleMappingsOffset = 0x50;
    private const int ChainMappingsOffset = 0x60;
    private const int SimpleMappingStride = 0x40;
    private const int SimpleMappingBoneBOffset = 2;
    private const int ArrayLengthOffset = 8;
    private const int ArrayCapacityOffset = 0x0C;
    private const int ArrayCapacityMask = 0x3FFFFFFF;

    private const int LogThrottleMs = 5000;

    // One throttle slot per message, so a chatty source-side catch cannot mask the others.
    private enum LogSlot
    {
        Source,
        Destination,
        DestinationWrite,
        Skipped,
    }

    private readonly long[] _lastLogTickMs = new long[Enum.GetValues<LogSlot>().Length];

    private long _resizedCount;
    private long _skippedCount;
    private long _destinationGrewCount;
    private long _destinationOverflowCount;

    public SkeletonMappingFix(ILogger<SkeletonMappingFix> logger, IGameInteropProvider gameInteropProvider, ISigScanner sigScanner)
    {
        _logger = logger;
        _gameInteropProvider = gameInteropProvider;

        try
        {
            _gameInteropProvider.InitializeFromAttributes(this);
            _globalHavokAllocator = sigScanner.GetStaticAddressFromSig(_globalHavokAllocatorSig);

            _active = _setupSkeletonMappingHook != null
                && _hkArrayUtilReserve != null
                && _globalHavokAllocator != nint.Zero;

            if (_active)
            {
                _logger.LogInformation("SkeletonMappingFix: hook resolved at 0x{addr:X}, Havok allocator at 0x{alloc:X}.",
                    _setupSkeletonMappingHook!.Address, _globalHavokAllocator);
            }
            else
            {
                _logger.LogWarning("SkeletonMappingFix: a signature resolved to nothing (game patch?); skeleton mapping fix is INACTIVE.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SkeletonMappingFix: signature did not resolve (game patch?); skeleton mapping fix is INACTIVE.");
        }
    }

    private void SetupSkeletonMappingDetour(hkaSkeletonMapper* skeletonMapper, hkaAnimationBinding* animationBinding, hkArray<short>* srcBoneToTrackIndices, hkArray<short>* dstBoneToTrackIndices, hkArray<short>* dstTrackToBoneIndices)
    {
        if (!ResizeIfNecessary(skeletonMapper, animationBinding, srcBoneToTrackIndices))
        {
            // The game empties all three arrays before rebuilding them. Returning without it would leave
            // the PREVIOUS binding's mapping in place, and this animation would be retargeted through a
            // correspondence built for a different one -- a wrong pose rather than a dropped one.
            ClearArrayLength(srcBoneToTrackIndices);
            ClearArrayLength(dstBoneToTrackIndices);
            ClearArrayLength(dstTrackToBoneIndices);
            return;
        }

        // What the destination buffer would have held on its own, or -1 if that could not be established.
        int destinationCapacity = ResizeDestinationIfNecessary(skeletonMapper, dstBoneToTrackIndices, out bool grew);

        _setupSkeletonMappingHook!.Original!.Invoke(skeletonMapper, animationBinding, srcBoneToTrackIndices, dstBoneToTrackIndices, dstTrackToBoneIndices);

        // Reading back what the call produced costs an O(n) pass on the animation tick. It is a tripwire,
        // not a measurement: once it has fired, the destination bound is known to be wrong and repeating
        // the pass on every binding buys nothing.
        if (destinationCapacity >= 0 && (grew || _destinationOverflowCount == 0))
        {
            CheckDestinationWrites(dstTrackToBoneIndices, destinationCapacity);
        }
    }

    // Returns false, skipping the original call, for a binding this cannot make safe: a negative bone index
    // writes before the buffer, and one far past any real skeleton means the binding is malformed rather
    // than merely authored for a larger one. Growing helps neither.
    private bool ResizeIfNecessary(hkaSkeletonMapper* skeletonMapper, hkaAnimationBinding* animationBinding, hkArray<short>* srcBoneToTrackIndices)
    {
        if (skeletonMapper == null || animationBinding == null || srcBoneToTrackIndices == null)
        {
            return true;
        }

        var skeleton = skeletonMapper->Mapping.SkeletonA.ptr;
        if (skeleton == null)
        {
            return true;
        }

        // The game writes each track index to srcBoneToTrackIndices[boneIndex], indexing by the VALUE from the
        // binding's TransformTrackToBoneIndices -- so the buffer must fit max(boneIndex) + 1, not the track count
        // (independent, both untrusted). A negative value writes before the buffer and no growth can make it safe.
        int skeletonBoneCount = skeleton->Bones.Length;
        var trackToBone = animationBinding->TransformTrackToBoneIndices;
        int maxBoneIndex = -1;
        int outOfRangeCount = 0;
        for (int i = 0; i < trackToBone.Length; i++)
        {
            int boneIndex = trackToBone[i];
            if (boneIndex < 0)
            {
                _skippedCount++;
                LogActivity(LogSlot.Skipped, "Skipping malformed animation binding with negative bone index {index}.", boneIndex);
                return false;
            }
            if (boneIndex > maxBoneIndex) maxBoneIndex = boneIndex;
            if (boneIndex >= skeletonBoneCount) outOfRangeCount++;
        }

        if (maxBoneIndex >= skeletonBoneCount)
        {
            // An index this far out cannot be a real bone on any skeleton that exists, so the binding is
            // malformed rather than merely oversized. Skip the call instead of growing: reserving to a
            // bogus size would still hand the game a buffer the write does not fit.
            if (maxBoneIndex >= MaxReasonableBoneCount)
            {
                _skippedCount++;
                LogActivity(LogSlot.Skipped, "Skipping animation binding with an implausible bone index {index}; the target skeleton has {have} bones.",
                    maxBoneIndex, skeletonBoneCount);
                return false;
            }

            _resizedCount++;
            int reserveResult = 0;
            _hkArrayUtilReserve(&reserveResult, (void*)_globalHavokAllocator, srcBoneToTrackIndices, maxBoneIndex + 1, sizeof(short));

            // How many tracks are out of range separates an authoring off-by-one from a real skeleton
            // mismatch -- the difference between two bytes of overrun and enough to corrupt the Havok pool.
            // SkeletonB's size is reported because it decides whether the destination side, which carries
            // the same hazard, was ever in danger on this call.
            var skeletonB = skeletonMapper->Mapping.SkeletonB.ptr;
            LogActivity(LogSlot.Source, "Growing a bone-to-track buffer sized for {have} bones to fit bone index {index}. {outOfRange} of {tracks} track(s) out of range; SkeletonB has {dst} bones.",
                skeletonBoneCount, maxBoneIndex, outOfRangeCount, trackToBone.Length, skeletonB == null ? -1 : skeletonB->Bones.Length);
        }

        return true;
    }

    /// <summary>
    /// The same scatter-write happens a second time at the end of the game function, into
    /// dstBoneToTrackIndices: it is sized to SkeletonB's bone count, then written as
    /// dst[dstTrackToBoneIndices[i]] = i. That index array is built by the function itself out of the
    /// mapper's mappings, so a mapper carrying indices from a larger skeleton than SkeletonB overflows it
    /// exactly like the source side does. This grows the buffer first.
    /// </summary>
    /// <remarks>
    /// Deliberately not gated on the source side's condition: the two overflows have independent triggers,
    /// and gating was what made an earlier attempt at this dead code. Only the simple mappings' bone indices
    /// can be read up front; the chain mappings' contribution materialises inside the call, so SkeletonA's
    /// bone count stands in as the bound for those -- retargeting cannot produce an index beyond the
    /// skeleton it is reading from. It has never been observed to grow, because SkeletonB has been the
    /// larger skeleton on every catch so far; CheckDestinationWrites exists to say if that changes.
    /// </remarks>
    /// <returns>
    /// What the destination buffer would have held without our intervention -- its own capacity, or the
    /// bone count the game is about to reserve to, whichever is larger. -1 only when that cannot be
    /// established. Returned whether or not it grew, so the caller can check the outcome either way.
    /// </returns>
    private int ResizeDestinationIfNecessary(hkaSkeletonMapper* skeletonMapper, hkArray<short>* dstBoneToTrackIndices, out bool grew)
    {
        grew = false;

        if (skeletonMapper == null || dstBoneToTrackIndices == null)
        {
            return -1;
        }

        var skeletonB = skeletonMapper->Mapping.SkeletonB.ptr;
        if (skeletonB == null)
        {
            return -1;
        }

        // These arrays are reused between bindings, so the buffer often already holds more than this
        // binding's bone count -- and the game reserves up to that bone count itself. A write only has to
        // fit the larger of the two, and measuring against the bone count alone would report overflows
        // that never happened.
        int destinationBoneCount = skeletonB->Bones.Length;
        int capacity = Math.Max(ReadArrayCapacity(dstBoneToTrackIndices), destinationBoneCount);

        // The canary for a game patch moving these offsets. Without it the guard would go back to doing
        // nothing and saying nothing, which is how the destination side stayed invisible for three sessions.
        if (!TryReadMaxDestinationBone(skeletonMapper, out int maxBoneB))
        {
            LogActivity(LogSlot.Destination, "Could not read the mapper's simple mappings; the destination buffer is unguarded on this call.");
            return capacity;
        }

        int needed = maxBoneB + 1;

        // Chain mappings are walked inside the call and their output is not readable from here.
        if (ReadChainMappingCount(skeletonMapper) > 0)
        {
            var skeletonA = skeletonMapper->Mapping.SkeletonA.ptr;
            if (skeletonA != null && skeletonA->Bones.Length > needed)
            {
                needed = skeletonA->Bones.Length;
            }
        }

        // A bound past MaxReasonableBoneCount means the mapping data is being misread rather than that a
        // huge buffer is wanted; CheckDestinationWrites reports what the call then does with it.
        if (needed <= capacity || needed > MaxReasonableBoneCount)
        {
            return capacity;
        }

        _destinationGrewCount++;
        int reserveResult = 0;
        _hkArrayUtilReserve(&reserveResult, (void*)_globalHavokAllocator, dstBoneToTrackIndices, needed, sizeof(short));
        grew = true;

        LogActivity(LogSlot.Destination, "Growing a destination bone-to-track buffer that would have held {have} to {needed}.",
            capacity, needed);
        return capacity;
    }

    // Tripwire, not a measurement: everything here is expected to stay silent. An index at or past what the
    // buffer would have held is an overflow the bound failed to predict, and a negative one writes before
    // the buffer, which no amount of sizing can prevent -- if that appears, the corruption has a second
    // source. Skipping the call on a negative would drop every animation whose mapper uses -1 as its
    // "unmapped" filler, which is the game's own convention for these arrays, so it reports instead.
    private void CheckDestinationWrites(hkArray<short>* dstTrackToBoneIndices, int capacityBeforeGrow)
    {
        if (dstTrackToBoneIndices == null)
        {
            return;
        }

        int maxBoneIndex = -1;
        int minBoneIndex = int.MaxValue;
        for (int i = 0; i < dstTrackToBoneIndices->Length; i++)
        {
            int boneIndex = (*dstTrackToBoneIndices)[i];
            if (boneIndex > maxBoneIndex) maxBoneIndex = boneIndex;
            if (boneIndex < minBoneIndex) minBoneIndex = boneIndex;
        }

        if (minBoneIndex < 0)
        {
            _destinationOverflowCount++;
            LogActivity(LogSlot.DestinationWrite, "Destination index {index} is negative; that writes before the buffer and no growth can prevent it.",
                minBoneIndex);
        }

        if (maxBoneIndex >= capacityBeforeGrow)
        {
            _destinationOverflowCount++;
            LogActivity(LogSlot.DestinationWrite, "Destination buffer OVERFLOWED: bone index {index} written into {capacity} slots.",
                maxBoneIndex, capacityBeforeGrow);
        }
    }

    private static bool TryReadMaxDestinationBone(hkaSkeletonMapper* skeletonMapper, out int maxBoneB)
    {
        maxBoneB = -1;

        if (skeletonMapper == null)
        {
            return false;
        }

        byte* header = (byte*)skeletonMapper + SimpleMappingsOffset;
        byte* data = *(byte**)header;
        int length = *(int*)(header + ArrayLengthOffset);
        if (length == 0)
        {
            return true;
        }

        // An untrusted length must not read as an empty mapping: that would size the bound to nothing and
        // look identical in the log to a mapper that legitimately has no simple mappings.
        if (data == null || length < 0 || length > MaxReasonableBoneCount)
        {
            return false;
        }

        for (int i = 0; i < length; i++)
        {
            int boneB = *(short*)(data + ((long)i * SimpleMappingStride) + SimpleMappingBoneBOffset);
            if (boneB > maxBoneB) maxBoneB = boneB;
        }

        return true;
    }

    private static int ReadChainMappingCount(hkaSkeletonMapper* skeletonMapper)
    {
        if (skeletonMapper == null)
        {
            return 0;
        }

        return *(int*)((byte*)skeletonMapper + ChainMappingsOffset + ArrayLengthOffset);
    }

    private static int ReadArrayCapacity(hkArray<short>* array)
    {
        if (array == null)
        {
            return 0;
        }

        return *(int*)((byte*)array + ArrayCapacityOffset) & ArrayCapacityMask;
    }

    private static void ClearArrayLength(hkArray<short>* array)
    {
        if (array == null)
        {
            return;
        }

        *(int*)((byte*)array + ArrayLengthOffset) = 0;
    }

    // Rate-limited because a venue full of oversized skeletons can hit this many times per frame, and it
    // runs on the animation tick. The running totals logged in StopAsync are what a crash pack needs.
    private void LogActivity(LogSlot slot, string message, params object?[] args)
    {
        long now = Environment.TickCount64;
        if ((now - _lastLogTickMs[(int)slot]) <= LogThrottleMs)
        {
            return;
        }

        _lastLogTickMs[(int)slot] = now;
        _logger.LogWarning(message, args);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_active)
        {
            _setupSkeletonMappingHook!.Enable();
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _setupSkeletonMappingHook?.Disable();
        _logger.LogInformation("SkeletonMappingFix: grew {resized} source and {resizedDst} destination buffer(s), "
            + "skipped {skipped} malformed binding(s), and saw {overflowed} destination write(s) out of bounds.",
            _resizedCount, _destinationGrewCount, _skippedCount, _destinationOverflowCount);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _setupSkeletonMappingHook?.Dispose();
    }
}
