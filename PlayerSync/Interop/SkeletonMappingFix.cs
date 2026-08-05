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
    // reads transform floats as bone indices -- observed live as maxBoneB=16290 (0x3FA2, the high half of
    // a float ~1.27) against a 172-bone skeleton, which then tripped MaxReasonableBoneCount and silently
    // disabled the destination guard. Array header layout is {data, int length, int capacity}.
    private const int SimpleMappingsOffset = 0x50;
    private const int ChainMappingsOffset = 0x60;
    private const int SimpleMappingStride = 0x40;
    private const int SimpleMappingBoneBOffset = 2;
    private const int ArrayLengthOffset = 8;

    // An hkArray's capacity shares its field with flags; the game masks it the same way before deciding
    // whether to reserve (`mov eax,[r15+0xc]` / `and eax,0x3fffffff` at SetupSkeletonMapping+0x2bd).
    // Capacity is what a write actually has to fit inside -- these arrays are reused between bindings, so
    // it is frequently larger than the bone count the current binding sets as the length.
    private const int ArrayCapacityOffset = 0x0C;
    private const int ArrayCapacityMask = 0x3FFFFFFF;

    private const int LogThrottleMs = 5000;

    // One throttle slot per message, so a chatty source-side catch cannot mask the destination-side and
    // overflow-confirmation lines -- they are emitted later in the same call and would always lose.
    private enum LogSlot
    {
        Source,
        Destination,
        ChainOverflow,
        Malformed,
    }

    private readonly long[] _lastLogTickMs = new long[Enum.GetValues<LogSlot>().Length];

    // What ResizeDestinationIfNecessary concluded, so the post-call check can describe the outcome
    // honestly: "the bound was wrong" and "no bound could be computed" are different failures.
    private enum DestinationOutcome
    {
        Unknown,
        Unguarded,
        NotNeeded,
        Grew,
    }

    // One read of the mapper's simple mappings, shared by the guard and by the log description so a single
    // detour call does not scan the array twice.
    private readonly struct MappingBounds
    {
        public readonly bool Readable;
        public readonly int Count;
        public readonly int MaxBoneA;
        public readonly int MinBoneB;
        public readonly int MaxBoneB;

        public MappingBounds(bool readable, int count, int maxBoneA, int minBoneB, int maxBoneB)
        {
            Readable = readable;
            Count = count;
            MaxBoneA = maxBoneA;
            MinBoneB = minBoneB;
            MaxBoneB = maxBoneB;
        }
    }

    private long _resizedCount;
    private long _resizedDestinationCount;
    private long _malformedCount;
    private long _chainOverflowContainedCount;
    private long _chainOverflowMissedCount;
    private long _negativeMappingIndexCount;
    private long _negativeDestinationIndexCount;

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
        // Read once and shared by the guard and the log description: the detour runs on the animation tick
        // and this array is as long as the source skeleton has bones.
        MappingBounds bounds = ReadSimpleMappingBounds(skeletonMapper);

        if (!ResizeIfNecessary(skeletonMapper, animationBinding, srcBoneToTrackIndices, bounds))
        {
            // The game empties all three arrays before rebuilding them. Returning without it would leave
            // the PREVIOUS binding's mapping in place, and this animation would be retargeted through a
            // correspondence built for a different one -- a wrong pose rather than a dropped one. Empty
            // them so the skip is a real no-op.
            ClearArrayLength(srcBoneToTrackIndices);
            ClearArrayLength(dstBoneToTrackIndices);
            ClearArrayLength(dstTrackToBoneIndices);
            return;
        }

        // What the destination buffer would have held on its own, or -1 if that could not be established.
        // Deliberately captured whether or not we grew: checking only after a grow would measure the calls
        // that were already handled and stay silent on the ones where the bound was too narrow, which is
        // the only failure this measurement exists to catch.
        int destinationCapacity = ResizeDestinationIfNecessary(skeletonMapper, dstBoneToTrackIndices, bounds, out DestinationOutcome outcome);

        _setupSkeletonMappingHook!.Original!.Invoke(skeletonMapper, animationBinding, srcBoneToTrackIndices, dstBoneToTrackIndices, dstTrackToBoneIndices);

        // Reading back what the call produced costs a second O(n) pass on the animation tick, so stop once
        // it has nothing left to say. It answers two independent questions -- was the bound too narrow, and
        // did anything write before the buffer -- so both have to have fired before it goes quiet, or one
        // early bound miss would switch off a negative-index detector that had never reported anything.
        // Grown calls are always checked; that is the cheap confirmation the guard works.
        if (destinationCapacity >= 0
            && (outcome == DestinationOutcome.Grew
                || _chainOverflowMissedCount == 0
                || _negativeDestinationIndexCount == 0))
        {
            CheckChainOverflow(dstTrackToBoneIndices, destinationCapacity, outcome);
        }
    }

    // Returns false, skipping the original call, for a binding this cannot make safe: a negative bone index
    // writes before the buffer, and one far past any real skeleton means the binding is malformed rather
    // than merely authored for a larger one. Growing helps neither.
    private bool ResizeIfNecessary(hkaSkeletonMapper* skeletonMapper, hkaAnimationBinding* animationBinding, hkArray<short>* srcBoneToTrackIndices, in MappingBounds bounds)
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
                _malformedCount++;
                LogActivity(LogSlot.Malformed, "Skipping malformed animation binding with negative bone index {index}.", boneIndex);
                return false;
            }
            if (boneIndex > maxBoneIndex) maxBoneIndex = boneIndex;
            if (boneIndex >= skeletonBoneCount) outOfRangeCount++;
        }

        if (maxBoneIndex >= skeletonBoneCount)
        {
            // An index this far out cannot be a real bone on any skeleton that exists, so the binding is
            // malformed rather than merely oversized. Skip the call instead of growing: reserving to a
            // bogus size would still hand the game a buffer the write does not fit, and dropping the
            // retarget is what the negative-index case above already does for the same reason.
            if (maxBoneIndex >= MaxReasonableBoneCount)
            {
                _malformedCount++;
                LogActivity(LogSlot.Malformed, "Skipping animation binding with an implausible bone index {index}; the target skeleton has {have} bones.",
                    maxBoneIndex, skeletonBoneCount);
                return false;
            }

            // How many tracks are out of range separates an authoring off-by-one (one track, one bone past
            // the end) from a real skeleton mismatch (a long run), which is the difference between two
            // bytes of overrun and enough to corrupt the Havok pool.
            _resizedCount++;

            // hkArrayUtil::_reserve writes to its first argument; the meaning is NOT confirmed, so report
            // it rather than branch on it. If growth ever fails silently, this is what will show it.
            int reserveResult = 0;
            _hkArrayUtilReserve(&reserveResult, (void*)_globalHavokAllocator, srcBoneToTrackIndices, maxBoneIndex + 1, sizeof(short));

            // Gated rather than passed as an argument: arguments are evaluated before the call, so building
            // the description inside the log call would run on every catch and then be thrown away whenever
            // the throttle suppressed the line.
            if (ShouldLog(LogSlot.Source))
            {
                _logger.LogWarning("Growing a bone-to-track buffer sized for {have} bones to fit bone index {index}. {outOfRange} of {tracks} track(s) out of range, reserve={reserve}. {mapping}",
                    skeletonBoneCount, maxBoneIndex, outOfRangeCount, trackToBone.Length, reserveResult, DescribeMapping(skeletonMapper, bounds));
            }
        }

        return true;
    }

    // Logged alongside a source-side catch so the destination side's decision can be judged after the fact.
    // If SkeletonB already covers MaxBoneB then the second write was never in danger and the absence of a
    // destination grow is correct; if it does not, the bound in ResizeDestinationIfNecessary is wrong.
    private string DescribeMapping(hkaSkeletonMapper* skeletonMapper, in MappingBounds bounds)
    {
        // Covers managed faults only. A torn-down mapper raises an access violation, which .NET does not
        // make catchable -- the null checks here and in the readers are the actual protection against it.
        try
        {
            var skeletonA = skeletonMapper->Mapping.SkeletonA.ptr;
            var skeletonB = skeletonMapper->Mapping.SkeletonB.ptr;
            string mappings;
            if (!bounds.Readable)
            {
                mappings = "simpleMappings=UNREADABLE";
            }
            else if (bounds.Count == 0)
            {
                // Reporting extrema of an empty set would print sentinels as though they were bone indices.
                mappings = "simpleMappings=0";
            }
            else
            {
                mappings = $"simpleMappings={bounds.Count}, maxBoneA={bounds.MaxBoneA}, minBoneB={bounds.MinBoneB}, maxBoneB={bounds.MaxBoneB}";
            }

            return $"(SkeletonA={(skeletonA == null ? -1 : skeletonA->Bones.Length)}, "
                + $"SkeletonB={(skeletonB == null ? -1 : skeletonB->Bones.Length)}, "
                + $"{mappings}, chainMappings={ReadChainMappingCount(skeletonMapper)})";
        }
        catch (Exception ex)
        {
            return $"(mapping details unavailable: {ex.Message})";
        }
    }

    // Readable is false when the array could not be trusted, which a caller must not confuse with an empty
    // one: a rejected read used to fall out as count=0/max=-1, which silently sized the destination bound
    // to nothing and looked in the log exactly like a mapper that legitimately has no simple mappings.
    // With no entries the extrema mean nothing, so they carry sentinels no bone index can equal -- 0 would
    // have read as the root bone -- and callers must check Count before using them.
    private static MappingBounds ReadSimpleMappingBounds(hkaSkeletonMapper* skeletonMapper)
    {
        if (skeletonMapper == null)
        {
            return new MappingBounds(false, 0, -1, int.MaxValue, -1);
        }

        byte* header = (byte*)skeletonMapper + SimpleMappingsOffset;
        byte* data = *(byte**)header;
        int length = *(int*)(header + ArrayLengthOffset);
        if (length == 0)
        {
            return new MappingBounds(true, 0, -1, int.MaxValue, -1);
        }

        if (data == null || length < 0 || length > MaxReasonableBoneCount)
        {
            return new MappingBounds(false, 0, -1, int.MaxValue, -1);
        }

        int maxBoneA = -1;
        int minBoneB = int.MaxValue;
        int maxBoneB = -1;
        for (int i = 0; i < length; i++)
        {
            byte* entry = data + ((long)i * SimpleMappingStride);
            int boneA = *(short*)entry;
            int boneB = *(short*)(entry + SimpleMappingBoneBOffset);
            if (boneA > maxBoneA) maxBoneA = boneA;
            if (boneB < minBoneB) minBoneB = boneB;
            if (boneB > maxBoneB) maxBoneB = boneB;
        }

        return new MappingBounds(true, length, maxBoneA, minBoneB, maxBoneB);
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

    /// <summary>
    /// The same scatter-write happens a second time at the end of the game function, into
    /// dstBoneToTrackIndices: it is sized to SkeletonB's bone count, then written as
    /// dst[dstTrackToBoneIndices[i]] = i. That index array is built by the function itself out of the
    /// mapper's mappings, so a mapper carrying indices from a larger skeleton than SkeletonB overflows it
    /// exactly like the source side does. This grows the buffer first.
    /// </summary>
    /// <remarks>
    /// A previous attempt at this (reverted 2026-07-11) never fired because it was gated behind the source
    /// side's condition, which at the time compared the binding's TRACK COUNT rather than its max bone
    /// index. The two overflows have independent triggers, so this one is deliberately not gated on the
    /// other. Only the simple mappings' bone indices can be read up front; the chain mappings' contribution
    /// materialises inside the call, so SkeletonA's bone count stands in as the bound for those --
    /// retargeting cannot produce an index beyond the skeleton it is reading from. CheckChainOverflow
    /// measures afterwards whether that bound actually held.
    /// </remarks>
    /// <returns>
    /// What the destination buffer would have held without our intervention -- its own capacity, or the
    /// bone count the game is about to reserve to, whichever is larger. -1 only when that cannot be
    /// established. Returned whether or not it grew, so the caller can measure the outcome either way.
    /// </returns>
    private int ResizeDestinationIfNecessary(hkaSkeletonMapper* skeletonMapper, hkArray<short>* dstBoneToTrackIndices, in MappingBounds bounds, out DestinationOutcome outcome)
    {
        outcome = DestinationOutcome.Unknown;

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

        // Never silently: an unreadable mapping array means the layout assumptions above are wrong, and
        // swallowing that is what hid the destination guard doing nothing at all. Still return the capacity
        // so the post-call check can report whatever the game then writes.
        if (!bounds.Readable)
        {
            outcome = DestinationOutcome.Unguarded;
            LogActivity(LogSlot.Destination, "Could not read the mapper's simple mappings; the destination buffer is unguarded on this call.");
            return capacity;
        }

        // The earliest point a write before the buffer can be predicted. Growing cannot prevent it and
        // skipping the call would drop every animation whose mapper uses -1 as its "unmapped" filler, so
        // this reports rather than acts -- but it reports even when the value never reaches the array the
        // post-call check reads, which is the case that check cannot see.
        if (bounds.Count > 0 && bounds.MinBoneB < 0)
        {
            _negativeMappingIndexCount++;
            LogActivity(LogSlot.Destination, "A simple mapping targets negative bone index {index}; if it reaches the write it lands before the destination buffer.",
                bounds.MinBoneB);
        }

        int needed = bounds.MaxBoneB + 1;

        // Chain mappings are walked inside the call and their output is not readable from here.
        if (ReadChainMappingCount(skeletonMapper) > 0)
        {
            var skeletonA = skeletonMapper->Mapping.SkeletonA.ptr;
            if (skeletonA != null && skeletonA->Bones.Length > needed)
            {
                needed = skeletonA->Bones.Length;
            }
        }

        if (needed <= capacity)
        {
            outcome = DestinationOutcome.NotNeeded;
            return capacity;
        }

        if (needed > MaxReasonableBoneCount)
        {
            outcome = DestinationOutcome.Unguarded;
            LogActivity(LogSlot.Destination, "Refusing an implausible destination bound of {needed} slots for a {have}-bone skeleton; mapping data looks wrong.",
                needed, destinationBoneCount);
            return capacity;
        }

        _resizedDestinationCount++;

        // See the source-side reserve for why this result is reported rather than acted on.
        int reserveResult = 0;
        _hkArrayUtilReserve(&reserveResult, (void*)_globalHavokAllocator, dstBoneToTrackIndices, needed, sizeof(short));
        outcome = DestinationOutcome.Grew;

        LogActivity(LogSlot.Destination, "Growing a destination bone-to-track buffer that would have held {have} to {needed}, reserve={reserve}.",
            capacity, needed, reserveResult);
        return capacity;
    }

    // Did the indices the call actually produced fit what the buffer would have held on its own? Runs on
    // every call whose capacity is known, not only the grown ones: a hit after a grow says the guard earned
    // its keep, and a hit WITHOUT one is an overflow that actually happened -- the failure this measurement
    // exists for, and the one it could not see when it was gated behind the grow.
    private void CheckChainOverflow(hkArray<short>* dstTrackToBoneIndices, int capacityBeforeGrow, DestinationOutcome outcome)
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

        // A negative index writes BEFORE the buffer, into whatever allocation precedes it. Growing cannot
        // help, and skipping the call on the strength of it would drop every animation whose mapper uses
        // -1 as its "unmapped" filler, which is the game's own convention for these arrays. Report it
        // instead: if this ever appears, the corruption has a second source that no sizing will close.
        if (minBoneIndex < 0)
        {
            _negativeDestinationIndexCount++;
            LogActivity(LogSlot.ChainOverflow, "Destination index {index} is negative; that writes before the buffer and no growth can prevent it.",
                minBoneIndex);
        }

        if (maxBoneIndex < capacityBeforeGrow)
        {
            return;
        }

        if (outcome == DestinationOutcome.Grew)
        {
            _chainOverflowContainedCount++;
            LogActivity(LogSlot.ChainOverflow, "Destination buffer would have overflowed and was grown in time: bone index {index} into {capacity} slots.",
                maxBoneIndex, capacityBeforeGrow);
            return;
        }

        _chainOverflowMissedCount++;
        if (outcome == DestinationOutcome.Unguarded)
        {
            LogActivity(LogSlot.ChainOverflow, "Destination buffer OVERFLOWED: bone index {index} written into {capacity} slots, and no bound was computed for this call.",
                maxBoneIndex, capacityBeforeGrow);
            return;
        }

        LogActivity(LogSlot.ChainOverflow, "Destination buffer OVERFLOWED: bone index {index} written into {capacity} slots and the bound did not predict it.",
            maxBoneIndex, capacityBeforeGrow);
    }

    // Rate-limited because a venue full of oversized skeletons can hit this many times per frame, and it
    // runs on the animation tick. The running totals logged in StopAsync are what a crash pack needs.
    private void LogActivity(LogSlot slot, string message, params object?[] args)
    {
        if (!ShouldLog(slot))
        {
            return;
        }

        _logger.LogWarning(message, args);
    }

    // Stamps the slot as a side effect, so a caller that asks must go on to log.
    private bool ShouldLog(LogSlot slot)
    {
        long now = Environment.TickCount64;
        if ((now - _lastLogTickMs[(int)slot]) <= LogThrottleMs)
        {
            return false;
        }

        _lastLogTickMs[(int)slot] = now;
        return true;
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
        _logger.LogInformation("SkeletonMappingFix: resized {resized} source and {resizedDst} destination buffer(s); "
            + "{contained} destination overflow(s) were caught in time and {missed} got through; "
            + "{negativeMapping} mapping(s) and {negativeWrite} write(s) went before the buffer; "
            + "skipped {malformed} malformed binding(s).",
            _resizedCount, _resizedDestinationCount, _chainOverflowContainedCount, _chainOverflowMissedCount,
            _negativeMappingIndexCount, _negativeDestinationIndexCount, _malformedCount);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _setupSkeletonMappingHook?.Dispose();
    }
}
