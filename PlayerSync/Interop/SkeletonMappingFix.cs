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

        ResizeDestinationIfNecessary(skeletonMapper, dstBoneToTrackIndices);

        _setupSkeletonMappingHook!.Original!.Invoke(skeletonMapper, animationBinding, srcBoneToTrackIndices, dstBoneToTrackIndices, dstTrackToBoneIndices);
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
        for (int i = 0; i < trackToBone.Length; i++)
        {
            int boneIndex = trackToBone[i];
            if (boneIndex < 0)
            {
                return false;
            }
            if (boneIndex > maxBoneIndex) maxBoneIndex = boneIndex;
        }

        if (maxBoneIndex >= skeletonBoneCount)
        {
            // An index this far out cannot be a real bone on any skeleton that exists, so the binding is
            // malformed rather than merely oversized. Skip the call instead of growing: reserving to a
            // bogus size would still hand the game a buffer the write does not fit.
            if (maxBoneIndex >= MaxReasonableBoneCount)
            {
                return false;
            }

            int reserveResult = 0;
            _hkArrayUtilReserve(&reserveResult, (void*)_globalHavokAllocator, srcBoneToTrackIndices, maxBoneIndex + 1, sizeof(short));
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
    /// skeleton it is reading from.
    /// </remarks>
    private void ResizeDestinationIfNecessary(hkaSkeletonMapper* skeletonMapper, hkArray<short>* dstBoneToTrackIndices)
    {
        if (skeletonMapper == null || dstBoneToTrackIndices == null)
        {
            return;
        }

        var skeletonB = skeletonMapper->Mapping.SkeletonB.ptr;
        if (skeletonB == null)
        {
            return;
        }

        // These arrays are reused between bindings, so the buffer often already holds more than this
        // binding's bone count -- and the game reserves up to that bone count itself. A write only has to
        // fit the larger of the two.
        int destinationBoneCount = skeletonB->Bones.Length;
        int capacity = Math.Max(ReadArrayCapacity(dstBoneToTrackIndices), destinationBoneCount);

        // An unreadable mapping array leaves the destination unguarded on this call, rather than sized to a
        // bound derived from garbage.
        if (!TryReadMaxDestinationBone(skeletonMapper, out int maxBoneB))
        {
            return;
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
        // huge buffer is wanted.
        if (needed <= capacity || needed > MaxReasonableBoneCount)
        {
            return;
        }

        int reserveResult = 0;
        _hkArrayUtilReserve(&reserveResult, (void*)_globalHavokAllocator, dstBoneToTrackIndices, needed, sizeof(short));
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

        // An untrusted length must not read as an empty mapping: that would size the bound to nothing.
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
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _setupSkeletonMappingHook?.Dispose();
    }
}
