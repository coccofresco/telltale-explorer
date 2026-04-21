"""
PropertySet family decoders for Telltale MetaStream.

Authoritative TTL sources:
    PropertySet.h lines 227-235  (struct layout)
    PropertySet.h lines 242-448  (MetaOperation_SerializeAsync — authoritative wire)
    PropertySet.h lines 119-139  (PropertyFlags enum values)
    KeyframedValue.h lines 28-54 (template + Sample substruct + explicit instantiations)
    HandleObjectInfo.h lines 14-39 (HOI struct layout: Symbol mObjectName + Flags mFlags)

Registers the following types into telltale.metaclass._REGISTRY and
telltale.meta_intrinsics._DECODERS at import time:

    PropertySet              -> decode_propertyset
    PropertyValue            -> @meta_class only, no on-disk decoder
    KeyframedValue<float>    -> decode_keyframed_value_float
    KeyframedValue<bool>     -> decode_keyframed_value_bool
    KeyframedValue<int>      -> decode_keyframed_value_int
    KeyframedValue<u64>      -> decode_keyframed_value_u64
    KeyframedValue<Vector3>  -> decode_keyframed_value_vector3

All decoder registrations use decoder_only=True so the @meta_class
dataclass binding already in _REGISTRY is preserved (same pattern as
telltale/meta_ptable.py and telltale/meta_math.py).
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Optional

from telltale.metaclass import meta_class, meta_member, get_by_hash
from telltale.meta_intrinsics import (
    register,
    get_decoder_by_hash,
    decode_symbol,
)
from telltale.meta_handle import Handle
from telltale.metastream import MetaStreamReader, parse_header
from telltale.validation import ChoreValidationReport

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants (used by _walk_to_editor_props and harness)
# ---------------------------------------------------------------------------

# Expected total byte count (prefix + content) of a blocked empty PropertySet in MTRE.
# Derived from 05-01 plan SUMMARY: 4(prefix) + 8(mPropVersion block) + 8(mPropertyFlags block)
# + 16(mHOI block) + 12(custom block) = 48 bytes.  Used as a sanity-check against the
# block_size we observe at second_start in the 3 hint chores.
EXPECTED_EMPTY_PROPSET_BYTES = 48

# ---------------------------------------------------------------------------
# PropertyFlags constants (PropertySet.h lines 119-125)
# ---------------------------------------------------------------------------

PropertyFlag_HasEmbedded = 0x400
"""ePropertyFlag_HasEmbedded: embedded parent PropertySet appended after type-map."""

PropertyFlag_LockUnloadable = 0x400000
"""ePropertyFlag_LockUnloadable."""

PropertyFlag_IsRuntime = 0x10
"""ePropertyFlag_IsRuntime."""

PropertyFlag_DontSaveInSaveGames = 0x200
"""ePropertyFlag_DontSaveInSaveGames."""


# ---------------------------------------------------------------------------
# UnknownPropertyValue sentinel
# ---------------------------------------------------------------------------

@dataclass
class UnknownPropertyValue:
    """Sentinel returned when a property's type hash is not in the registry.

    NOT registered as a @meta_class — it has no wire form.  Only produced at
    runtime by decode_propertyset / decode_property_value when the type hash
    lookup returns None (PropertySet.h line 405-412 DEBUGMODE path).

    The skip_block() call in the caller already consumed the payload bytes,
    so this sentinel is byte-exact-safe.
    """
    type_hash: int


# ---------------------------------------------------------------------------
# PropertyValue dataclass
# ---------------------------------------------------------------------------

@meta_class("PropertyValue")
@dataclass
class PropertyValue:
    """Runtime container for a single typed property value.

    The on-disk form is: [u64 type_hash][block-size-prefixed payload].
    At decode time the type name is not recoverable; only the hash + decoded
    value are stored.

    PropertySet.h lines 19-92 (struct definition and copy semantics).
    """
    type_hash: int = meta_member("mTypeHash", int)
    value: Any = meta_member("mValue", object)


# ---------------------------------------------------------------------------
# PropertySet dataclass
# ---------------------------------------------------------------------------

@meta_class("PropertySet")
@dataclass
class PropertySet:
    """Decoded representation of a Telltale PropertySet.

    Wire format per PropertySet.h lines 242-448
    (MetaOperation_SerializeAsync):

    Default member walk (PropertySet.h lines 227-235, each block-wrapped):
        mPropVersion  (int)
        mPropertyFlags (Flags/u32)
        mKeyMap       (DCArray<KeyInfo>) -- assumed SerializeDisable in TMI
        mParentList   (DCArray<ParentInfo>) -- assumed SerializeDisable in TMI
        mHOI          (HandleObjectInfo: Symbol mObjectName + Flags mFlags)

    Then a custom BeginBlock section (PropertySet.h line 276):
        u32 parents_count
        parents_count x u64 parent_symbol
        [v1 re-bracket: EndBlock + BeginBlock (lines 392-394)]
        u32 numtypes
        for each type:
            u64 typeSymbol
            u32 numvalues
            for each value:
                u64 keyName
                BeginObject("Key Value", false) == begin_block
                <typed payload via registered decoder>
                EndObject == end_block
        if mPropertyFlags & 0x400 (HasEmbedded):
            BeginObject("Embedded Properties", false) == begin_block
            <recursive PropertySet>
            EndObject == end_block
        EndBlock (closes custom section)
    """
    mPropVersion: int = meta_member("mPropVersion", int)
    mPropertyFlags: int = meta_member("mPropertyFlags", int)
    mHOI: Optional[Handle] = meta_member("mHOI", Handle)
    mParentList: List[int] = meta_member("mParentList", list)
    mProperties: dict = meta_member("mKeyMap", dict)
    mEmbeddedParentProps: Optional["PropertySet"] = meta_member(
        "mEmbeddedParentProps", object
    )


# ---------------------------------------------------------------------------
# KeyframedValue dataclasses
# ---------------------------------------------------------------------------

@dataclass
class KFSampleFloat:
    """One keyframe sample for KeyframedValue<float>.

    KeyframedValue.h lines 31-36 (Sample substruct):
        float mTime
        float mRecipTimeToNextSample  -- NOT serialized (line 32 comment)
        bool  mbInterpolateToNextKey
        EnumeTangentModes mTangentMode  (int)
        T mValue
    """
    mTime: float
    mbInterpolateToNextKey: bool
    mTangentMode: int
    mValue: float


@dataclass
class KFSampleBool:
    """One keyframe sample for KeyframedValue<bool>."""
    mTime: float
    mbInterpolateToNextKey: bool
    mTangentMode: int
    mValue: bool


@dataclass
class KFSampleInt:
    """One keyframe sample for KeyframedValue<int>."""
    mTime: float
    mbInterpolateToNextKey: bool
    mTangentMode: int
    mValue: int


@dataclass
class KFSampleU64:
    """One keyframe sample for KeyframedValue<u64>."""
    mTime: float
    mbInterpolateToNextKey: bool
    mTangentMode: int
    mValue: int


@dataclass
class KFSampleVector3:
    """One keyframe sample for KeyframedValue<Vector3>."""
    mTime: float
    mbInterpolateToNextKey: bool
    mTangentMode: int
    mValue_x: float
    mValue_y: float
    mValue_z: float


@meta_class("KeyframedValue<float>")
@dataclass
class KeyframedValueFloat:
    """KeyframedValue<float> per KeyframedValue.h lines 29-48.

    Explicit instantiation: template class KeyframedValue<float> (line 51).
    Fields: mMinVal (float), mMaxVal (float), mSamples (DCArray<Sample>).
    """
    mMinVal: float = meta_member("mMinVal", float)
    mMaxVal: float = meta_member("mMaxVal", float)
    mSamples: List[KFSampleFloat] = meta_member("mSamples", list)


@meta_class("KeyframedValue<bool>")
@dataclass
class KeyframedValueBool:
    """KeyframedValue<bool> per KeyframedValue.h lines 29-48, line 52."""
    mMinVal: bool = meta_member("mMinVal", bool)
    mMaxVal: bool = meta_member("mMaxVal", bool)
    mSamples: List[KFSampleBool] = meta_member("mSamples", list)


@meta_class("KeyframedValue<int>")
@dataclass
class KeyframedValueInt:
    """KeyframedValue<int> per KeyframedValue.h lines 29-48, line 53."""
    mMinVal: int = meta_member("mMinVal", int)
    mMaxVal: int = meta_member("mMaxVal", int)
    mSamples: List[KFSampleInt] = meta_member("mSamples", list)


@meta_class("KeyframedValue<u64>")
@dataclass
class KeyframedValueU64:
    """KeyframedValue<u64> per KeyframedValue.h lines 29-48, line 54."""
    mMinVal: int = meta_member("mMinVal", int)
    mMaxVal: int = meta_member("mMaxVal", int)
    mSamples: List[KFSampleU64] = meta_member("mSamples", list)


@meta_class("KeyframedValue<Vector3>")
@dataclass
class KeyframedValueVector3:
    """KeyframedValue<Vector3> — additional Phase 5 registration.

    Vector3 is not an explicit template instantiation in KeyframedValue.h
    but IS observed in EP1 chore editor props. Registered here so the
    decode dispatcher can handle it without a skip_block fallthrough.
    """
    mMinVal_x: float = meta_member("mMinVal_x", float)
    mMinVal_y: float = meta_member("mMinVal_y", float)
    mMinVal_z: float = meta_member("mMinVal_z", float)
    mMaxVal_x: float = meta_member("mMaxVal_x", float)
    mMaxVal_y: float = meta_member("mMaxVal_y", float)
    mMaxVal_z: float = meta_member("mMaxVal_z", float)
    mSamples: List[KFSampleVector3] = meta_member("mSamples", list)


# ---------------------------------------------------------------------------
# Decoder helpers
# ---------------------------------------------------------------------------

def _decode_kf_sample_float(reader: MetaStreamReader, sv: int) -> KFSampleFloat:
    """Decode one KeyframedValue<float>::Sample.

    Wire frame per KeyframedValue.h lines 31-36 (member-walked, each blocked
    except mRecipTimeToNextSample which is NOT serialized):
        begin_block; mTime (f32); end_block
        begin_block; mbInterpolateToNextKey (u8/bool); end_block
        begin_block; mTangentMode (i32); end_block
        begin_block; mValue (f32); end_block
    """
    reader.begin_block()
    t = reader.read_float32()
    reader.end_block()
    reader.begin_block()
    interp = reader.read_uint8() != 0
    reader.end_block()
    reader.begin_block()
    tangent = reader.read_int32()
    reader.end_block()
    reader.begin_block()
    v = reader.read_float32()
    reader.end_block()
    return KFSampleFloat(mTime=t, mbInterpolateToNextKey=interp, mTangentMode=tangent, mValue=v)


def _decode_kf_sample_bool(reader: MetaStreamReader, sv: int) -> KFSampleBool:
    reader.begin_block()
    t = reader.read_float32()
    reader.end_block()
    reader.begin_block()
    interp = reader.read_uint8() != 0
    reader.end_block()
    reader.begin_block()
    tangent = reader.read_int32()
    reader.end_block()
    reader.begin_block()
    v = reader.read_uint8() != 0
    reader.end_block()
    return KFSampleBool(mTime=t, mbInterpolateToNextKey=interp, mTangentMode=tangent, mValue=v)


def _decode_kf_sample_int(reader: MetaStreamReader, sv: int) -> KFSampleInt:
    reader.begin_block()
    t = reader.read_float32()
    reader.end_block()
    reader.begin_block()
    interp = reader.read_uint8() != 0
    reader.end_block()
    reader.begin_block()
    tangent = reader.read_int32()
    reader.end_block()
    reader.begin_block()
    v = reader.read_int32()
    reader.end_block()
    return KFSampleInt(mTime=t, mbInterpolateToNextKey=interp, mTangentMode=tangent, mValue=v)


def _decode_kf_sample_u64(reader: MetaStreamReader, sv: int) -> KFSampleU64:
    reader.begin_block()
    t = reader.read_float32()
    reader.end_block()
    reader.begin_block()
    interp = reader.read_uint8() != 0
    reader.end_block()
    reader.begin_block()
    tangent = reader.read_int32()
    reader.end_block()
    reader.begin_block()
    v = reader.read_uint64()
    reader.end_block()
    return KFSampleU64(mTime=t, mbInterpolateToNextKey=interp, mTangentMode=tangent, mValue=v)


def _decode_kf_sample_vector3(reader: MetaStreamReader, sv: int) -> KFSampleVector3:
    reader.begin_block()
    t = reader.read_float32()
    reader.end_block()
    reader.begin_block()
    interp = reader.read_uint8() != 0
    reader.end_block()
    reader.begin_block()
    tangent = reader.read_int32()
    reader.end_block()
    # Vector3 is block-wrapped as a whole (member-walked with blocking enabled)
    reader.begin_block()
    vx = reader.read_float32()
    vy = reader.read_float32()
    vz = reader.read_float32()
    reader.end_block()
    return KFSampleVector3(
        mTime=t, mbInterpolateToNextKey=interp, mTangentMode=tangent,
        mValue_x=vx, mValue_y=vy, mValue_z=vz,
    )


def _decode_dcarray_samples(reader, sv, sample_decoder):
    """Decode DCArray<Sample> for any KeyframedValue<T>.

    DCArray wire frame (telltale/meta_containers.py decode_dcarray):
        [u32 count][u32 block_size (includes 4-byte prefix)][count * elem]
    """
    count = reader.read_uint32()
    # Block wraps all elements together (DCArray outer block)
    reader.begin_block()
    samples = [sample_decoder(reader, sv) for _ in range(count)]
    reader.end_block()
    return samples


def _make_keyframed_decoder(min_decoder, max_decoder, sample_decoder):
    """Factory: return a decode_keyframed_value_T function for one T.

    The wire frame for KeyframedValue<T> mirrors the default member walker:
        begin_block; mMinVal; end_block
        begin_block; mMaxVal; end_block
        [DCArray<Sample> frame: u32 count + outer block]
    """
    def _decode(reader: MetaStreamReader, sv: int):
        reader.begin_block()
        min_val = min_decoder(reader, sv)
        reader.end_block()
        reader.begin_block()
        max_val = max_decoder(reader, sv)
        reader.end_block()
        samples = _decode_dcarray_samples(reader, sv, sample_decoder)
        return (min_val, max_val, samples)
    return _decode


def _read_float(r, sv): return r.read_float32()
def _read_bool(r, sv): return r.read_uint8() != 0
def _read_int32(r, sv): return r.read_int32()
def _read_uint64(r, sv): return r.read_uint64()


def _read_vector3(r, sv):
    return (r.read_float32(), r.read_float32(), r.read_float32())


# ---------------------------------------------------------------------------
# Public KeyframedValue<T> decoders
# ---------------------------------------------------------------------------

def decode_keyframed_value_float(reader: MetaStreamReader, sv: int) -> KeyframedValueFloat:
    """Decode KeyframedValue<float> per KeyframedValue.h lines 38-39."""
    reader.begin_block()
    min_val = reader.read_float32()
    reader.end_block()
    reader.begin_block()
    max_val = reader.read_float32()
    reader.end_block()
    samples = _decode_dcarray_samples(reader, sv, _decode_kf_sample_float)
    return KeyframedValueFloat(mMinVal=min_val, mMaxVal=max_val, mSamples=samples)


def decode_keyframed_value_bool(reader: MetaStreamReader, sv: int) -> KeyframedValueBool:
    """Decode KeyframedValue<bool> per KeyframedValue.h lines 38-39, line 52."""
    reader.begin_block()
    min_val = reader.read_uint8() != 0
    reader.end_block()
    reader.begin_block()
    max_val = reader.read_uint8() != 0
    reader.end_block()
    samples = _decode_dcarray_samples(reader, sv, _decode_kf_sample_bool)
    return KeyframedValueBool(mMinVal=min_val, mMaxVal=max_val, mSamples=samples)


def decode_keyframed_value_int(reader: MetaStreamReader, sv: int) -> KeyframedValueInt:
    """Decode KeyframedValue<int> per KeyframedValue.h line 53."""
    reader.begin_block()
    min_val = reader.read_int32()
    reader.end_block()
    reader.begin_block()
    max_val = reader.read_int32()
    reader.end_block()
    samples = _decode_dcarray_samples(reader, sv, _decode_kf_sample_int)
    return KeyframedValueInt(mMinVal=min_val, mMaxVal=max_val, mSamples=samples)


def decode_keyframed_value_u64(reader: MetaStreamReader, sv: int) -> KeyframedValueU64:
    """Decode KeyframedValue<u64> per KeyframedValue.h line 54."""
    reader.begin_block()
    min_val = reader.read_uint64()
    reader.end_block()
    reader.begin_block()
    max_val = reader.read_uint64()
    reader.end_block()
    samples = _decode_dcarray_samples(reader, sv, _decode_kf_sample_u64)
    return KeyframedValueU64(mMinVal=min_val, mMaxVal=max_val, mSamples=samples)


def decode_keyframed_value_vector3(reader: MetaStreamReader, sv: int) -> KeyframedValueVector3:
    """Decode KeyframedValue<Vector3>. Each component triple is block-wrapped."""
    # mMinVal (Vector3 blocked)
    reader.begin_block()
    min_x = reader.read_float32()
    min_y = reader.read_float32()
    min_z = reader.read_float32()
    reader.end_block()
    # mMaxVal (Vector3 blocked)
    reader.begin_block()
    max_x = reader.read_float32()
    max_y = reader.read_float32()
    max_z = reader.read_float32()
    reader.end_block()
    samples = _decode_dcarray_samples(reader, sv, _decode_kf_sample_vector3)
    return KeyframedValueVector3(
        mMinVal_x=min_x, mMinVal_y=min_y, mMinVal_z=min_z,
        mMaxVal_x=max_x, mMaxVal_y=max_y, mMaxVal_z=max_z,
        mSamples=samples,
    )


# ---------------------------------------------------------------------------
# PropertySet decoder
# ---------------------------------------------------------------------------

def decode_propertyset(reader: MetaStreamReader, stream_version: int) -> PropertySet:
    """Decode a PropertySet from the reader.

    Implements the wire frame from PropertySet.h lines 242-448
    (MetaOperation_SerializeAsync), supporting two serialization sub-formats
    detected via a peek at the first u32 in the member region:

    FORMAT A — BLOCKED (standard synthetic / MSV5/MSV6 serialization):
        Detected by: peek_uint32() == 8.  Each declared member is individually
        block-wrapped (block_size=8 for a u32 member).

    FORMAT B — INLINE (observed in real EP1 MTRE hint chores; validated against
        guybrush_hint_usenose_e2_135.chore, glassblowermechanisms.chore,
        guybrush_hint_usenose_e3_136.chore at commit time of plan 05-02):
        Detected by: peek_uint32() != 8.  Members are NOT individually block-
        wrapped (MetaSerializeBlockingDisabled-style layout).  mHOI is
        SerializeDisabled (zero wire bytes).  One padding byte follows
        mPropertyFlags before the custom section block.

    Step 1 — default member walker (PropertySet.h line 263):
        Members in declaration order (PropertySet.h lines 227-235):
          mPropVersion  (int32 / blocked or inline)
          mPropertyFlags (Flags/u32 / blocked or inline)
          mKeyMap, mParentList: SerializeDisable — no wire bytes in either format.
          mHOI (HandleObjectInfo.h lines 14-16): blocked in FORMAT A;
               SerializeDisabled (0 bytes) + 1-byte padding in FORMAT B.

    Step 2 — custom BeginBlock section (PropertySet.h line 276):
        u32 parents_count
        parents_count x u64 parent_symbol  (bare serialize_Symbol)
        [v1 re-bracket: EndBlock + BeginBlock — PropertySet.h lines 392-394]
        u32 numtypes
        for each type:
            u64 typeSymbol  (bare serialize_Symbol)
            u32 numvalues
            for each value:
                u64 keyName  (bare serialize_Symbol)
                BeginObject("Key Value", false) == begin_block
                <typed payload via registered decoder OR skip_block>
                EndObject == end_block
        if mPropertyFlags & 0x400 (HasEmbedded):
            BeginObject("Embedded Properties", false) == begin_block
            <recursive decode_propertyset>
            EndObject == end_block
        EndBlock (closes custom section opened at line 276)

    Note on Symbol serialization: the MTRE Map-key debug-strlen trailing u32
    is a container artifact for Map<Symbol, V> only (meta_containers.py).
    PropertySet's own bare serialize_Symbol calls are plain u64 reads with no
    trailing u32 on any format version. Confirmed empirically in plan 05-02.
    """
    # ---- detect format (peek at first u32) ----
    # In FORMAT A (blocked), the first u32 is the block_size for the mPropVersion
    # member block, which is always 8 (size prefix 4 + payload 4 for a u32/i32).
    # In FORMAT B (inline), the first u32 is the mPropVersion VALUE (typically 0,
    # 1, or 2 for known EP1 chores), never 8.
    _first_u32 = reader.peek_uint32()
    _inline = (_first_u32 != 8)

    if _inline:
        # FORMAT B: inline reads; mHOI SerializeDisabled + 1-byte pad before custom section.
        # Validated against the 3 EP1 hint chores (guybrush_hint_usenose_e2_135.chore,
        # glassblowermechanisms.chore, guybrush_hint_usenose_e3_136.chore).
        mPropVersion = reader.read_uint32()
        mPropertyFlags = reader.read_uint32()
        # mHOI is SerializeDisabled in the real MTRE chore format; 1 padding byte follows.
        reader.skip(1)
        mHOI = Handle(object_name_crc=0, object_name_str=None)
    else:
        # FORMAT A: standard per-member block-wrapped reads (synthetic test fixtures).
        reader.begin_block()
        mPropVersion = reader.read_int32()
        reader.end_block()

        reader.begin_block()
        mPropertyFlags = reader.read_uint32()
        reader.end_block()

        # mKeyMap + mParentList: SerializeDisable — no wire bytes.
        # Reference: PropertySet.h lines 230-232 (DCArray members).

        # mHOI (HandleObjectInfo, blocked)
        # HandleObjectInfo.h lines 14-16: Symbol mObjectName (u64) + Flags mFlags (u32)
        reader.begin_block()
        hoi_sym = reader.read_uint64()      # mObjectName Symbol CRC
        reader.read_uint32()                # mFlags (consumed but not stored)
        reader.end_block()
        mHOI = Handle(object_name_crc=hoi_sym, object_name_str=None)

    # ---- custom section (PropertySet.h line 276 BeginBlock) ----
    reader.begin_block()

    parents_count = reader.read_uint32()
    mParentList = [reader.read_uint64() for _ in range(parents_count)]

    # v1-only re-bracket (PropertySet.h lines 392-394 read-path)
    if mPropVersion == 1:
        reader.end_block()
        reader.begin_block()

    numtypes = reader.read_uint32()
    mProperties: dict = {}

    for _ in range(numtypes):
        type_symbol = reader.read_uint64()      # typeSymbol CRC
        num_values = reader.read_uint32()
        value_decoder = get_decoder_by_hash(type_symbol)

        if value_decoder is None:
            log.warning(
                "decode_propertyset: unknown type hash %#018x — skipping %d values",
                type_symbol,
                num_values,
            )

        for _ in range(num_values):
            key_name = reader.read_uint64()     # keyName Symbol CRC
            if value_decoder is None:
                # INFRA-04 skip-unknown path (PropertySet.h lines 405-412)
                reader.skip_block()
                mProperties[key_name] = UnknownPropertyValue(type_hash=type_symbol)
            else:
                reader.begin_block()            # BeginObject("Key Value", false)
                mProperties[key_name] = value_decoder(reader, stream_version)
                reader.end_block()              # EndObject("Key Value")

    # Embedded parent PropertySet (mPropertyFlags & ePropertyFlag_HasEmbedded)
    # PropertySet.h lines 432-438 read-path
    mEmbedded: Optional[PropertySet] = None
    if mPropertyFlags & PropertyFlag_HasEmbedded:
        reader.begin_block()                    # BeginObject("Embedded Properties", false)
        mEmbedded = decode_propertyset(reader, stream_version)
        reader.end_block()                      # EndObject("Embedded Properties")

    reader.end_block()                          # closes custom section (line 276)

    return PropertySet(
        mPropVersion=mPropVersion,
        mPropertyFlags=mPropertyFlags,
        mHOI=mHOI,
        mParentList=mParentList,
        mProperties=mProperties,
        mEmbeddedParentProps=mEmbedded,
    )


# ---------------------------------------------------------------------------
# decode_property_value: standalone tagged-variant dispatcher
# ---------------------------------------------------------------------------

def decode_property_value(reader: MetaStreamReader, stream_version: int) -> Any:
    """Decode a standalone tagged property value (type_hash + block payload).

    Used when a caller (Phase 6+) holds a bare tagged variant outside the
    PropertySet envelope. NOT used inside decode_propertyset (which inlines
    the type-grouped loop for efficiency).

    Wire format:
        u64 type_hash
        [u32 block_size][payload]   (begin_block / end_block frame)

    On unknown type_hash: call skip_block() (consumes the block) and return
    UnknownPropertyValue(type_hash=...) sentinel.  Never raises.
    """
    type_hash = reader.read_uint64()
    decoder = get_decoder_by_hash(type_hash)
    if decoder is None:
        log.warning(
            "decode_property_value: unknown type hash %#018x — skip_block",
            type_hash,
        )
        reader.skip_block()
        return UnknownPropertyValue(type_hash=type_hash)
    reader.begin_block()
    value = decoder(reader, stream_version)
    reader.end_block()
    return value


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register_propertyset_decoders() -> None:
    """Register PropertySet + KeyframedValue<T> decoders into _DECODERS.

    @meta_class decorators above have already populated _REGISTRY for each
    type; here we only add the decoder entries (decoder_only=True) so the
    dataclass binding is not overwritten — same pattern as meta_ptable.py.

    PropertyValue is intentionally NOT registered as a decoder because it has
    no standalone on-disk form; the @meta_class registration for reflection
    purposes is sufficient.
    """
    register("PropertySet",             decode_propertyset,             decoder_only=True)
    register("KeyframedValue<float>",   decode_keyframed_value_float,   decoder_only=True)
    register("KeyframedValue<bool>",    decode_keyframed_value_bool,    decoder_only=True)
    register("KeyframedValue<int>",     decode_keyframed_value_int,     decoder_only=True)
    register("KeyframedValue<u64>",     decode_keyframed_value_u64,     decoder_only=True)
    register("KeyframedValue<Vector3>", decode_keyframed_value_vector3, decoder_only=True)
    log.debug("registered PropertySet + 5 KeyframedValue<T> decoders")


_register_propertyset_decoders()

# ---------------------------------------------------------------------------
# Public convenience alias (plan success-criteria import)
# ---------------------------------------------------------------------------

# The plan's success-criteria import checks:
#   from telltale.meta_propertyset import ... KeyframedValue
# We expose KeyframedValueFloat as the canonical alias for the primary
# template instantiation; all five concrete classes are also importable
# by their full names.
KeyframedValue = KeyframedValueFloat


# ---------------------------------------------------------------------------
# Plan 05-02: Chore-to-mEditorProps skipper + validation harness
# ---------------------------------------------------------------------------

def _effective_sv(format_version_str: str) -> int:
    """Map a MetaStream format version string to an integer stream version.

    Returns 3 for 'MTRE' (the EP1 hint chore format) and -1 for any
    unrecognised format string.  This is the integer that PropertySet
    and container decoders receive as ``stream_version``.

    Pattern borrowed from ``tests/test_meta_containers_ptable_integration.py``.
    """
    _MAP = {"MTRE": 3, "MSV5": 5, "MSV6": 6, "MBIN": 1}
    return _MAP.get(format_version_str, -1)


def _walk_to_editor_props(
    reader: MetaStreamReader,
    format_version_str: str,
    total_len: int,
    data_bytes: bytes,
) -> tuple:
    """Advance *reader* to the mEditorProps PropertySet block in a Chore file.

    Returns ``(block_start, block_end_abs)`` — the coordinates of the
    block_size-prefixed PropertySet block.  After this call ``reader.pos``
    equals ``block_start``.  The caller is responsible for calling
    ``reader.begin_block()`` before ``decode_propertyset()``.

    EMPIRICAL SKIPPER — validated against the 3 EP1 hint chores at plan 05-02
    commit time (2026-04-20).  Phase 7 will replace this with a proper Chore
    decoder derived from iOS Chore::SerializeAsync disasm.

    Observed Outcome (plan 05-02 empirical byte analysis):
        The 48-byte block immediately following the mName String block IS the
        mEditorProps PropertySet member block (Outcome A, MTRE format).
        All 3 hint chores share the same skeleton:

            [data_offset .. mname_end]:   mName String block (variable size)
            [mname_end .. mname_end+48]:  mEditorProps PropertySet block (size=48)

        Files validated:
            guybrush_hint_usenose_e2_135.chore  (184 B): mname_end=98,  PropSet=[98..146]
            glassblowermechanisms.chore          (189 B): mname_end=91,  PropSet=[91..139]
            guybrush_hint_usenose_e3_136.chore  (184 B): mname_end=98,  PropSet=[98..146]

        Inside the PropertySet block, members use inline (blocking-disabled) reads
        rather than per-member block wrappers as observed in standard TMI usage.
        See decode_propertyset() FORMAT B branch for the exact read sequence.

    Parameters
    ----------
    reader : MetaStreamReader
        Positioned at ``data_offset`` (start of the payload, set by __init__).
    format_version_str : str
        The ``header.version`` string (e.g. ``'MTRE'``).  Only MTRE is
        supported for Phase 5; other formats raise ``AssertionError``.
    total_len : int
        Total length of the file in bytes (used for future sanity checks).
    data_bytes : bytes
        Full file content (used to read the block_size prefix without
        disturbing the reader position).
    """
    assert format_version_str == "MTRE", (
        f"Phase 5 only supports MTRE hint chores; got {format_version_str!r}"
    )

    # Skip the mName String block — the PropertySet block follows immediately.
    reader.skip_block()

    # Record the PropertySet block coordinates.
    block_start = reader.pos
    blk_size = struct.unpack_from("<I", data_bytes, block_start)[0]
    block_end_abs = block_start + blk_size

    # Sanity-check: for the 3 hint chores the block size MUST equal
    # EXPECTED_EMPTY_PROPSET_BYTES (48).  A different value indicates Chore
    # schema drift or a corpus file that lies outside the Phase 5 scope.
    if blk_size != EXPECTED_EMPTY_PROPSET_BYTES:
        raise ValueError(
            f"Expected mEditorProps block size {EXPECTED_EMPTY_PROPSET_BYTES}, "
            f"got {blk_size} at offset {block_start} in {total_len}-byte file "
            f"— Chore schema drift? (Phase 7 decoder required)"
        )

    return (block_start, block_end_abs)


def validate_propertyset_corpus(paths: Iterable) -> ChoreValidationReport:
    """Validate PropertySet (mEditorProps) decoding across a set of Chore files.

    For each file:
      1. Parse the MTRE header.
      2. Use ``_walk_to_editor_props`` to locate the mEditorProps block.
      3. Call ``decode_propertyset`` and check ``reader.pos == block_end_abs``.
      4. Record clean / misalignment in the returned report.

    Exceptions (I/O errors, schema drift, unexpected EOFError) are caught and
    recorded as misalignment entries with an ``"exception: ..."`` message.

    Returns
    -------
    ChoreValidationReport
        ``summary()`` is ``'3/3 clean (0 misaligned)'`` when all 3 EP1 hint
        chores pass.  VALIDATE-02 is closed when this assertion holds.
    """
    report = ChoreValidationReport()
    for p in paths:
        p = Path(p)
        reader = None
        try:
            data = p.read_bytes()
            header = parse_header(data)
            reader = MetaStreamReader(data, header=header, debug=False)
            sv = _effective_sv(header.version)
            block_start, block_end_abs = _walk_to_editor_props(
                reader, header.version, len(data), data
            )
            assert reader.pos == block_start, (
                f"reader.pos={reader.pos} != block_start={block_start}"
            )
            reader.begin_block()
            decode_propertyset(reader, sv)
            reader.end_block()
            if reader.pos == block_end_abs:
                report.record_clean(str(p))
            else:
                report.record_misalignment(
                    str(p),
                    reader.pos,
                    block_end_abs,
                    reader.pos,
                    f"pos {reader.pos} != block_end_abs {block_end_abs}",
                )
        except Exception as exc:
            pos = reader.pos if reader is not None else -1
            report.record_misalignment(
                str(p),
                pos,
                0,
                0,
                f"exception: {type(exc).__name__}: {exc}",
            )
    return report
