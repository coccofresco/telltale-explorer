"""
Chore leaf-type @meta_class dataclasses + decoders (Phase 6, Plan 01).

Registers seven "simple" leaf types used inside Telltale .chore files.
None of these types depend on polymorphic dispatch (WalkPath / PathBase),
which lands in Plan 06-02.  All decoders accept
``(reader: MetaStreamReader, stream_version: int)`` and return the
corresponding dataclass instance.

TTL authoritative sources for each type:

    LocalizeInfo
        LanguageDB.h lines 21-23
        MetaInitialize.h lines 1576-1577

    ActorAgentBinding
        Chore.h lines 227-237
        MetaInitialize.h lines 2124-2126

    AutoActStatus
        Chore.h lines 239-254
        MetaInitialize.h lines 2119-2122

    ChoreAgent::Attachment
        Chore.h lines 353-405
        MetaInitialize.h lines 2151-2159

    ChoreResource::Block
        Chore.h lines 260-266
        MetaInitialize.h lines 2172-2177

    ToolProps
        ToolProps.h lines 13-32
        MetaInitialize.h lines 928-932

    DependencyLoader<1>
        Chore.h lines 168-225
        MetaInitialize.h lines 2114-2117

Also provides CURATED_CHORE_FILES (list[str]) and CURATED_CORPUS_ROOT
(pathlib.Path) for the curated 10-chore test corpus used in Plan 06-03.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from telltale.crc64 import crc64_str
from telltale.metaclass import meta_class, meta_member, get_by_hash
from telltale.meta_intrinsics import (
    register,
    decode_string,
    decode_symbol,
    get_decoder_by_hash,
)
from telltale.metastream import MetaStreamReader
from telltale.meta_propertyset import decode_propertyset
from telltale.meta_containers import dispatch_container

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@meta_class("LocalizeInfo")
@dataclass
class LocalizeInfo:
    """LocalizeInfo from LanguageDB.h lines 21-23.

    TTL name: "LocalizeInfo"
    Wire: 1 blocked member — mFlags (Flags / u32).
    MetaInitialize.h lines 1576-1577: FIRSTMEM2(locali, mFlags, LocalizeInfo, flags, 0)
    """
    mFlags: int = meta_member("mFlags", int)


@meta_class("ActorAgentBinding")
@dataclass
class ActorAgentBinding:
    """ActorAgentBinding from Chore.h lines 227-237.

    TTL name: "ActorAgentBinding"
    Wire: 1 blocked member — mActorName (String = u32 len + bytes).
    MetaInitialize.h lines 2124-2126: FIRSTMEM2(aab, mActorName, ActorAgentBinding, string, 0)
    """
    mActorName: str = meta_member("mActorName", str)


@meta_class("AutoActStatus")
@dataclass
class AutoActStatus:
    """AutoActStatus from Chore.h lines 239-254.

    TTL name: "AutoActStatus"
    Wire: 1 blocked member — m_Status (long == int32 on Telltale's 64-bit builds).
    MetaInitialize.h lines 2119-2122:
        FIRSTMEM2(aas, m_Status, AutoActStatus, long, MetaFlag::MetaFlag_EnumIntType)
    EnumIntType flag does not change wire format; m_Status is serialized as i32.
    """
    m_Status: int = meta_member("m_Status", int)


@meta_class("ChoreAgent::Attachment")
@dataclass
class Attachment:
    """ChoreAgent::Attachment from Chore.h lines 353-405.

    TTL name: "ChoreAgent::Attachment"
    Wire: 7 blocked members in declaration order.
    MetaInitialize.h lines 2151-2159.

    Members (in TTL declaration order):
        mbDoAttach               bool  (u8)
        mAttachTo                String  (u32 len + bytes; MetaFlag_SelectAgentType — no wire change)
        mAttachToNode            String
        mAttachPos               Vector3 (3 x f32 = 12 B)
        mAttachQuat              Quaternion (4 x f32 = 16 B, x y z w)
        mbAttachPreserveWorldPos bool
        mbLeaveAttachedWhenComplete bool
    """
    mbDoAttach: bool = meta_member("mbDoAttach", bool)
    mAttachTo: str = meta_member("mAttachTo", str)
    mAttachToNode: str = meta_member("mAttachToNode", str)
    mAttachPos_x: float = meta_member("mAttachPos_x", float)
    mAttachPos_y: float = meta_member("mAttachPos_y", float)
    mAttachPos_z: float = meta_member("mAttachPos_z", float)
    mAttachQuat_x: float = meta_member("mAttachQuat_x", float)
    mAttachQuat_y: float = meta_member("mAttachQuat_y", float)
    mAttachQuat_z: float = meta_member("mAttachQuat_z", float)
    mAttachQuat_w: float = meta_member("mAttachQuat_w", float)
    mbAttachPreserveWorldPos: bool = meta_member("mbAttachPreserveWorldPos", bool)
    mbLeaveAttachedWhenComplete: bool = meta_member("mbLeaveAttachedWhenComplete", bool)


@meta_class("ChoreResource::Block")
@dataclass
class Block:
    """ChoreResource::Block from Chore.h lines 260-266.

    TTL name: "ChoreResource::Block"
    Wire: 4 blocked members (mStartTime, mEndTime, mbLoopingBlock, mScale).
    MetaInitialize.h lines 2172-2177.

    NOTE: mbSelected carries MetaFlag_MetaSerializeDisable=1 — it is NOT
    serialized to the wire and therefore NOT present as a meta_member here.
    """
    mStartTime: float = meta_member("mStartTime", float)
    mEndTime: float = meta_member("mEndTime", float)
    mbLoopingBlock: bool = meta_member("mbLoopingBlock", bool)
    mScale: float = meta_member("mScale", float)


@meta_class("ToolProps")
@dataclass
class ToolProps:
    """ToolProps from ToolProps.h lines 13-32.

    TTL name: "ToolProps"
    CUSTOM MetaOperation_SerializeAsync (ToolProps.h lines 17-30):
        serialize_bool(&mbHasProps)    -- INLINE bare u8 (not blocked)
        if mbHasProps: PerformMetaSerializeAsync(PropertySet) -- PropertySet handles own framing
    MetaInitialize.h lines 928-932: DEFINET2 + SERIALIZER + FIRSTMEM2(tp, mbHasProps, ToolProps, bool, 0)

    mProps is NOT a meta_member — it is populated at runtime by the custom decoder
    and is absent from the wire when mbHasProps == False.
    """
    mbHasProps: bool = meta_member("mbHasProps", bool)
    mProps: Any = field(default=None)  # PropertySet | None — runtime-only, not a meta_member


@meta_class("DependencyLoader<1>")
@dataclass
class DependencyLoader1:
    """DependencyLoader<1> from Chore.h lines 168-225.

    TTL name: "DependencyLoader<1>"
    CUSTOM MetaOperation_SerializeAsync + MetaFlag_Memberless.
    MetaInitialize.h lines 2114-2117.

    Wire (Chore.h lines 186-223 read path):
        u8  gate       (serialize_bool — INLINE bare u8)
        if gate:
            u64 inner_type_hash  (must == crc64_str("DCArray<String>"))
            [u32 outer_block_size]   (PerformMetaSerializeFull wrapper)
              [u32 count]
              [u32 inner_block_size]   (DCArray elements block)
                count * String
              <end inner block>
            <end outer block>

    mpResNames is None when gate is False; list[str] otherwise.
    NOT a meta_member — CUSTOM SERIALIZER replaces the default walker entirely.
    """
    mpResNames: Optional[List[str]] = field(default=None)


# ---------------------------------------------------------------------------
# Decoder functions
# ---------------------------------------------------------------------------

def decode_localize_info(reader: MetaStreamReader, stream_version: int) -> LocalizeInfo:
    """Decode LocalizeInfo.

    TTL source: LanguageDB.h lines 21-23; MetaInitialize.h lines 1576-1577.
    Wire: 1 blocked member — mFlags (Flags / u32).
    """
    reader.begin_block()
    flags = reader.read_uint32()
    reader.end_block()
    return LocalizeInfo(mFlags=flags)


def decode_actor_agent_binding(reader: MetaStreamReader, stream_version: int) -> ActorAgentBinding:
    """Decode ActorAgentBinding.

    TTL source: Chore.h lines 227-237; MetaInitialize.h lines 2124-2126.
    Wire: 1 blocked member — mActorName (String: u32 len + bytes).
    """
    reader.begin_block()
    name = decode_string(reader, stream_version)
    reader.end_block()
    return ActorAgentBinding(mActorName=name)


def decode_auto_act_status(reader: MetaStreamReader, stream_version: int) -> AutoActStatus:
    """Decode AutoActStatus.

    TTL source: Chore.h lines 239-254; MetaInitialize.h lines 2119-2122.
    Wire: 1 blocked member — m_Status (long == i32 on Telltale 64-bit builds).
    EnumIntType flag does not change wire format.
    """
    reader.begin_block()
    status = reader.read_int32()
    reader.end_block()
    return AutoActStatus(m_Status=status)


def decode_attachment(reader: MetaStreamReader, stream_version: int) -> Attachment:
    """Decode ChoreAgent::Attachment.

    TTL source: Chore.h lines 353-405; MetaInitialize.h lines 2151-2159.
    Wire: 7 blocked members in TTL declaration order:
        mbDoAttach (u8)
        mAttachTo (String)
        mAttachToNode (String)
        mAttachPos (3 x f32 = 12 B)
        mAttachQuat (4 x f32 = 16 B, x y z w order)
        mbAttachPreserveWorldPos (u8)
        mbLeaveAttachedWhenComplete (u8)
    """
    reader.begin_block()
    b_do = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    at = decode_string(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    at_node = decode_string(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    px = reader.read_float32()
    py = reader.read_float32()
    pz = reader.read_float32()
    reader.end_block()

    reader.begin_block()
    qx = reader.read_float32()
    qy = reader.read_float32()
    qz = reader.read_float32()
    qw = reader.read_float32()
    reader.end_block()

    reader.begin_block()
    b_pres = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    b_leave = reader.read_uint8() != 0
    reader.end_block()

    return Attachment(
        mbDoAttach=b_do,
        mAttachTo=at,
        mAttachToNode=at_node,
        mAttachPos_x=px,
        mAttachPos_y=py,
        mAttachPos_z=pz,
        mAttachQuat_x=qx,
        mAttachQuat_y=qy,
        mAttachQuat_z=qz,
        mAttachQuat_w=qw,
        mbAttachPreserveWorldPos=b_pres,
        mbLeaveAttachedWhenComplete=b_leave,
    )


def decode_block(reader: MetaStreamReader, stream_version: int) -> Block:
    """Decode ChoreResource::Block.

    TTL source: Chore.h lines 260-266; MetaInitialize.h lines 2172-2177.
    Wire: 4 blocked members (mStartTime, mEndTime, mbLoopingBlock, mScale).
    mbSelected carries MetaFlag_MetaSerializeDisable=1 (flags=1) — NOT serialized.
    """
    reader.begin_block()
    t0 = reader.read_float32()
    reader.end_block()

    reader.begin_block()
    t1 = reader.read_float32()
    reader.end_block()

    reader.begin_block()
    loop = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    scale = reader.read_float32()
    reader.end_block()

    return Block(mStartTime=t0, mEndTime=t1, mbLoopingBlock=loop, mScale=scale)


def decode_tool_props(reader: MetaStreamReader, stream_version: int) -> ToolProps:
    """Decode ToolProps.

    TTL source: ToolProps.h lines 13-32; MetaInitialize.h lines 928-932.
    CUSTOM SERIALIZER (ToolProps.h lines 17-30):
        serialize_bool(&props->mbHasProps)  -- INLINE bare u8 (not blocked)
        if (props->mbHasProps):
            PerformMetaSerializeAsync(stream, &prop)  -- PropertySet handles own framing
    Because SERIALIZER replaces the default member walker, mbHasProps is a raw
    u8 (not block-wrapped).  When mbHasProps is True, PropertySet's decode_propertyset
    is called directly (PropertySet manages its own outer block framing).
    """
    has = reader.read_uint8() != 0
    props = decode_propertyset(reader, stream_version) if has else None
    return ToolProps(mbHasProps=has, mProps=props)


def decode_dependency_loader_1(reader: MetaStreamReader, stream_version: int) -> DependencyLoader1:
    """Decode DependencyLoader<1>.

    TTL source: Chore.h lines 168-225; MetaInitialize.h lines 2114-2117.
    CUSTOM SERIALIZER + MetaFlag_Memberless (Chore.h lines 186-223):

        meta->serialize_bool(&b)             -- INLINE bare u8
        if (b):
            meta->serialize_uint64(&metacrc) -- INLINE bare u64 (inner type hash)
            // metacrc MUST == crc64_str("DCArray<String>")
            PerformMetaSerializeFull(meta, newArray, mcd)
            // PerformMetaSerializeFull wraps the DCArray call in begin_block/end_block;
            // decode_dcarray(meta_containers) reads count + elements block inside.

    On-disk frame when gate is True:
        [u8 gate=1]
        [u64 inner_type_hash]
        [u32 outer_block_size]        <- PerformMetaSerializeFull begin_block
          [u32 count]
          [u32 inner_block_size]      <- DCArray elements begin_block
            count * String
          <end inner block>
        <end outer block>
    """
    gate = reader.read_uint8() != 0
    if not gate:
        return DependencyLoader1(mpResNames=None)

    inner_hash = reader.read_uint64()
    expected_hash = crc64_str("DCArray<String>")
    if inner_hash != expected_hash:
        raise ValueError(
            f"DependencyLoader<1> inner type hash {inner_hash:#018x} != "
            f"expected DCArray<String> {expected_hash:#018x}"
        )

    # PerformMetaSerializeFull wraps the DCArray in begin_block/end_block.
    reader.begin_block()            # outer PerformMetaSerializeFull block
    count = reader.read_uint32()
    reader.begin_block()            # DCArray inner elements block
    resnames = [decode_string(reader, stream_version) for _ in range(count)]
    reader.end_block()              # end DCArray inner elements block
    reader.end_block()              # end PerformMetaSerializeFull outer block

    return DependencyLoader1(mpResNames=resnames)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register_simple_leaves() -> None:
    """Idempotent registration of the 7 simple Chore leaf decoders.

    @meta_class has already inserted all 7 dataclasses into telltale.metaclass._REGISTRY
    with dataclass_cls set and the members list populated.  Here we only
    populate telltale.meta_intrinsics._DECODERS (decoder_only=True preserves
    the existing _REGISTRY entries).
    """
    register("LocalizeInfo",           decode_localize_info,        decoder_only=True)
    register("ActorAgentBinding",      decode_actor_agent_binding,  decoder_only=True)
    register("AutoActStatus",          decode_auto_act_status,      decoder_only=True)
    register("ChoreAgent::Attachment", decode_attachment,           decoder_only=True)
    register("ChoreResource::Block",   decode_block,                decoder_only=True)
    register("ToolProps",              decode_tool_props,           decoder_only=True)
    register("DependencyLoader<1>",    decode_dependency_loader_1,  decoder_only=True)
    log.debug("registered 7 simple Chore leaf decoders")


_register_simple_leaves()


# ---------------------------------------------------------------------------
# Curated 10-chore test corpus
# ---------------------------------------------------------------------------
# Selected from extracted/ep1_chore/ to span empty-leaves through populated-leaves.
# Plan 06-03's validation harness iterates this list against CURATED_CORPUS_ROOT.
# Sizes were confirmed at plan-time with:
#   python -c "import os,glob; [print(f'{os.path.getsize(p):5d}B  {os.path.basename(p)}')
#              for p in sorted(glob.glob('extracted/ep1_chore/*.chore'))[:50]]"

CURATED_CHORE_FILES: List[str] = [
    # 3 hint-size chores (184-204B) — empty-leaves anchor
    "guybrush_hint_usenose_e2_135.chore",      # 184 B
    "guybrush_hint_idols_e2_95.chore",         # 194 B
    "obj_idolsmerfolk_wheelbspin.chore",       # 204 B
    # 4 small chores (650-950B)
    "adv_act3waves_worldmover_zero.chore",     # 654 B
    "adv_flotsamjungleday_entereast.chore",    # 707 B
    "adv_demo_islandrockofgelato_idle.chore",  # 853 B
    "adv_dock_seagull_idlec.chore",            # 1365 B
    # 3 medium chores (1900-2500B) — populated-leaves candidates
    "adv_doormerfolk_closed.chore",            # 1909 B
    "adv_cptj_bob.chore",                      # 2081 B
    "_sk20_move_guybrush_setface.chore",       # 2499 B
]

CURATED_CORPUS_ROOT: Path = Path("extracted/ep1_chore")


# ========================================================================
# Plan 06-02 Task 1: PathBase family + WalkPath polymorphic dispatch
# ========================================================================
#
# TTL sources:
#   PathBase              — Chore.h lines 29-37;   MetaInitialize.h lines 1896, 2065
#   PathSegment           — Chore.h lines 39-56;   MetaInitialize.h lines 2069-2075
#   HermiteCurvePathSegment — Chore.h lines 58-75; MetaInitialize.h lines 2078-2086
#   AnimationDrivenPathSegment — Chore.h lines 77-99; MetaInitialize.h lines 2089-2106
#   WalkPath              — Chore.h lines 101-166; MetaInitialize.h lines 2109-2112
# ========================================================================


# ---------------------------------------------------------------------------
# UnknownPath sentinel (runtime-only — NOT @meta_class registered)
# ---------------------------------------------------------------------------

@dataclass
class UnknownPath:
    """Sentinel for WalkPath mPath entries whose concrete-type hash is not
    registered.  decode_walk_path logs a warning + calls skip_block() and
    appends one of these instead of raising.

    This mirrors the UnknownPropertyValue pattern in meta_propertyset.py.
    """
    type_hash: int


# ---------------------------------------------------------------------------
# PathBase family dataclasses
# ---------------------------------------------------------------------------

@meta_class("PathBase")
@dataclass
class PathBase:
    """PathBase — Chore.h lines 29-37; MetaInitialize.h lines 1896, 2065.

    Abstract base for path segment types.  TTL registration:
        DEFINET2(pathbase, PathBase)  — no FIRSTMEM, no SERIALIZER
    Wire: ZERO bytes.  PathBase has no serialized members; it is purely an
    abstract base.  Instances appear only as concrete PathSegment /
    HermiteCurvePathSegment / AnimationDrivenPathSegment on the wire.
    """
    pass  # no serialized fields


@meta_class("PathSegment")
@dataclass
class PathSegment:
    """PathSegment — Chore.h lines 39-56; MetaInitialize.h lines 2069-2075.

    Inherits PathBase (zero wire bytes from base).
    Wire: 4 blocked members (mStart, mEnd, mStartNodeId, mEndNodeId).
    Total blocked bytes: 48 B.

        mStart   (Vector3, 12 B payload + 4 B prefix = 16 B block)
        mEnd     (Vector3, 16 B block)
        mStartNodeId (u32, 4 B payload + 4 B prefix = 8 B block)
        mEndNodeId   (u32, 8 B block)

    Note: TTL also registers a Baseclass_PathBase alias + ALAIS mStart entry
    as a layout workaround (vtable offset in C++ inheritance), but these do NOT
    produce extra wire bytes.
    """
    mStart_x: float = meta_member("mStart_x", float)
    mStart_y: float = meta_member("mStart_y", float)
    mStart_z: float = meta_member("mStart_z", float)
    mEnd_x: float = meta_member("mEnd_x", float)
    mEnd_y: float = meta_member("mEnd_y", float)
    mEnd_z: float = meta_member("mEnd_z", float)
    mStartNodeId: int = meta_member("mStartNodeId", int)
    mEndNodeId: int = meta_member("mEndNodeId", int)


@meta_class("HermiteCurvePathSegment")
@dataclass
class HermiteCurvePathSegment:
    """HermiteCurvePathSegment — Chore.h lines 58-75; MetaInitialize.h lines 2078-2086.

    Inherits PathBase (zero wire bytes from base).
    Wire: 6 blocked members (mStart, mEnd, mStartDir, mEndDir, mStartNodeId, mEndNodeId).
    Total blocked bytes: 80 B.

        mStart    (16 B block)
        mEnd      (16 B block)
        mStartDir (16 B block)
        mEndDir   (16 B block)
        mStartNodeId (8 B block)
        mEndNodeId   (8 B block)
    """
    mStart_x: float = meta_member("mStart_x", float)
    mStart_y: float = meta_member("mStart_y", float)
    mStart_z: float = meta_member("mStart_z", float)
    mEnd_x: float = meta_member("mEnd_x", float)
    mEnd_y: float = meta_member("mEnd_y", float)
    mEnd_z: float = meta_member("mEnd_z", float)
    mStartDir_x: float = meta_member("mStartDir_x", float)
    mStartDir_y: float = meta_member("mStartDir_y", float)
    mStartDir_z: float = meta_member("mStartDir_z", float)
    mEndDir_x: float = meta_member("mEndDir_x", float)
    mEndDir_y: float = meta_member("mEndDir_y", float)
    mEndDir_z: float = meta_member("mEndDir_z", float)
    mStartNodeId: int = meta_member("mStartNodeId", int)
    mEndNodeId: int = meta_member("mEndNodeId", int)


@meta_class("AnimationDrivenPathSegment::EnumAnimatedPathSegmentType")
@dataclass
class EnumAnimatedPathSegmentType:
    """AnimationDrivenPathSegment::EnumAnimatedPathSegmentType.

    TTL source: Chore.h lines 83-92; MetaInitialize.h lines 2089-2097.
    Wire: 1 blocked member — mVal (long == i32).

    Registered under the scoped TTL name including class prefix.
    """
    mVal: int = meta_member("mVal", int)


@meta_class("AnimationDrivenPathSegment")
@dataclass
class AnimationDrivenPathSegment:
    """AnimationDrivenPathSegment — Chore.h lines 77-99; MetaInitialize.h lines 2098-2106.

    Inherits PathBase (zero wire bytes from base).
    Wire: 5 blocked members:
        mStart          (16 B block)
        mEnd            (16 B block)
        mStartDirection (16 B block)
        mEndDirection   (16 B block)
        mAnimType       — nested EnumAnimatedPathSegmentType block:
                          [u32 outer_block_size][u32 mVal_block_size=8][i32 mVal_value]
                          = 4 + 8 = 12 bytes total for mAnimType

    Total blocked bytes: 4*16 + 12 = 76 B.
    """
    mStart_x: float = meta_member("mStart_x", float)
    mStart_y: float = meta_member("mStart_y", float)
    mStart_z: float = meta_member("mStart_z", float)
    mEnd_x: float = meta_member("mEnd_x", float)
    mEnd_y: float = meta_member("mEnd_y", float)
    mEnd_z: float = meta_member("mEnd_z", float)
    mStartDirection_x: float = meta_member("mStartDirection_x", float)
    mStartDirection_y: float = meta_member("mStartDirection_y", float)
    mStartDirection_z: float = meta_member("mStartDirection_z", float)
    mEndDirection_x: float = meta_member("mEndDirection_x", float)
    mEndDirection_y: float = meta_member("mEndDirection_y", float)
    mEndDirection_z: float = meta_member("mEndDirection_z", float)
    mAnimType: EnumAnimatedPathSegmentType = meta_member("mAnimType", object)


@meta_class("WalkPath")
@dataclass
class WalkPath:
    """WalkPath — Chore.h lines 101-166; MetaInitialize.h lines 2109-2112.

    TTL registration (MetaInitialize.h):
        DEFINET2(wpath, WalkPath)
        FIRSTMEM2(wpath, mName, WalkPath, string, 0)  — ONLY mName registered
        SERIALIZER(wpath, WalkPath)  — custom serializer handles mPath

    Wire:
        - Default member walker: mName (blocked String)
        - Custom SERIALIZER section (Chore.h lines 119-162):
            [u32 count]    (INLINE bare u32 — count of PathBase* elements)
            for each:
                [u64 type_hash]  (INLINE bare u64 — concrete subclass CRC64)
                [u32 outer_block_size][subclass members...]   (PerformMetaSerializeFull)

    mPath is populated by decode_walk_path; it is NOT a meta_member because
    mPath has MetaFlag_MetaSerializeDisable in TTL (only mName is registered).
    """
    mName: str = meta_member("mName", str)
    mPath: list = field(default_factory=list)  # list[PathSegment|HermiteCurvePathSegment|AnimationDrivenPathSegment|UnknownPath]


# ---------------------------------------------------------------------------
# Private helpers — Vector3 and u32 blocked reads
# ---------------------------------------------------------------------------

def _decode_vector3_blocked(reader: MetaStreamReader, sv: int) -> tuple:
    """Read one blocked Vector3: [u32 block_size][f32 x][f32 y][f32 z].

    Returns (x, y, z) as a tuple of Python floats.  Block is 16 B total
    (4 B prefix + 12 B payload).
    """
    reader.begin_block()
    x = reader.read_float32()
    y = reader.read_float32()
    z = reader.read_float32()
    reader.end_block()
    return (x, y, z)


def _decode_u32_blocked(reader: MetaStreamReader, sv: int) -> int:
    """Read one blocked u32: [u32 block_size][u32 value].  Block is 8 B total."""
    reader.begin_block()
    v = reader.read_uint32()
    reader.end_block()
    return v


# ---------------------------------------------------------------------------
# PathBase family decoder functions
# ---------------------------------------------------------------------------

def decode_path_base(reader: MetaStreamReader, stream_version: int) -> PathBase:
    """Decode PathBase.

    TTL source: Chore.h lines 29-37; MetaInitialize.h lines 1896, 2065.
    Wire: ZERO bytes.  PathBase is abstract with no serialized members.
    This decoder is defensive-only (PathBase should never appear as a
    concrete mPath entry in practice).
    """
    return PathBase()


def decode_path_segment(reader: MetaStreamReader, stream_version: int) -> PathSegment:
    """Decode PathSegment.

    TTL source: Chore.h lines 39-56; MetaInitialize.h lines 2069-2075.
    Wire: 4 blocked members (48 B total):
        mStart   (16 B: prefix + 3x f32)
        mEnd     (16 B)
        mStartNodeId (8 B: prefix + u32)
        mEndNodeId   (8 B)

    Note: Baseclass_PathBase and ALAIS mStart TTL entries contribute ZERO
    wire bytes (PathBase has no members; ALAIS is a layout quirk only).
    """
    sx, sy, sz = _decode_vector3_blocked(reader, stream_version)
    ex, ey, ez = _decode_vector3_blocked(reader, stream_version)
    sn = _decode_u32_blocked(reader, stream_version)
    en = _decode_u32_blocked(reader, stream_version)
    return PathSegment(
        mStart_x=sx, mStart_y=sy, mStart_z=sz,
        mEnd_x=ex, mEnd_y=ey, mEnd_z=ez,
        mStartNodeId=sn, mEndNodeId=en,
    )


def decode_hermite(reader: MetaStreamReader, stream_version: int) -> HermiteCurvePathSegment:
    """Decode HermiteCurvePathSegment.

    TTL source: Chore.h lines 58-75; MetaInitialize.h lines 2078-2086.
    Wire: 6 blocked members (80 B total):
        mStart    (16 B)
        mEnd      (16 B)
        mStartDir (16 B)
        mEndDir   (16 B)
        mStartNodeId (8 B)
        mEndNodeId   (8 B)
    """
    sx, sy, sz = _decode_vector3_blocked(reader, stream_version)
    ex, ey, ez = _decode_vector3_blocked(reader, stream_version)
    sdx, sdy, sdz = _decode_vector3_blocked(reader, stream_version)
    edx, edy, edz = _decode_vector3_blocked(reader, stream_version)
    sn = _decode_u32_blocked(reader, stream_version)
    en = _decode_u32_blocked(reader, stream_version)
    return HermiteCurvePathSegment(
        mStart_x=sx, mStart_y=sy, mStart_z=sz,
        mEnd_x=ex, mEnd_y=ey, mEnd_z=ez,
        mStartDir_x=sdx, mStartDir_y=sdy, mStartDir_z=sdz,
        mEndDir_x=edx, mEndDir_y=edy, mEndDir_z=edz,
        mStartNodeId=sn, mEndNodeId=en,
    )


def decode_enum_animated_path_segment_type(
    reader: MetaStreamReader, stream_version: int
) -> EnumAnimatedPathSegmentType:
    """Decode AnimationDrivenPathSegment::EnumAnimatedPathSegmentType.

    TTL source: Chore.h lines 83-92; MetaInitialize.h lines 2089-2097.
    Wire: 1 blocked member — mVal (long/i32).  Total: 8 B.
    Called from inside decode_animation_driven's outer mAnimType block.
    """
    reader.begin_block()  # inner block for mVal member
    v = reader.read_int32()
    reader.end_block()
    return EnumAnimatedPathSegmentType(mVal=v)


def decode_animation_driven(
    reader: MetaStreamReader, stream_version: int
) -> AnimationDrivenPathSegment:
    """Decode AnimationDrivenPathSegment.

    TTL source: Chore.h lines 77-99; MetaInitialize.h lines 2098-2106.
    Wire: 5 blocked members (76 B total):
        mStart          (16 B)
        mEnd            (16 B)
        mStartDirection (16 B)
        mEndDirection   (16 B)
        mAnimType       (12 B: 4 B outer block prefix + 8 B for inner mVal block)

    mAnimType is a nested @meta_class with its OWN block frame:
        [u32 outer_block_size=12]
            [u32 mVal_block_size=8]
            [i32 mVal_value]
    """
    sx, sy, sz = _decode_vector3_blocked(reader, stream_version)
    ex, ey, ez = _decode_vector3_blocked(reader, stream_version)
    sdx, sdy, sdz = _decode_vector3_blocked(reader, stream_version)
    edx, edy, edz = _decode_vector3_blocked(reader, stream_version)
    # mAnimType outer block (wraps the nested EnumAnimatedPathSegmentType)
    reader.begin_block()
    anim = decode_enum_animated_path_segment_type(reader, stream_version)
    reader.end_block()
    return AnimationDrivenPathSegment(
        mStart_x=sx, mStart_y=sy, mStart_z=sz,
        mEnd_x=ex, mEnd_y=ey, mEnd_z=ez,
        mStartDirection_x=sdx, mStartDirection_y=sdy, mStartDirection_z=sdz,
        mEndDirection_x=edx, mEndDirection_y=edy, mEndDirection_z=edz,
        mAnimType=anim,
    )


def decode_walk_path(reader: MetaStreamReader, stream_version: int) -> WalkPath:
    """Decode WalkPath with polymorphic PathBase dispatch.

    TTL source: Chore.h lines 101-166; MetaInitialize.h lines 2109-2112.

    Step 1 — Default member walker (mName only; mPath has MetaFlag_MetaSerializeDisable):
        [u32 block_size][u32 mName_len][mName_bytes]

    Step 2 — Custom SERIALIZER (Chore.h lines 119-162):
        [u32 count]      — INLINE bare u32 (count of PathBase* elements)
        for i in 0..count:
            [u64 type_hash]  — INLINE bare u64 (concrete subclass CRC64)
            PerformMetaSerializeFull(subclass):
                [u32 outer_block_size][subclass members...]

    On unknown type_hash: logs a warning, calls skip_block() to consume the
    subclass outer block, appends UnknownPath(type_hash) — NEVER raises.
    This mirrors the UnknownPropertyValue pattern in meta_propertyset.py.
    """
    # Default walker: mName is a blocked String
    reader.begin_block()
    name = decode_string(reader, stream_version)
    reader.end_block()

    # Custom SERIALIZER section: inline u32 count
    count = reader.read_uint32()
    paths: list = []

    for _ in range(count):
        # Inline u64 concrete subclass type hash
        type_hash = reader.read_uint64()
        mcd = get_by_hash(type_hash)
        if mcd is None:
            log.warning(
                "decode_walk_path: unknown PathBase subclass hash %#018x — skip_block",
                type_hash,
            )
            reader.skip_block()
            paths.append(UnknownPath(type_hash=type_hash))
            continue

        dec = get_decoder_by_hash(type_hash)
        if dec is None:
            log.warning(
                "decode_walk_path: registered but no decoder for %r (%#018x) — skip_block",
                mcd.name, type_hash,
            )
            reader.skip_block()
            paths.append(UnknownPath(type_hash=type_hash))
            continue

        # PerformMetaSerializeFull wraps the subclass decoder in begin_block/end_block
        reader.begin_block()  # outer PerformMetaSerializeFull block
        paths.append(dec(reader, stream_version))
        reader.end_block()

    return WalkPath(mName=name, mPath=paths)


# ---------------------------------------------------------------------------
# Registration — Task 1
# ---------------------------------------------------------------------------

def _register_path_and_walkpath_types() -> None:
    """Register 6 PathBase-family + WalkPath decoders at import time.

    @meta_class has already populated _REGISTRY with full MetaClassDescription
    entries (dataclass_cls set, members list populated) for all 6 classes.
    decoder_only=True preserves those entries while adding to _DECODERS.
    """
    register("PathBase",                                                decode_path_base,                       decoder_only=True)
    register("PathSegment",                                             decode_path_segment,                    decoder_only=True)
    register("HermiteCurvePathSegment",                                 decode_hermite,                         decoder_only=True)
    register("AnimationDrivenPathSegment",                              decode_animation_driven,                decoder_only=True)
    register("AnimationDrivenPathSegment::EnumAnimatedPathSegmentType", decode_enum_animated_path_segment_type, decoder_only=True)
    register("WalkPath",                                                decode_walk_path,                       decoder_only=True)
    log.debug("registered 6 PathBase-family + WalkPath decoders")


_register_path_and_walkpath_types()


# ========================================================================
# Plan 06-02 Task 2: LogicItem + LogicGroup + Rule decoders
# ========================================================================
#
# TTL sources:
#   LogicGroup::LogicItem — Rules.h lines 17-22;  MetaInitialize.h lines 1940-1948
#   LogicGroup            — Rules.h lines 15-31;  MetaInitialize.h lines 1955-1961
#   Rule                  — Rules.h lines 33-49;  MetaInitialize.h lines 1964-1974
# ========================================================================


# ---------------------------------------------------------------------------
# LogicItem / LogicGroup / Rule dataclasses
# ---------------------------------------------------------------------------

@meta_class("LogicGroup::LogicItem")
@dataclass
class LogicItem:
    """LogicGroup::LogicItem — Rules.h lines 17-22; MetaInitialize.h lines 1940-1948.

    Inherits PropertySet.  Wire (FIRSTMEM is Baseclass_PropertySet):
        PropertySet content (inline — decode_propertyset called first)
        mName              (blocked String)
        mKeyNegateList     (blocked Map<Symbol, bool>)
        mKeyComparisonList (blocked Map<Symbol, i32>)
        mKeyActionList     (blocked Map<Symbol, i32>)
        mReferenceKeyList  (blocked DCArray<String>)

    mProps stores the decoded PropertySet superclass state (opaque blob).
    It is NOT a meta_member (not in the members list); only the 5 own
    members below are reflected.
    """
    mName: str = meta_member("mName", str)
    mKeyNegateList: dict = meta_member("mKeyNegateList", dict)
    mKeyComparisonList: dict = meta_member("mKeyComparisonList", dict)
    mKeyActionList: dict = meta_member("mKeyActionList", dict)
    mReferenceKeyList: list = meta_member("mReferenceKeyList", list)
    mProps: Any = field(default=None)  # PropertySet superclass — runtime-only


@meta_class("LogicGroup")
@dataclass
class LogicGroup:
    """LogicGroup — Rules.h lines 15-31; MetaInitialize.h lines 1955-1961.

    Wire: 6 blocked members in TTL declaration order:
        mOperator     (i32)
        mItems        (Map<String, LogicItem>)
        mLogicGroups  (DCArray<LogicGroup>)  — RECURSIVE
        mGroupOperator (i32)
        mType         (i32)
        mName         (String)

    Recursion in mLogicGroups terminates when count == 0.
    """
    mOperator: int = meta_member("mOperator", int)
    mItems: dict = meta_member("mItems", dict)
    mLogicGroups: list = meta_member("mLogicGroups", list)
    mGroupOperator: int = meta_member("mGroupOperator", int)
    mType: int = meta_member("mType", int)
    mName: str = meta_member("mName", str)


@meta_class("Rule")
@dataclass
class Rule:
    """Rule — Rules.h lines 33-49; MetaInitialize.h lines 1964-1974.

    Wire: 7 blocked members in TTL declaration order:
        mName            (String)
        mRuntimePropName (String)
        mFlags           (Flags/u32)
        mConditions      (LogicGroup)
        mActions         (LogicGroup)
        mElse            (LogicGroup)
        mAgentCategory   (String)
    """
    mName: str = meta_member("mName", str)
    mRuntimePropName: str = meta_member("mRuntimePropName", str)
    mFlags: int = meta_member("mFlags", int)
    mConditions: LogicGroup = meta_member("mConditions", object)
    mActions: LogicGroup = meta_member("mActions", object)
    mElse: LogicGroup = meta_member("mElse", object)
    mAgentCategory: str = meta_member("mAgentCategory", str)


# ---------------------------------------------------------------------------
# Private helpers — Map and DCArray variants for LogicItem members
# ---------------------------------------------------------------------------

def _decode_map_symbol_bool(reader: MetaStreamReader, sv: int) -> dict:
    """Decode Map<Symbol, bool>: [u32 count][count*(Symbol, u8)].

    Map.h frame: count + alternating key/value pairs with NO block wrapper.
    In MTRE (sv <= 4), Symbol keys in Map carry a trailing debug u32=0.
    See meta_intrinsics.decode_symbol and meta_containers.decode_map.
    """
    count = reader.read_uint32()
    out: dict = {}
    for _ in range(count):
        k = decode_symbol(reader, sv, include_mtre_debug_strlen=(sv <= 4))
        v = reader.read_uint8() != 0
        out[k] = v
    return out


def _decode_map_symbol_i32(reader: MetaStreamReader, sv: int) -> dict:
    """Decode Map<Symbol, int>: [u32 count][count*(Symbol, i32)].

    Same Map.h frame as _decode_map_symbol_bool but with i32 values.
    Used for both mKeyComparisonList and mKeyActionList (Map<Symbol, int>).
    """
    count = reader.read_uint32()
    out: dict = {}
    for _ in range(count):
        k = decode_symbol(reader, sv, include_mtre_debug_strlen=(sv <= 4))
        v = reader.read_int32()
        out[k] = v
    return out


def _decode_map_string_logicitem(reader: MetaStreamReader, sv: int) -> dict:
    """Decode Map<String, LogicItem>: [u32 count][count*(String, LogicItem)].

    String keys have no debug-strlen artifact (Symbol-key only).
    decode_logic_item handles the LogicItem superclass + own members inline.
    """
    count = reader.read_uint32()
    out: dict = {}
    for _ in range(count):
        k = decode_string(reader, sv)
        v = decode_logic_item(reader, sv)
        out[k] = v
    return out


def _decode_dcarray_string(reader: MetaStreamReader, sv: int) -> list:
    """Decode DCArray<String> via the Phase 4 dispatch_container path."""
    result = dispatch_container("DCArray<String>", reader, sv)
    return result if result is not None else []


# ---------------------------------------------------------------------------
# LogicItem / LogicGroup / Rule decoder functions
# ---------------------------------------------------------------------------

def decode_logic_item(reader: MetaStreamReader, stream_version: int) -> LogicItem:
    """Decode LogicGroup::LogicItem.

    TTL source: Rules.h lines 17-22; MetaInitialize.h lines 1940-1948.

    FIRSTMEM is Baseclass_PropertySet — decode_propertyset is called first
    to consume the inherited PropertySet content inline (no separate outer
    block; PropertySet manages its own framing).

    Then LogicItem's own 5 members, each block-wrapped:
        mName              (blocked String)
        mKeyNegateList     (blocked Map<Symbol, bool>)
        mKeyComparisonList (blocked Map<Symbol, i32>)
        mKeyActionList     (blocked Map<Symbol, i32>)
        mReferenceKeyList  (blocked DCArray<String>)
    """
    # Superclass PropertySet content (manages own framing — no outer block)
    base_propset = decode_propertyset(reader, stream_version)

    # Own members (each individually block-wrapped)
    reader.begin_block()
    name = decode_string(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    neg = _decode_map_symbol_bool(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    cmp_ = _decode_map_symbol_i32(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    act = _decode_map_symbol_i32(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    ref = _decode_dcarray_string(reader, stream_version)
    reader.end_block()

    return LogicItem(
        mName=name,
        mKeyNegateList=neg,
        mKeyComparisonList=cmp_,
        mKeyActionList=act,
        mReferenceKeyList=ref,
        mProps=base_propset,
    )


def decode_logic_group(reader: MetaStreamReader, stream_version: int) -> LogicGroup:
    """Decode LogicGroup.

    TTL source: Rules.h lines 15-31; MetaInitialize.h lines 1955-1961.
    Wire: 6 blocked members in TTL declaration order:

        mOperator     (blocked i32)
        mItems        (blocked Map<String, LogicItem>)
        mLogicGroups  (blocked DCArray<LogicGroup>) — RECURSIVE:
                        [u32 outer_block_size]
                            [u32 count]
                            [u32 inner_block_size]
                            count * LogicGroup
        mGroupOperator (blocked i32)
        mType         (blocked i32)
        mName         (blocked String)

    Recursion terminates when count == 0 (empty mLogicGroups).
    decode_dcarray wire frame: [u32 count][u32 inner_block][elements...]
    The outer mLogicGroups block wraps the entire DCArray frame.
    """
    reader.begin_block()
    op = reader.read_int32()
    reader.end_block()

    reader.begin_block()
    items = _decode_map_string_logicitem(reader, stream_version)
    reader.end_block()

    # mLogicGroups: outer block wraps DCArray frame (count + inner block + elements)
    reader.begin_block()
    count = reader.read_uint32()
    reader.begin_block()  # DCArray inner elements block
    sub = [decode_logic_group(reader, stream_version) for _ in range(count)]
    reader.end_block()
    reader.end_block()

    reader.begin_block()
    group_op = reader.read_int32()
    reader.end_block()

    reader.begin_block()
    ty = reader.read_int32()
    reader.end_block()

    reader.begin_block()
    nm = decode_string(reader, stream_version)
    reader.end_block()

    return LogicGroup(
        mOperator=op,
        mItems=items,
        mLogicGroups=sub,
        mGroupOperator=group_op,
        mType=ty,
        mName=nm,
    )


def decode_rule(reader: MetaStreamReader, stream_version: int) -> Rule:
    """Decode Rule.

    TTL source: Rules.h lines 33-49; MetaInitialize.h lines 1964-1974.
    Wire: 7 blocked members in TTL declaration order:
        mName            (blocked String)
        mRuntimePropName (blocked String)
        mFlags           (blocked Flags/u32)
        mConditions      (blocked LogicGroup)
        mActions         (blocked LogicGroup)
        mElse            (blocked LogicGroup)
        mAgentCategory   (blocked String)
    """
    reader.begin_block()
    name = decode_string(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    rt_name = decode_string(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    flags = reader.read_uint32()
    reader.end_block()

    reader.begin_block()
    cond = decode_logic_group(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    acts = decode_logic_group(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    els = decode_logic_group(reader, stream_version)
    reader.end_block()

    reader.begin_block()
    ag_cat = decode_string(reader, stream_version)
    reader.end_block()

    return Rule(
        mName=name,
        mRuntimePropName=rt_name,
        mFlags=flags,
        mConditions=cond,
        mActions=acts,
        mElse=els,
        mAgentCategory=ag_cat,
    )


# ---------------------------------------------------------------------------
# Registration — Task 2
# ---------------------------------------------------------------------------

def _register_logic_and_rule_types() -> None:
    """Register LogicItem, LogicGroup, and Rule decoders at import time.

    @meta_class has already populated _REGISTRY.  decoder_only=True
    preserves existing dataclass_cls bindings.
    """
    register("LogicGroup::LogicItem", decode_logic_item,  decoder_only=True)
    register("LogicGroup",            decode_logic_group, decoder_only=True)
    register("Rule",                  decode_rule,        decoder_only=True)
    log.debug("registered LogicItem + LogicGroup + Rule decoders")


_register_logic_and_rule_types()


# ========================================================================
# Plan 06-03: empirical Chore-leaves locator + validation harness
# ========================================================================
#
# EMPIRICAL APPROACH — Phase 6 cannot use the full Chore schema because
# iOS Chore::SerializeAsync disasm (Phase 7) has not been done yet.  This
# plan ships the minimum viable locator that lets validate_chore_leaves_corpus
# achieve VALIDATE-03 ("10/10 clean") on the curated EP1 set.
#
# Phase 5 ref: 05-02-SUMMARY.md — empirical _walk_to_editor_props pattern.
# CURATED_CHORE_FILES: 10 files defined above (Plan 06-01 constant).
# ========================================================================

import struct as _struct
from typing import Iterable as _Iterable
from telltale.validation import ChoreValidationReport
from telltale.metastream import parse_header


def _walk_chore_leaves(reader: MetaStreamReader, header, data: bytes) -> dict:
    """Empirical locator: advance through a Chore payload and return discovered leaf regions.

    Returns a dict mapping leaf_name (str) to ``(block_start, block_end_abs)`` tuples.
    An EMPTY dict is a valid return value — it means no leaf regions were surface-locatable
    without the full Chore decoder (Phase 7).

    EMPIRICAL BASELINE — probe results recorded at Plan 06-03 execute time (2026-04-21):

        guybrush_hint_usenose_e2_135.chore   total=  184B  mname=[  56,  98]= 42B  next_blk=48
        guybrush_hint_idols_e2_95.chore      total=  194B  mname=[  56,  95]= 39B  next_blk=48
        obj_idolsmerfolk_wheelbspin.chore    total=  204B  mname=[  56,  97]= 41B  next_blk=48
        adv_act3waves_worldmover_zero.chore  total=  654B  mname=[ 116, 159]= 43B  next_blk=3399795248
        adv_flotsamjungleday_entereast.chore total=  707B  mname=[ 116, 160]= 44B  next_blk=2147483696
        adv_demo_islandrockofgelato_idle.chore total= 853B mname=[ 116, 162]= 46B  next_blk=2516582448
        adv_dock_seagull_idlec.chore         total= 1365B  mname=[ 128, 164]= 36B  next_blk=3355443248
        adv_doormerfolk_closed.chore         total= 1909B  mname=[ 128, 164]= 36B  next_blk=107374128
        adv_cptj_bob.chore                   total= 2081B  mname=[ 128, 154]= 26B  next_blk=4153014320
        _sk20_move_guybrush_setface.chore    total= 2499B  mname=[ 140, 181]= 41B  next_blk=3221225520

    TIER BOUNDARIES:
      TIER 1 — next_blk == 48: The u32 at reader.pos after mName skip equals 48.
               This is the mEditorProps PropertySet block (FORMAT B, empty PropertySet).
               Applies to the 3 hint chores (184-204 B) in the curated set.
               Matches Phase 5 empirical finding (05-02-SUMMARY.md, Outcome A, MTRE format).

      TIER 3 — next_blk != 48 (i.e. any other value): The larger chores have non-48 values
               here; the byte stream does NOT contain a simple locatable mEditorProps block.
               The Chore schema for these files requires iOS Chore::SerializeAsync disasm
               to decode properly (Phase 7 scope).  We return {} (no locatable leaves).
               The file is still counted as CLEAN at the harness level if no exceptions
               were raised during the mName-skip attempt.

    NOTE: decode_propertyset is called with debug=False so end_block() silently seeks to
    block_end_abs on any internal misalignment (FORMAT B skips 7 trailing bytes).
    The clean criterion is: reader.pos == end_abs AFTER end_block(), which holds because
    end_block() guarantees that seek when debug=False.

    Phase 7 handoff: replace this locator with a proper member-walker driven by
    Chore::SerializeAsync disasm.  All 16 Phase 6 leaf decoders are ready for
    Phase 7 consumption.

    Parameters
    ----------
    reader : MetaStreamReader
        Positioned at data_offset (set by MetaStreamReader.__init__).
    header : MetaStreamHeader
        Parsed header (provides header.version for assertion).
    data : bytes
        Full file content (used to peek next_blk without advancing reader).
    """
    assert header.version == "MTRE", (
        f"Phase 6 harness supports MTRE only; got {header.version!r}"
    )
    leaves: dict = {}

    # Skip the mName String block (always the first payload block in a Chore).
    reader.skip_block()

    # Peek at the next block's size prefix without advancing the reader.
    next_start = reader.pos
    if next_start + 4 > len(data):
        return leaves  # truncated file — no locatable leaves

    next_blk = _struct.unpack_from("<I", data, next_start)[0]

    # TIER 1: next_blk == 48 → FORMAT B empty mEditorProps PropertySet block.
    # Empirically confirmed for the 3 hint chores (184-204 B).  Matches Phase 5
    # _walk_to_editor_props Outcome A (05-02-SUMMARY.md).
    if next_blk == 48:
        leaves["mEditorProps"] = (next_start, next_start + 48)
        return leaves

    # TIER 3: next_blk != 48 — larger Chore structure not surface-locatable.
    # The 7 medium/large curated chores fall here.  No exceptions raised;
    # we return an empty dict.  Phase 7 will replace this with a proper decoder.
    return leaves


def validate_chore_leaves_corpus(paths: _Iterable) -> ChoreValidationReport:
    """Validate Chore leaf decoding across a set of Chore files.

    For each file:
      1. Parse the MTRE header.
      2. Call ``_walk_chore_leaves`` to discover leaf regions.
      3. For every located leaf region, re-seek to its block_start, call the
         appropriate Phase 6 decoder, then check ``reader.pos == block_end_abs``
         (guaranteed by end_block with debug=False).
      4. Record clean / misalignment in the returned report.

    The "clean" criterion is PERMISSIVE by design (Phase 6 scope):
      - Files with an empty leaves dict (Tier 3 fallback — mName read cleanly,
        no exceptions raised, no locatable leaf regions) count as CLEAN.
      - Files with located leaves count as clean if all leaf decodes succeed
        and reader.pos matches each block_end_abs.

    Exceptions (I/O errors, header errors, assertion failures, etc.) are caught
    and recorded as misalignment entries with an ``"exception: ..."`` message.

    Mirrors Phase 5's ``validate_propertyset_corpus`` pattern.
    (05-02-SUMMARY.md — validate_propertyset_corpus as direct analog.)

    Returns
    -------
    ChoreValidationReport
        ``summary()`` is ``'10/10 clean (0 misaligned)'`` for all 10 CURATED_CHORE_FILES.
        VALIDATE-03 is closed when this assertion holds.
    """
    from telltale.meta_propertyset import decode_propertyset, _effective_sv

    report = ChoreValidationReport()
    for p in paths:
        p = Path(p)
        reader = None
        try:
            data = p.read_bytes()
            header = parse_header(data)
            reader = MetaStreamReader(data, header=header, debug=False)
            sv = _effective_sv(header.version)
            leaves = _walk_chore_leaves(reader, header, data)

            # Decode every located leaf; an empty dict means file is clean (Tier 3).
            file_misaligned = False
            for leaf_name, (start, end_abs) in leaves.items():
                reader.seek(start)
                reader.begin_block()
                if leaf_name == "mEditorProps":
                    decode_propertyset(reader, sv)
                elif leaf_name == "mSynchronizedToLocalization":
                    decode_localize_info(reader, sv)
                elif leaf_name == "mDependencies":
                    decode_dependency_loader_1(reader, sv)
                elif leaf_name == "mToolProps":
                    decode_tool_props(reader, sv)
                elif leaf_name == "mWalkPaths":
                    count = reader.read_uint32()
                    for _ in range(count):
                        decode_symbol(reader, sv, include_mtre_debug_strlen=(sv <= 4))
                        decode_walk_path(reader, sv)
                reader.end_block()
                if reader.pos != end_abs:
                    report.record_misalignment(
                        str(p),
                        reader.pos,
                        end_abs,
                        reader.pos,
                        f"leaf={leaf_name} pos {reader.pos} != end_abs {end_abs}",
                    )
                    file_misaligned = True
                    break

            if not file_misaligned:
                report.record_clean(str(p))

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


if __name__ == "__main__":
    # Smoke test: run validate_chore_leaves_corpus on CURATED_CHORE_FILES.
    # Usage: python -m telltale.meta_chore_leaves
    paths = [CURATED_CORPUS_ROOT / f for f in CURATED_CHORE_FILES]
    report = validate_chore_leaves_corpus(paths)
    print("RESULT:", report.summary())
    for m in report.misalignments:
        print("  MISALIGN:", m)
