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
from telltale.metaclass import meta_class, meta_member
from telltale.meta_intrinsics import register, decode_string
from telltale.metastream import MetaStreamReader
from telltale.meta_propertyset import decode_propertyset

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
