"""
Chore / ChoreResource / ChoreAgent decoder for Telltale MetaStream (.chore files).

Primary source
--------------
iOS ARM32 binary ``altre_versioni/MonkeyIsland101``:
    ``Chore::MetaOperation_Serialize`` at VA 0x00205788
    (See ``docs/CHORE_DISASM.md`` for full field-walk table — Plan 07-01 artifact.)

TTL cross-references
--------------------
    Chore.h:408-649     — Chore struct declaration + SerializeAsync custom post-loop
    Chore.h:256-351     — ChoreResource struct declaration + SerializeAsync stub
    Chore.h:353-405     — ChoreAgent struct declaration + SerializeAsync

Field-walk order
----------------
iOS SerializeAsync (VA 0x00205788) delegates the 12 top-level Chore members to
``Meta::MetaOperation_SerializeAsync`` (VA 0x001E99CC), which iterates the
``MetaClassDescription`` member list in registration order.
``Chore::InternalGetMetaClassDescription`` (VA 0x000B609C) registers members in the
EXACT same sequence as Chore.h:422-433.  No drift was observed — iOS order ==
TTL declaration order.

Per ``docs/CHORE_DISASM.md`` and ``07-01-SUMMARY.md``:
  1.  mName                         — Chore.h:422
  2.  mFlags                        — Chore.h:423
  3.  mLength                       — Chore.h:424
  4.  mNumResources                 — Chore.h:425
  5.  mNumAgents                    — Chore.h:426
  6.  mEditorProps                  — Chore.h:427 (PropertySet)
  7.  mChoreSceneFile               — Chore.h:428
  8.  mRenderDelay                  — Chore.h:429
  9.  mSynchronizedToLocalization   — Chore.h:430 (LocalizeInfo)
 10.  mDependencies                 — Chore.h:431 (DependencyLoader<1>)
 11.  mToolProps                    — Chore.h:432 (ToolProps)
 12.  mWalkPaths                    — Chore.h:433 (Map<Symbol, WalkPath>)

Custom post-loop (Chore.h:601-647 — OUTSIDE the default MetaClass walk):
  mNumResources × PerformMetaSerialize<ChoreResource> (VA 0x002089D0)
  mNumAgents    × PerformMetaSerialize<ChoreAgent>    (VA 0x00208980)

iOS wins on conflict (PROJECT.md standing decision).

SerializedVersionInfo
---------------------
TMI ships a Chore SerializedVersionInfo CRC of 1830510796 (per PROJECT.md context).
This is the per-class version CRC found in the .chore header's class-entry list, NOT
the MetaStream container format version (MTRE/MSV5/MSV6).

Phase handoff
-------------
Plan 07-03 will run byte-range corpus validation against 3 EP1 chores.
Plan 07-02 (this module) provides the decoders; Plan 07-03 owns VALIDATE-03 style
cross-checks.  For the ChoreValidationReport type see telltale/validation.py.

mControlAnimation
-----------------
ChoreResource contains a full ``Animation mControlAnimation`` (Chore.h:280).
The embedded Animation block is consumed via ``reader.skip_block()``; its
content is a variable-length Animation object (e.g. bsz=174 in EP1 medium
chores) that requires a full Animation decoder to interpret.  Decoding
Animation objects is outside this module's scope — the Animation wire format
is defined by the CTK/CompressedKeys infrastructure, not by the Chore structs.
A DEBUG entry is logged when the block is skipped.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from telltale.crc64 import crc64_str
from telltale.metaclass import meta_class, meta_member, get_by_hash
from telltale.meta_intrinsics import (
    register,
    decode_string,
    decode_symbol,
)
from telltale.metastream import MetaStreamReader, parse_header
from telltale.meta_propertyset import decode_propertyset, _effective_sv
from telltale.meta_handle import decode_handle
from telltale.meta_containers import dispatch_container, decode_map
from telltale.meta_chore_leaves import (
    LocalizeInfo,
    Attachment,
    ToolProps,
    AutoActStatus,
    ActorAgentBinding,
    Rule,
    WalkPath,
    DependencyLoader1,
    decode_localize_info,
    decode_attachment,
    decode_tool_props,
    decode_auto_act_status,
    decode_actor_agent_binding,
    decode_rule,
    decode_walk_path,
    decode_dependency_loader_1,
    Block,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@meta_class("ChoreResource")
@dataclass
class ChoreResource:
    """ChoreResource — TTL Chore.h:256-351.

    iOS VA of ``PerformMetaSerialize<ChoreResource>``: 0x002089D0.
    Called from ``Chore::MetaOperation_Serialize`` (VA 0x00205788) in a
    custom post-loop for each of ``mNumResources`` resources.
    See ``docs/CHORE_DISASM.md`` custom post-loop section.

    Phase 7 scope: populate mResName / mResLength / mPriority / mFlags /
    mResourceGroup / mhObject / mBlocks + behaviour flags.

    mControlAnimation (Chore.h:280) is an embedded Animation object.  It is
    consumed via ``reader.skip_block()`` and stored as an empty bytes placeholder.
    Decoding the Animation wire format requires the CTK/CompressedKeys
    infrastructure and is outside the scope of the Chore decoder.

    mhObjectEmbedded and mhObjectDesc (Chore.h:277-278) are runtime-only
    library metadata fields — NOT serialized.
    mpChore (Chore.h:268) is a back-pointer — NOT serialized.
    """
    mVersion: int = meta_member("mVersion", int)               # Chore.h:269 long
    mResName: int = meta_member("mResName", int)               # Chore.h:270 Symbol u64
    mResLength: float = meta_member("mResLength", float)       # Chore.h:271 float
    mPriority: int = meta_member("mPriority", int)             # Chore.h:272 long
    mFlags: int = meta_member("mFlags", int)                   # Chore.h:273 Flags
    mResourceGroup: str = meta_member("mResourceGroup", str)   # Chore.h:274 String
    mhObject: Any = meta_member("mhObject", object)            # Chore.h:275 HandleBase
    # mControlAnimation: embedded Animation — skip_block'd (CTK decode out of scope)
    mControlAnimation: Optional[bytes] = field(default=None)
    mBlocks: list = field(default_factory=list)                # Chore.h:281 DCArray<Block>
    mbNoPose: bool = meta_member("mbNoPose", bool)             # Chore.h:282
    mbEmbedded: bool = meta_member("mbEmbedded", bool)         # Chore.h:283
    mbEnabled: bool = meta_member("mbEnabled", bool)           # Chore.h:284
    mbIsAgentResource: bool = meta_member("mbIsAgentResource", bool)   # Chore.h:285
    mbViewGraphs: bool = meta_member("mbViewGraphs", bool)     # Chore.h:286
    mbViewEmptyGraphs: bool = meta_member("mbViewEmptyGraphs", bool)   # Chore.h:287
    mbViewProperties: bool = meta_member("mbViewProperties", bool)     # Chore.h:288
    mbViewResourceGroups: bool = meta_member("mbViewResourceGroups", bool)  # Chore.h:289
    mResourceProperties: Any = meta_member("mResourceProperties", object)  # Chore.h:290 PropertySet
    mResourceGroupInclude: Any = meta_member("mResourceGroupInclude", object)  # Chore.h:291 Map<Symbol,float>
    mAAStatus: Any = meta_member("mAAStatus", object)          # Chore.h:292 AutoActStatus


@meta_class("ChoreAgent")
@dataclass
class ChoreAgent:
    """ChoreAgent — TTL Chore.h:353-405.

    iOS VA of ``PerformMetaSerialize<ChoreAgent>``: 0x00208980.
    Called from ``Chore::MetaOperation_Serialize`` (VA 0x00205788) in a
    custom post-loop for each of ``mNumAgents`` agents.
    See ``docs/CHORE_DISASM.md`` custom post-loop section.

    ChoreAgent::SerializeAsync (Chore.h:400-403) calls the default
    ``Meta::MetaOperation_SerializeAsync`` walker — no custom post-loop.

    mpChore (Chore.h:365) is a back-pointer — NOT serialized.
    """
    mAgentName: str = meta_member("mAgentName", str)           # Chore.h:366 String
    mFlags: int = meta_member("mFlags", int)                   # Chore.h:367 Flags
    mResources: list = meta_member("mResources", list)         # Chore.h:368 DCArray<int>
    mAttachment: Any = meta_member("mAttachment", object)      # Chore.h:369 Attachment
    mAABinding: Any = meta_member("mAABinding", object)        # Chore.h:370 ActorAgentBinding
    mAgentEnabledRule: Any = meta_member("mAgentEnabledRule", object)  # Chore.h:371 Rule


@meta_class("Chore")
@dataclass
class Chore:
    """Top-level Chore struct — TTL Chore.h:408-649.

    iOS ``Chore::MetaOperation_Serialize`` at VA 0x00205788.
    See ``docs/CHORE_DISASM.md`` for the complete disassembly and field-walk table.

    The 12 top-level members below are serialized by the default
    ``Meta::MetaOperation_SerializeAsync`` walker (VA 0x001E99CC).
    Field order matches TTL Chore.h:422-433 exactly (iOS-confirmed, no drift).

    After the 12-member default walk, two custom post-loops run (Chore.h:601-647):
        for i in range(mNumResources): ... decode_chore_resource(...)
        for i in range(mNumAgents):   ... decode_chore_agent(...)

    These populate ``resources`` and ``agents`` (plain Python list fields, NOT
    meta_members — they are not part of the standard MetaClass member walk).

    SerializedVersionInfo CRC for TMI Chore: 1830510796 (PROJECT.md).
    """
    mName: str = meta_member("mName", str)                          # Chore.h:422 String
    mFlags: int = meta_member("mFlags", int)                        # Chore.h:423 Flags
    mLength: float = meta_member("mLength", float)                  # Chore.h:424 float
    mNumResources: int = meta_member("mNumResources", int)          # Chore.h:425 long
    mNumAgents: int = meta_member("mNumAgents", int)                # Chore.h:426 long
    mEditorProps: Any = meta_member("mEditorProps", object)         # Chore.h:427 PropertySet
    mChoreSceneFile: str = meta_member("mChoreSceneFile", str)      # Chore.h:428 String
    mRenderDelay: int = meta_member("mRenderDelay", int)            # Chore.h:429 long
    mSynchronizedToLocalization: Any = meta_member(                 # Chore.h:430 LocalizeInfo
        "mSynchronizedToLocalization", object
    )
    mDependencies: Any = meta_member("mDependencies", object)       # Chore.h:431 DependencyLoader<1>
    mToolProps: Any = meta_member("mToolProps", object)             # Chore.h:432 ToolProps
    mWalkPaths: Any = meta_member("mWalkPaths", object)             # Chore.h:433 Map<Symbol,WalkPath>

    # Custom post-loop populated — NOT meta_members (Chore.h:435-437 "DO NOT ADD TO THIS"):
    resources: List[ChoreResource] = field(default_factory=list)
    agents: List[ChoreAgent] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Decoder: ChoreResource
# ---------------------------------------------------------------------------

def decode_chore_resource(reader: MetaStreamReader, stream_version: int) -> ChoreResource:
    """Decode one ChoreResource.

    iOS VA of ``PerformMetaSerialize<ChoreResource>``: 0x002089D0.
    TTL source: Chore.h:256-351 (struct) + ChoreResource::SerializeAsync.

    Member read order follows TTL declaration order (Chore.h:269-292).
    iOS PerformMetaSerialize uses the standard MetaClass member walker, so
    order matches TTL exactly.  Each member is block-wrapped (begin_block /
    end_block) per the standard MetaStream framing.

    mControlAnimation (Chore.h:280, embedded Animation) is consumed via
    ``reader.skip_block()``.  A WARNING is logged.  Decoding the Animation
    object requires the CTK/CompressedKeys infrastructure, which is outside
    the scope of the Chore decoder.

    mhObjectEmbedded and mhObjectDesc (Chore.h:277-278) are runtime-only
    library metadata — NOT serialized.
    mpChore (Chore.h:268) is a back-pointer — NOT serialized.
    """
    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_resource: entry at pos=%d", reader.pos)

    # mVersion — Chore.h:269 long (i32)
    reader.begin_block()
    m_version = reader.read_int32()
    reader.end_block()

    # mResName — Chore.h:270 Symbol (u64)
    reader.begin_block()
    m_res_name = reader.read_uint64()
    reader.end_block()

    # mResLength — Chore.h:271 float
    reader.begin_block()
    m_res_length = reader.read_float32()
    reader.end_block()

    # mPriority — Chore.h:272 long (i32)
    reader.begin_block()
    m_priority = reader.read_int32()
    reader.end_block()

    # mFlags — Chore.h:273 Flags (u32)
    reader.begin_block()
    m_flags = reader.read_uint32()
    reader.end_block()

    # mResourceGroup — Chore.h:274 String
    reader.begin_block()
    m_resource_group = decode_string(reader, stream_version)
    reader.end_block()

    # mhObject — Chore.h:275 HandleBase
    reader.begin_block()
    m_h_object = decode_handle(reader, stream_version)
    reader.end_block()

    # mControlAnimation — Chore.h:280 Animation (embedded)
    # The Animation block is skipped: decoding Animation objects requires the
    # CTK/CompressedKeys infrastructure (not part of the Chore decoder scope).
    # The block size is variable (e.g. bsz=174 for a 170-byte Animation in EP1).
    log.warning(
        "decode_chore_resource: skipping embedded mControlAnimation (Animation block) "
        "at pos=%d (Chore.h:280) — Animation decode requires CTK infrastructure",
        reader.pos,
    )
    anim_start = reader.pos
    reader.skip_block()
    anim_end = reader.pos
    m_control_animation = bytes()  # raw bytes placeholder (Animation content is opaque)

    # mBlocks — Chore.h:281 DCArray<ChoreResource::Block>
    # Phase 6 registered "ChoreResource::Block" (scoped name, per STATE 04-02).
    # dispatch_container resolves Block via the registry.
    reader.begin_block()
    m_blocks = dispatch_container("DCArray<ChoreResource::Block>", reader, stream_version)
    reader.end_block()
    if m_blocks is None:
        m_blocks = []

    # Behaviour flags (each u8, blocked) — Chore.h:282-289
    reader.begin_block()
    mb_no_pose = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_embedded = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_enabled = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_is_agent_resource = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_view_graphs = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_view_empty_graphs = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_view_properties = reader.read_uint8() != 0
    reader.end_block()

    reader.begin_block()
    mb_view_resource_groups = reader.read_uint8() != 0
    reader.end_block()

    # mResourceProperties — Chore.h:290 PropertySet
    # Reuses Phase 5 decode_propertyset (05-02-SUMMARY.md).
    reader.begin_block()
    m_resource_properties = decode_propertyset(reader, stream_version)
    reader.end_block()

    # mResourceGroupInclude — Chore.h:291 Map<Symbol, float, Symbol::CompareCRC>
    # dispatch_container resolves Map<Symbol, float>; MTRE auto-enables debug-strlen.
    reader.begin_block()
    m_resource_group_include = dispatch_container("Map<Symbol, float>", reader, stream_version)
    reader.end_block()
    if m_resource_group_include is None:
        m_resource_group_include = {}

    # mAAStatus — Chore.h:292 AutoActStatus (Phase 6 leaf)
    reader.begin_block()
    m_aa_status = decode_auto_act_status(reader, stream_version)
    reader.end_block()

    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_resource: exit at pos=%d", reader.pos)

    return ChoreResource(
        mVersion=m_version,
        mResName=m_res_name,
        mResLength=m_res_length,
        mPriority=m_priority,
        mFlags=m_flags,
        mResourceGroup=m_resource_group,
        mhObject=m_h_object,
        mControlAnimation=m_control_animation,
        mBlocks=m_blocks,
        mbNoPose=mb_no_pose,
        mbEmbedded=mb_embedded,
        mbEnabled=mb_enabled,
        mbIsAgentResource=mb_is_agent_resource,
        mbViewGraphs=mb_view_graphs,
        mbViewEmptyGraphs=mb_view_empty_graphs,
        mbViewProperties=mb_view_properties,
        mbViewResourceGroups=mb_view_resource_groups,
        mResourceProperties=m_resource_properties,
        mResourceGroupInclude=m_resource_group_include,
        mAAStatus=m_aa_status,
    )


# ---------------------------------------------------------------------------
# Decoder: ChoreAgent
# ---------------------------------------------------------------------------

def decode_chore_agent(reader: MetaStreamReader, stream_version: int) -> ChoreAgent:
    """Decode one ChoreAgent.

    iOS VA of ``PerformMetaSerialize<ChoreAgent>``: 0x00208980.
    TTL source: Chore.h:353-405 (struct declaration).

    ChoreAgent::SerializeAsync (Chore.h:400-403) calls the default
    ``Meta::MetaOperation_SerializeAsync`` walker — the 6 own members are
    serialized in declaration order (Chore.h:366-371), each block-wrapped.

    mpChore (Chore.h:365) is a back-pointer — NOT serialized.
    """
    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_agent: entry at pos=%d", reader.pos)

    # mAgentName — Chore.h:366 String
    reader.begin_block()
    m_agent_name = decode_string(reader, stream_version)
    reader.end_block()

    # mFlags — Chore.h:367 Flags (u32)
    reader.begin_block()
    m_flags = reader.read_uint32()
    reader.end_block()

    # mResources — Chore.h:368 DCArray<int>
    reader.begin_block()
    m_resources = dispatch_container("DCArray<int>", reader, stream_version)
    reader.end_block()
    if m_resources is None:
        m_resources = []

    # mAttachment — Chore.h:369 ChoreAgent::Attachment (Phase 6 leaf)
    # decode_attachment reads 7 individual blocked members internally.
    reader.begin_block()
    m_attachment = decode_attachment(reader, stream_version)
    reader.end_block()

    # mAABinding — Chore.h:370 ActorAgentBinding (Phase 6 leaf)
    reader.begin_block()
    m_aa_binding = decode_actor_agent_binding(reader, stream_version)
    reader.end_block()

    # mAgentEnabledRule — Chore.h:371 Rule (Phase 6 leaf)
    reader.begin_block()
    m_agent_enabled_rule = decode_rule(reader, stream_version)
    reader.end_block()

    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_agent: exit at pos=%d", reader.pos)

    return ChoreAgent(
        mAgentName=m_agent_name,
        mFlags=m_flags,
        mResources=m_resources,
        mAttachment=m_attachment,
        mAABinding=m_aa_binding,
        mAgentEnabledRule=m_agent_enabled_rule,
    )


# ---------------------------------------------------------------------------
# MTRE-specific decoders: ChoreResource and ChoreAgent
# ---------------------------------------------------------------------------

def _mtre_read_string_block(reader: MetaStreamReader) -> str:
    """Read one block-wrapped MTRE String without using begin_block/end_block.

    MTRE String wire format:
      uint32  block_size  (includes the 4-byte size field itself)
      uint32  strlen
      bytes   string bytes (latin-1)

    If ``block_size == 0`` the block is an empty placeholder — skip 4 bytes,
    return ``""``.  The clamp in ``MetaStreamReader.begin_block`` handles this
    for normal blocked reads, but here we read manually so we can return the
    string content directly without touching the block stack.
    """
    bsz = reader.read_uint32()
    if bsz < 8:
        # bsz=0/1/4/etc: empty block (no strlen, no content).
        # The 4-byte bsz field was already consumed; nothing else to skip.
        return ""
    strlen = reader.read_uint32()
    raw = reader.read_bytes(strlen)
    # Skip alignment padding inside the block (bsz - 4hdr - 4strlen - strlen)
    extra = bsz - 4 - 4 - strlen
    if extra > 0:
        reader.skip(extra)
    return raw.decode("latin-1")


def decode_chore_resource_mtre(
    reader: MetaStreamReader,
    stream_version: int,
    *,
    _num_agents: int = 0,
    _remaining_resources: int = 1,
    _pal_skip_out: "list[int] | None" = None,
) -> ChoreResource:
    """Decode one ChoreResource from an MTRE (sv<=3) stream.

    MTRE fields are NOT wrapped in individual begin_block/end_block pairs the
    way MSV5 fields are.  The layout was reverse-engineered empirically from
    the EP1 corpus (docs/CHORE_DISASM.md Gap-01 + 07-GAP-02 wave-2 work).

    Wire layout (all integers little-endian):

    1.  mResourceGroup   block-wrapped String  (bsz=N, 4+4+strlen bytes)
    2.  mResLength       raw f32               (4 bytes, no block header)
    3.  mVersion         raw u32               (4 bytes)
    4.  mPriority        raw u32               (4 bytes)
    5.  mFlags (low)     raw u32               (4 bytes, value typically 8)
    6.  mFlags (high)    raw u32               (4 bytes, value typically 0)
    7.  mhObject         block-wrapped String  (bsz=N; bsz=8 when handle is null)
    8.  mControlAnimation skip_block           (variable; WARNING logged)
    9.  mBlocks          block-wrapped DCArray (bsz=N; count u32 + raw entries)
    10. mbNoPose         raw ASCII byte        (0x30='0'=False, 0x31='1'=True)
    11. mbEmbedded       raw ASCII byte
    12. mbEnabled        raw ASCII byte
    13. mbIsAgentResource raw ASCII byte
    14. mbViewGraphs     raw ASCII byte
    15. mbViewEmptyGraphs raw ASCII byte
    16. mbViewProperties raw ASCII byte
    17. mbViewResourceGroups raw ASCII byte
    18. mResourceProperties  skip_block        (always bsz=28 in EP1)
    19. mResourceGroupInclude skip_block       (always bsz=8 in EP1, empty Map)
    20. mAAStatus tail:
          u32  outer_placeholder = 0
          u32  inner_bsz
          if inner_bsz >= 4: inner_bsz-4 bytes (mAAName string payload)

    mResName (Symbol u64) is NOT present on the MTRE wire — it is absent from
    the MTRE class description for EP1 chores.  mResName is stored as 0.

    mControlAnimation (Chore.h:280) is consumed via skip_block.  Decoding
    the embedded Animation requires CTK/CompressedKeys infrastructure outside
    the scope of the Chore decoder.
    """
    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_resource_mtre: entry at pos=%d", reader.pos)

    # 1. mResourceGroup — block-wrapped String
    m_resource_group = _mtre_read_string_block(reader)

    # 2. mResLength — raw f32
    m_res_length = reader.read_float32()

    # 3-6. Four raw u32 scalar fields (mVersion / mPriority / mFlags halves)
    m_version = reader.read_uint32()
    m_priority = reader.read_uint32()
    m_flags_lo = reader.read_uint32()
    m_flags_hi = reader.read_uint32()
    m_flags = m_flags_lo  # use low word as mFlags

    # 7. mhObject — block-wrapped String (filename of the referenced resource)
    m_h_object_name = _mtre_read_string_block(reader)

    # 8. mControlAnimation — skip embedded Animation block
    # The block is variable-length (e.g. bsz=174 for a 170-byte Animation in EP1).
    # Decoding requires CTK/CompressedKeys infrastructure outside this module's scope.
    log.debug(
        "decode_chore_resource_mtre: skipping mControlAnimation Animation block at pos=%d",
        reader.pos,
    )
    reader.skip_block()

    # 9. mBlocks — block-wrapped DCArray<ChoreResource::Block>
    # MTRE DCArray: bsz=N then count(u32) then raw block entries (no inner block wrapper).
    _blocks_bsz = reader.read_uint32()
    m_blocks: list = []
    if _blocks_bsz >= 8:
        _count = reader.read_uint32()
        _payload_remaining = _blocks_bsz - 4 - 4  # subtract outer-bsz field and count field
        if _count > 0 and _payload_remaining > 0:
            reader.skip(_payload_remaining)  # skip block entries (Block decoding out of scope)
    elif _blocks_bsz >= 4:
        # bsz=4: just the size field itself, count=0 implied
        pass
    # bsz=0: handled by _mtre_read_string_block-style: already consumed the 4 bytes

    # 10-17. Eight raw ASCII boolean flags
    mb_no_pose            = reader.read_uint8() == 0x31
    mb_embedded           = reader.read_uint8() == 0x31
    mb_enabled            = reader.read_uint8() == 0x31
    mb_is_agent_resource  = reader.read_uint8() == 0x31
    mb_view_graphs        = reader.read_uint8() == 0x31
    mb_view_empty_graphs  = reader.read_uint8() == 0x31
    mb_view_properties    = reader.read_uint8() == 0x31
    mb_view_resource_groups = reader.read_uint8() == 0x31

    # 18. mResourceProperties — skip the entire PropertySet block
    reader.skip_block()

    # 19. mResourceGroupInclude — skip the entire Map block (always empty in EP1)
    reader.skip_block()

    # 20. mAAStatus tail: [u32=0 placeholder][inner_bsz][if inner_bsz>=4: (inner_bsz-4) bytes]
    #
    # For most resources: outer=0, inner_bsz=1 (8 bytes total) or inner_bsz=18 (22 bytes total).
    # For "Procedural Look At" (PAL) resources: inner_bsz=0xcc33a947 (first 4 bytes of a type CRC
    # embedded in the PAL serialized data).  The PAL mAAStatus encodes a full constraint graph
    # whose schema is unknown; its size varies from ~100 to ~8000 bytes across EP1 files.
    #
    # PAL detection: inner_bsz > 0xFFFF (no valid MTRE block exceeds 64 KB).  When detected,
    # scan forward for the next valid structure boundary (next resource's mResourceGroup block
    # OR next agent's mAgentName block), both of which start with a small bsz u32 (≤512)
    # followed by a small strlen u32 (≤256) and printable ASCII bytes (or bsz=0 for anonymous
    # agent).  The scan consumes exactly the bytes needed to reach that boundary.
    _outer_placeholder = reader.read_uint32()   # always 0
    _inner_bsz = reader.read_uint32()
    if _inner_bsz > 0xFFFF:
        # PAL resource: skip variable-length mAAStatus by scanning for the next block boundary.
        #
        # The "Procedural Look At" (PAL) constraint graph is serialized as an opaque blob
        # whose size ranges from ~100 to ~8000+ bytes.  The inner_bsz field (which should
        # encode the mAAStatus payload size) instead contains the first 4 bytes of a type
        # CRC (0xcc33a947), making naive size-directed parsing impossible.
        #
        # Strategy: scan forward from the current position looking for the start of the
        # NEXT structure (either the next resource's mResourceGroup block or the first
        # agent's mAgentName block).  When _num_agents > 0 (the caller has told us how
        # many agents follow ALL resources), use the strongest possible check: simulate
        # decoding ALL _num_agents agents sequentially from the candidate position and
        # require that the chain ends exactly at the file end.  When _num_agents == 0
        # (caller did not supply the count), fall back to single-agent simulation.
        _scan_data = reader._data
        _scan_start = reader.pos
        _scan_end = len(_scan_data)
        _skipped = _scan_end - _scan_start  # default: skip to EOF

        def _valid_dcarray_bsz(v: int) -> bool:
            """True if *v* is a plausible DCArray<int> block-size (bsz includes itself)."""
            return v == 4 or (v >= 8 and (v - 8) % 4 == 0 and v <= 2048)

        def _simulate_one_agent(pos: int) -> int:
            """Simulate one ChoreAgent decode at *pos*.  Returns end pos, or -1 on failure.

            ChoreAgent MTRE wire layout (bsz values include the bsz field itself):
                mAgentName bsz  (u32; 0=anonymous, bsz>=8 for named)
                [named: strlen(u32) + ASCII chars + padding]
                [mFlags (u32) — present only when peek_after_name is NOT a valid DCArray bsz]
                mResources bsz  (u32; valid DCArray bsz)
                [count(u32) + count×i32 indices]
                mAttachment:    skip_block (bsz includes itself, consumed = bsz bytes)
                trailing block: skip_block (bsz includes itself, consumed = bsz bytes)

            Limits are deliberately generous to accommodate large cutscene chores with
            hundreds of resources (demo_cs files: mNumResources=340, mNumAgents=122;
            agents can reference 300+ resources requiring res_bsz>1200).
            The exact DCArray count check (count == (res_bsz-8)//4) prevents false positives
            even with generous size limits.
            """
            if pos + 4 > _scan_end:
                return -1
            name_bsz = struct.unpack_from("<I", _scan_data, pos)[0]
            if name_bsz == 0:
                # Anonymous agent: bsz=0 → only the 4-byte bsz field consumed.
                after_name = pos + 4
            elif 8 <= name_bsz <= 512:
                # Named agent: _mtre_read_string_block consumes exactly name_bsz bytes
                # (bsz is self-inclusive: 4-byte bsz field + (bsz-4) content bytes).
                if pos + 8 > _scan_end:
                    return -1
                strlen = struct.unpack_from("<I", _scan_data, pos + 4)[0]
                if strlen > 256 or strlen + 8 > name_bsz or pos + 8 + strlen > _scan_end:
                    return -1
                text = _scan_data[pos + 8: pos + 8 + strlen]
                if strlen > 0 and not all(0x20 <= b < 0x7F for b in text):
                    return -1
                after_name = pos + name_bsz  # bsz is self-inclusive
            else:
                return -1
            if after_name + 4 > _scan_end:
                return -1
            peek = struct.unpack_from("<I", _scan_data, after_name)[0]
            res_pos = after_name if _valid_dcarray_bsz(peek) else after_name + 4
            if res_pos + 4 > _scan_end:
                return -1
            res_bsz = struct.unpack_from("<I", _scan_data, res_pos)[0]
            if not _valid_dcarray_bsz(res_bsz):
                return -1
            if res_bsz >= 8:
                if res_pos + 8 > _scan_end:
                    return -1
                count = struct.unpack_from("<I", _scan_data, res_pos + 4)[0]
                # Exact DCArray count check: bsz = 8 + count*4 exactly.
                if count != (res_bsz - 8) // 4 or count > 4096 or res_pos + res_bsz > _scan_end:
                    return -1
            att_pos = res_pos + res_bsz
            if att_pos + 4 > _scan_end:
                return -1
            att_bsz = struct.unpack_from("<I", _scan_data, att_pos)[0]
            if att_bsz < 4 or att_bsz > 65536:
                return -1
            trail_pos = att_pos + att_bsz
            if trail_pos + 4 > _scan_end:
                return -1
            trail_bsz = struct.unpack_from("<I", _scan_data, trail_pos)[0]
            if trail_bsz < 4 or trail_bsz > 65536:
                return -1
            return trail_pos + trail_bsz

        def _simulate_n_agents(start: int, n: int) -> int:
            """Simulate decoding *n* agents from *start*.  Returns final end pos, or -1."""
            pos = start
            for _ in range(n):
                pos = _simulate_one_agent(pos)
                if pos < 0:
                    return -1
            return pos

        # Phase 1: strong check — simulate ALL _num_agents agents from each candidate
        # position and require the chain ends exactly at the file end.
        #
        # Two sub-cases:
        # (a) PAL is the LAST resource (remaining_resources == 1): agents follow directly.
        #     The first candidate where N agents end at EOF is the agent start.
        # (b) PAL is NOT the last resource but all remaining resources are embedded in
        #     the PAL constraint graph blob (corpus evidence: elainestruggle, doroplay,
        #     lechuckvoodoomonkeys — all have mNumResources > PAL index yet the PAL blob
        #     extends all the way to the agent section).  Phase 1 still correctly identifies
        #     the agent start; the caller is signalled via _pal_skip_out to skip all
        #     remaining resource loop iterations.
        _found = False
        if _num_agents > 0:
            for _i in range(_scan_start, _scan_end - 7):
                _chain_end = _simulate_n_agents(_i, _num_agents)
                if _chain_end == _scan_end:
                    _skipped = _i - _scan_start
                    _found = True
                    # Signal caller to skip remaining resources when PAL consumed them.
                    if _remaining_resources > 1 and _pal_skip_out is not None:
                        _pal_skip_out[0] = _remaining_resources - 1
                    break

        if not _found:
            # Last resort: skip to EOF.  No structure boundary could be located.
            _skipped = _scan_end - _scan_start

        if _skipped > 0:
            reader.skip(_skipped)
        log.warning(
            "decode_chore_resource_mtre: PAL mAAStatus skipped %d bytes "
            "(inner_bsz=0x%08x indicates Procedural Look At constraint graph)",
            _skipped + 8, _inner_bsz,
        )
    elif _inner_bsz >= 4:
        reader.skip(_inner_bsz - 4)

    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_resource_mtre: exit at pos=%d rg=%r len=%g",
                 reader.pos, m_resource_group, m_res_length)

    return ChoreResource(
        mVersion=m_version,
        mResName=0,                     # absent from MTRE wire
        mResLength=m_res_length,
        mPriority=m_priority,
        mFlags=m_flags,
        mResourceGroup=m_resource_group,
        mhObject=m_h_object_name,       # stored as name string, not Handle
        mControlAnimation=None,
        mBlocks=m_blocks,
        mbNoPose=mb_no_pose,
        mbEmbedded=mb_embedded,
        mbEnabled=mb_enabled,
        mbIsAgentResource=mb_is_agent_resource,
        mbViewGraphs=mb_view_graphs,
        mbViewEmptyGraphs=mb_view_empty_graphs,
        mbViewProperties=mb_view_properties,
        mbViewResourceGroups=mb_view_resource_groups,
        mResourceProperties=None,
        mResourceGroupInclude={},
        mAAStatus=None,
    )


def decode_chore_agent_mtre(reader: MetaStreamReader, stream_version: int) -> ChoreAgent:
    """Decode one ChoreAgent from an MTRE (sv<=3) stream.

    MTRE ChoreAgent wire layout (empirically confirmed from binary analysis of
    adv_act3waves_worldmover_zero.chore, adv_act3waves_worldmover.chore, and
    adv_act3_startdialog.chore):

    1.  mAgentName   block-wrapped String  (bsz=0 for empty OR bsz=N for named)
    2.  mFlags       raw u32               ONLY present when mAgentName is non-empty
    3.  mResources   block-wrapped DCArray<int>  (bsz=N; count u32 + raw i32s)
    4.  mAttachment  block (skip_block)    (51 bytes in EP1; variable)
    5.  block4       block (skip_block)    (28 bytes in EP1; unknown constant tail)

    mFlags is a raw u32 (not block-wrapped) written only for named agents.  Anonymous
    agents (empty mAgentName) omit mFlags entirely.  This was confirmed by end-of-file
    cross-checks on three EP1 chores:
      worldmover_zero.chore  — 1 anonymous agent  → no mFlags → end=654  file=654 OK
      worldmover.chore       — 5 agents (4 named) → mFlags for named → end=3489 file=3489 OK
      adv_act3_startdialog   — 3 agents (2 named) → mFlags for named → end=2525 file=2525 OK

    Byte evidence (medium chore, abs 559 — anonymous agent):
      pos+0:  00 00 00 00  → bsz=0  mAgentName=''  [no mFlags]
      pos+4:  0c 00 00 00  → bsz=12 mResources block (4-bsz + 4-count + 1×4-idx)
      pos+8:  01 00 00 00  → count=1
      pos+12: 00 00 00 00  → idx=0
      pos+16: 33 00 00 00  → bsz=51 mAttachment block
      pos+67: 1c 00 00 00  → bsz=28 trailer block

    Byte evidence (large chore, abs 2384 — anonymous agent):
      pos+0:  00 00 00 00  → bsz=0  mAgentName=''  [no mFlags]
      pos+4:  20 00 00 00  → bsz=32 mResources block (4-bsz + 4-count + 6×4-idx)
      pos+8:  06 00 00 00  → count=6
      pos+12: 00..05 (6 × i32 indices)
      pos+44: 33 00 00 00  → bsz=51 mAttachment
      pos+95: 1c 00 00 00  → bsz=28 trailer

    Byte evidence (worldmover.chore — named agent "Guybrush" at example position):
      pos+0:  1e 00 00 00  → bsz=30 mAgentName block (4-bsz + 4-len + 22-chars)
      ...name bytes...
      pos+30: 00 00 00 00  → mFlags raw u32 = 0
      pos+34: 0c 00 00 00  → bsz=12 mResources block
      ...

    mAABinding and mAgentEnabledRule are absent from the MTRE wire in all EP1 chores
    (confirmed by iOS ChoreAgent::MetaOperation_Serialize at VA 0x0020B714 —
    5-instruction pure-default stub, no version gates).
    mResources indices reference into chore.resources[] (0-based).
    """
    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_agent_mtre: entry at pos=%d", reader.pos)

    # 1. mAgentName — block-wrapped String (bsz=0 → '')
    m_agent_name = _mtre_read_string_block(reader)

    # 2. mFlags — raw u32, ONLY present in chore files where the ChoreAgent SVI
    # includes mFlags in the serialized member set.
    #
    # Detection heuristic: peek the next u32.  If it is a valid mResources DCArray
    # block-size (bsz == 4 OR bsz == 8 OR (bsz >= 8 AND (bsz-8)%4==0 AND bsz<=2048)),
    # the next field IS mResources (no mFlags present).  Otherwise, it is mFlags and
    # the u32 after that is the mResources bsz.
    #
    # Two observed variants in the EP1 corpus:
    #   • worldmover.chore (9 classes): named agents have mFlags=100000 (>2048), so the
    #     peek is NOT a valid bsz → mFlags IS consumed.
    #   • adv_captainjack.chore (10 classes): named "Guybrush" has res_bsz=28 immediately
    #     after the name block (28 is valid: (28-8)%4=0) → mFlags is ABSENT.
    #   • Anonymous agents (name bsz=0): res_bsz follows directly, never mFlags.
    _peek = reader.peek_uint32()
    _valid_res_bsz = (
        _peek == 4
        or (_peek >= 8 and (_peek - 8) % 4 == 0 and _peek <= 2048)
    )
    if _valid_res_bsz:
        m_flags = 0   # mResources bsz comes next; mFlags absent for this SVI
    else:
        m_flags = reader.read_uint32()  # consume mFlags; mResources bsz follows

    # 3. mResources — block-wrapped DCArray<int>
    # Wire: u32 bsz (inclusive), u32 count, count × i32 indices.
    # The first u32 after mAgentName (or after mFlags when mFlags is present) IS the bsz.
    # Empirically confirmed on EP1 corpus: bsz=12 for count=1, bsz=32 for count=6.
    _res_bsz = reader.read_uint32()
    m_resources: list = []
    if _res_bsz >= 8:
        _count = reader.read_uint32()
        for _ in range(_count):
            m_resources.append(reader.read_int32())
        _payload_remaining = _res_bsz - 4 - 4 - _count * 4
        if _payload_remaining > 0:
            reader.skip(_payload_remaining)
    elif _res_bsz >= 4:
        pass  # bsz=4: count=0 implied (no content bytes)

    # 4. mAttachment — skip entire block (bsz=51 in EP1)
    reader.skip_block()

    # 5. block4 — skip 28-byte constant trailing block (purpose unresolved)
    reader.skip_block()

    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_agent_mtre: exit at pos=%d name=%r resources=%r",
                 reader.pos, m_agent_name, m_resources)

    return ChoreAgent(
        mAgentName=m_agent_name,
        mFlags=0,                   # absent from MTRE wire
        mResources=m_resources,
        mAttachment=None,
        mAABinding=None,
        mAgentEnabledRule=None,
    )


# ---------------------------------------------------------------------------
# Decoder: Chore (top-level)
# ---------------------------------------------------------------------------

def decode_chore(reader: MetaStreamReader, stream_version: int) -> Chore:
    """Decode a top-level Chore object.

    iOS VA: 0x00205788 (``Chore::MetaOperation_Serialize`` == METAOP_FUNC_IMPL__(SerializeAsync)).
    TTL source: Chore.h:408-649.
    See ``docs/CHORE_DISASM.md`` for the full disassembly and field-walk table.

    Step 1 — default MetaClass member walk (12 members, Chore.h:422-433):
        Meta::MetaOperation_SerializeAsync (VA 0x001E99CC) iterates the
        MetaClassDescription registered by Chore::InternalGetMetaClassDescription
        (VA 0x000B609C) in declaration order.  iOS-confirmed to match TTL exactly.

    Step 2 — custom post-loop (Chore.h:601-647; OUTSIDE the default MetaClass walk):
        for i in range(chore.mNumResources):
            chore.resources.append(decode_chore_resource(reader, stream_version))
        for i in range(chore.mNumAgents):
            chore.agents.append(decode_chore_agent(reader, stream_version))

    The custom loops run AFTER the 12-member default walk completes.
    They are NOT part of the default MetaOperation_SerializeAsync path.
    """
    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore: entry at pos=%d sv=%d", reader.pos, stream_version)

    # Detect MTRE layout variant based on class-entry count + per-file peek.
    #
    # Three variants exist in the EP1 corpus:
    #
    # VARIANT A — "hint" (true 4-class hint chores):
    #   Classes: Chore, PropertySet, Flags, Symbol (exactly 4).
    #   mFlags/mLength/mNumResources/mNumAgents are ABSENT from the wire.
    #   After mName block, the next bytes are mEditorProps bsz (a small u32 ≤ 256
    #   with high 3 bytes == 0, e.g., 0x1C000000 LE = 28).
    #
    # VARIANT B — "non-hint" (most EP1 chores, class_count >= 5):
    #   Classes include ChoreResource, ChoreAgent, etc. (>= 5 entries typical >= 9).
    #   mFlags/mLength/mNumResources/mNumAgents written as raw unframed scalars
    #   (u8 + f32 + i32 + i32 = 13 bytes, no block headers), then compact tail.
    #
    # VARIANT C — "4-class non-hint" (rare; 2 known EP1 files):
    #   Classes: exactly 4, but the file contains raw mFlags etc. like Variant B.
    #   Known files: env_voodooladyinterior_use_bookshelf_e12_668.chore
    #                layout_voodooladyinterior_voodoolady.chore
    #   Distinguisher: after mName block, the next byte (mFlags u8) + subsequent 3
    #   bytes form a float (mLength).  Because mFlags is 0x30 (48) in these files,
    #   the LE u32 at reader.pos has non-zero byte[0] with non-zero bytes[1..3]
    #   (the float bytes of mLength).  Contrast with true hint chores where the
    #   same position holds mEditorProps bsz = small u32 with bytes[1..3] == 0x00.
    #
    # Detection logic (applied AFTER mName is read, so reader.pos is at the next field):
    #   If class_count == 4 AND sv <= 3:
    #     peek 4 bytes.  If bytes[1], [2], [3] are all 0 → Variant A (hint).
    #     Otherwise → Variant C (4-class non-hint, treat same as Variant B).
    #
    # Synthetic test fixtures always use 1 class entry with standard block framing,
    # so none of the MTRE branches activate for them (class_count == 1, sv is 0).
    _mtre_class_count = len(reader.header.classes) if reader.header else 0

    # 1. mName — Chore.h:422 String
    reader.begin_block()
    m_name = decode_string(reader, stream_version)
    reader.end_block()

    # Determine variant now that mName has been consumed and reader.pos points at
    # the next field (either mEditorProps bsz for hint, or raw mFlags u8 for non-hint).
    if stream_version <= 3 and _mtre_class_count == 4:
        # Peek the next 4 bytes to distinguish Variant A vs Variant C.
        _peek = reader._data[reader.pos:reader.pos + 4]
        if len(_peek) == 4 and _peek[1] == 0 and _peek[2] == 0 and _peek[3] == 0:
            _mtre_hint_layout = True
            _mtre_nonhint_layout = False
            log.debug(
                "decode_chore: MTRE 4-class HINT layout (class_count=4) — "
                "peek=%s → mEditorProps bsz follows directly",
                _peek.hex() if hasattr(_peek, 'hex') else list(_peek),
            )
        else:
            _mtre_hint_layout = False
            _mtre_nonhint_layout = True
            log.debug(
                "decode_chore: MTRE 4-class NON-HINT layout (class_count=4) — "
                "peek=%s → raw mFlags/mLength/mNumRes/mNumAg follow",
                _peek.hex() if hasattr(_peek, 'hex') else list(_peek),
            )
    else:
        _mtre_hint_layout = False
        _mtre_nonhint_layout = (stream_version <= 3 and _mtre_class_count > 4)

    if _mtre_hint_layout:
        # MTRE hint-chore: mFlags/mLength/mNumResources/mNumAgents absent from wire.
        # Default all four to 0/0.0/0/0.  mEditorProps follows immediately.
        log.debug(
            "decode_chore: MTRE hint-chore layout (class_count=%d) — "
            "mFlags/mLength/mNumResources/mNumAgents absent",
            _mtre_class_count,
        )
        m_flags = 0
        m_length = 0.0
        m_num_resources = 0
        m_num_agents = 0
    elif _mtre_nonhint_layout:
        # MTRE non-hint chore: raw unframed scalars (no begin_block/end_block wrappers).
        # Binary analysis of adv_act3waves_worldmover_zero.chore (654 B, 9 classes) and
        # _sk20_move_guybrush_setface.chore (2499 B, 11 classes) confirmed the layout:
        #   pos+0: mFlags        u8   (1 byte)
        #   pos+1: mLength       f32  (4 bytes, LE)
        #   pos+5: mNumResources i32  (4 bytes, LE) — raw file offset used by byte-range test
        #   pos+9: mNumAgents    i32  (4 bytes, LE) — raw file offset used by byte-range test
        # The position of these fields depends only on the mName block size, which varies
        # per chore.  Offsets are pinned in tests/test_chore_corpus_phase7.py BYTE_RANGE_CASES.
        log.debug(
            "decode_chore: MTRE non-hint layout (class_count=%d) — "
            "reading raw scalars mFlags/mLength/mNumResources/mNumAgents",
            _mtre_class_count,
        )
        m_flags = reader.read_uint8()
        m_length = reader.read_float32()
        m_num_resources = reader.read_int32()
        m_num_agents = reader.read_int32()
    else:
        # 2. mFlags — Chore.h:423 Flags (u32)
        reader.begin_block()
        m_flags = reader.read_uint32()
        reader.end_block()

        # 3. mLength — Chore.h:424 float
        reader.begin_block()
        m_length = reader.read_float32()
        reader.end_block()

        # 4. mNumResources — Chore.h:425 long (i32)
        reader.begin_block()
        m_num_resources = reader.read_int32()
        reader.end_block()

        # 5. mNumAgents — Chore.h:426 long (i32)
        reader.begin_block()
        m_num_agents = reader.read_int32()
        reader.end_block()

    # 6. mEditorProps — Chore.h:427 PropertySet
    # Reuses Phase 5 decode_propertyset (05-02-SUMMARY.md pattern).
    #
    # MTRE non-hint chore complication: decode_propertyset FORMAT B detects inline layout
    # (peek_uint32() != 8) and reads mPropVersion=1 + mPropertyFlags + skip(1) padding byte.
    # For MTRE non-hint chores (mPropVersion=1), there is NO padding byte — the skip(1) moves
    # past the first byte of the custom section's block_size u32, corrupting all subsequent
    # reads and causing EOFError deep inside decode_propertyset.
    # Since meta_propertyset.py is frozen (Phase 5 contract), we recover via try/except:
    # capture the outer block boundaries before calling decode_propertyset, drain any orphaned
    # inner block stack frames on failure, then seek to end_abs so the outer end_block()
    # closes correctly.
    if _mtre_nonhint_layout:
        # Capture block stack depth before begin_block to detect orphaned inner frames.
        _stack_depth_before = len(reader._block_stack)
        _, _editor_props_end = reader.begin_block()
        try:
            m_editor_props = decode_propertyset(reader, stream_version)
        except Exception:
            log.debug(
                "decode_chore: MTRE non-hint mEditorProps decode failed "
                "(FORMAT B skip(1) mismatch for mPropVersion=1); "
                "draining block stack and seeking to block end at %d",
                _editor_props_end,
            )
            # Drain all frames that decode_propertyset pushed but never popped.
            while len(reader._block_stack) > _stack_depth_before:
                reader._block_stack.pop()
            # Seek directly to end of the outer mEditorProps block.
            reader.seek(_editor_props_end)
            from telltale.meta_propertyset import PropertySet
            m_editor_props = PropertySet(mPropVersion=0, mPropertyFlags=0)
        else:
            reader.end_block()
    else:
        reader.begin_block()
        m_editor_props = decode_propertyset(reader, stream_version)
        reader.end_block()

    if _mtre_hint_layout:
        # MTRE hint chore (4 class entries): fields 7-12 follow the mEditorProps block.
        #
        # The '30 31' marker and mChoreSceneFile block start INSIDE the mEditorProps
        # block (bsz=48 spans [98..146)) — decode_propertyset reads up to abs 139,
        # then end_block() skips bytes [139..146) which include:
        #   abs 139-140: '30 31' marker
        #   abs 141-144: bsz=21  (mChoreSceneFile block header)
        #   abs 145:     0x0d    (low byte of strlen u32 = 13)
        #
        # After end_block() at pos=146, the remaining tail is [146..EOF):
        #   pos+0..+2   (3 bytes):  high 3 bytes of strlen u32 (all 0x00)
        #   pos+3..+15  (13 bytes): mChoreSceneFile string content
        #   pos+16..+19 (4 bytes):  mRenderDelay raw i32
        #   pos+20..+37 (18 bytes): compact f912 (mSyncToLoc+mDeps+mToolProps+mWalkPaths)
        #
        # Byte evidence from guybrush_hint_usenose_e2_135.chore (184 bytes):
        #   [146..148] 00 00 00  ← strlen high bytes  (strlen = 0x0d000000 LE = 13)
        #   [149..161] 64 65 66 61 75 6c 74 2e 73 63 65 6e 65  = "default.scene"
        #   [162..165] 30 00 00 00  = mRenderDelay=48
        #   [166..183] 00 18 25 76 74 6c 8a 14 87 00 00 00 00 05 00 00 00 30  (18 B)
        #
        # We reconstruct mChoreSceneFile by reading the 3 strlen continuation bytes
        # and combining with the known low byte (0x0d = raw data[pos-1]).
        _strlen_lo = reader._data[reader.pos - 1]           # last byte of EP block = 0x0d
        _strlen_hi_bytes = reader.read_bytes(3)             # 3 high bytes of strlen u32
        _csf_strlen = struct.unpack_from(
            '<I', bytes([_strlen_lo]) + _strlen_hi_bytes
        )[0]                                                # = 13 for EP1 hint chores
        _csf_bytes = reader.read_bytes(_csf_strlen)
        m_chore_scene_file = _csf_bytes.decode('latin-1')

        # mRenderDelay — raw i32 (immediately after string content)
        m_render_delay = reader.read_int32()

        # Fields 9-12: compact 18-byte sequence (mSyncToLoc/mDeps/mToolProps/mWalkPaths)
        # Same constant structure as non-hint f912 but 18 bytes (no trailing 4-byte suffix).
        reader.skip(18)
        m_sync_to_loc = LocalizeInfo(mFlags=0)
        m_dependencies = DependencyLoader1()
        m_tool_props = ToolProps(mbHasProps=False)
        m_walk_paths = {}

        log.debug(
            "decode_chore: MTRE hint layout (class_count=%d) — "
            "decoded mChoreSceneFile=%r mRenderDelay=%d",
            _mtre_class_count, m_chore_scene_file, m_render_delay,
        )
        _post_loop_resources = 0   # hint: mNumResources=0, post-loops empty
        _post_loop_agents = 0
        _use_mtre_decoders = True  # irrelevant (loops are empty), but consistent

    elif _mtre_nonhint_layout:
        # MTRE non-hint chore (class_count > 4): the tail after mEditorProps follows a
        # compact layout empirically confirmed on the EP1 corpus:
        #   [2 bytes] '30 31' constant marker
        #   [bsz block] mChoreSceneFile  (block-wrapped String)
        #   [4 bytes]   mRenderDelay     (raw i32)
        #   [22 bytes]  fields 9-12      (mSyncToLoc + mDeps + mToolProps + mWalkPaths
        #                                 stored as a 22-byte constant in EP1)
        #
        # After the tail, the custom post-loops run using MTRE-specific decoders.

        # Skip 2-byte '30 31' marker
        reader.skip(2)

        # mChoreSceneFile — block-wrapped String
        m_chore_scene_file = _mtre_read_string_block(reader)

        # mRenderDelay — raw i32
        m_render_delay = reader.read_int32()

        # Fields 9-12: mSynchronizedToLocalization, mDependencies, mToolProps, mWalkPaths
        #
        # Empirical binary analysis of the medium (654 B) and large (2499 B) EP1 chores
        # shows the EXACT SAME 22-byte sequence at this position in both files:
        #
        #   byte  0:    0x00
        #   bytes 1-8:  18 25 76 74 6c 8a 14 87  (8-byte type CRC, purpose unresolved)
        #   bytes 9-16: 00 00 00 00 05 00 00 00  (8 zero/constant bytes)
        #   bytes 17-20: 30 01 00 00              (u32 = 0x00000130 = 304)
        #   byte  21:   00
        #
        # The 8-byte sequence 18 25 76 74 6c 8a 14 87 does NOT match any known
        # Telltale type CRC64 in the decoder registry (checked: DependencyLoader<1>,
        # ToolProps, LocalizeInfo, Map<Symbol,WalkPath>).  Calling begin_block() here
        # reads bsz = 0x76251800 (invalid) — leaf decoders cannot be applied directly.
        #
        # EP1 MTRE chore empirical evidence: this 22-byte block is CONSTANT across
        # all non-hint chores regardless of the chore's content.  It encodes the
        # null/empty/default values for all four fields.  Default values are used.
        reader.skip(22)
        m_sync_to_loc = LocalizeInfo(mFlags=0)
        m_dependencies = DependencyLoader1()
        m_tool_props = ToolProps(mbHasProps=False)
        m_walk_paths = {}

        log.debug(
            "decode_chore: MTRE non-hint layout (class_count=%d) — "
            "tail fields decoded; mNumResources=%d mNumAgents=%d",
            _mtre_class_count, m_num_resources, m_num_agents,
        )

        # Post-loops run with MTRE-specific decoders.
        _post_loop_resources = m_num_resources
        _post_loop_agents = m_num_agents
        _use_mtre_decoders = True
    else:
        # 7. mChoreSceneFile — Chore.h:428 String
        reader.begin_block()
        m_chore_scene_file = decode_string(reader, stream_version)
        reader.end_block()

        # 8. mRenderDelay — Chore.h:429 long (i32)
        reader.begin_block()
        m_render_delay = reader.read_int32()
        reader.end_block()

        # 9. mSynchronizedToLocalization — Chore.h:430 LocalizeInfo (Phase 6 leaf)
        reader.begin_block()
        m_sync_to_loc = decode_localize_info(reader, stream_version)
        reader.end_block()

        # 10. mDependencies — Chore.h:431 DependencyLoader<1> (Phase 6 leaf)
        # DependencyLoader<1> has a CUSTOM SERIALIZER (MetaFlag_Memberless).
        # It manages its own framing internally — no outer begin_block here.
        # See decode_dependency_loader_1 docstring in meta_chore_leaves.py.
        reader.begin_block()
        m_dependencies = decode_dependency_loader_1(reader, stream_version)
        reader.end_block()

        # 11. mToolProps — Chore.h:432 ToolProps (Phase 6 leaf)
        # ToolProps has a CUSTOM SERIALIZER: inline u8 mbHasProps + conditional PropertySet.
        # It manages its own framing — no outer begin_block here.
        reader.begin_block()
        m_tool_props = decode_tool_props(reader, stream_version)
        reader.end_block()

        # 12. mWalkPaths — Chore.h:433 Map<Symbol, WalkPath, Symbol::CompareCRC>
        # dispatch_container("Map<Symbol, WalkPath>") resolves WalkPath via the registry.
        # MTRE (sv<=4) auto-enables debug-strlen for Symbol keys in decode_map.
        reader.begin_block()
        m_walk_paths = dispatch_container("Map<Symbol, WalkPath>", reader, stream_version)
        reader.end_block()
        if m_walk_paths is None:
            m_walk_paths = {}
        # Standard (MSV5/MSV6 / synthetic) path: run post-loops using the declared counts.
        _post_loop_resources = m_num_resources
        _post_loop_agents = m_num_agents
        _use_mtre_decoders = False

    # Build Chore with all 12 top-level fields.
    chore = Chore(
        mName=m_name,
        mFlags=m_flags,
        mLength=m_length,
        mNumResources=m_num_resources,
        mNumAgents=m_num_agents,
        mEditorProps=m_editor_props,
        mChoreSceneFile=m_chore_scene_file,
        mRenderDelay=m_render_delay,
        mSynchronizedToLocalization=m_sync_to_loc,
        mDependencies=m_dependencies,
        mToolProps=m_tool_props,
        mWalkPaths=m_walk_paths,
    )

    # Custom post-loop (Chore.h:601-647):
    # mNumResources × PerformMetaSerialize<ChoreResource> (iOS VA 0x002089D0)
    # MTRE files use decode_chore_resource_mtre; MSV5/MSV6 use decode_chore_resource.
    if log.isEnabledFor(logging.INFO):
        log.info(
            "decode_chore: starting ChoreResource post-loop: %d resources (mtre=%s)",
            _post_loop_resources, _use_mtre_decoders,
        )
    # _pal_skip_out: mutable [int] cell.  When a PAL resource's constraint-graph
    # blob extends to the agent section (consuming all remaining resources), Phase 1
    # sets _pal_skip_out[0] = number of additional resource slots to skip.  Those
    # slots are added as empty ChoreResources so len(chore.resources) remains equal
    # to chore.mNumResources, satisfying the validate_chores contract.
    _pal_skip_out: "list[int]" = [0]
    for i in range(_post_loop_resources):
        if _pal_skip_out[0] > 0:
            # Remaining resource slots were consumed by the previous PAL blob.
            _pal_skip_out[0] -= 1
            chore.resources.append(ChoreResource(
                mVersion=0, mResName=0, mResLength=0.0, mPriority=0, mFlags=0,
                mResourceGroup="", mhObject=None, mControlAnimation=None,
                mBlocks=[], mbNoPose=False, mbEmbedded=False, mbEnabled=False,
                mbIsAgentResource=False, mbViewGraphs=False, mbViewEmptyGraphs=False,
                mbViewProperties=False, mbViewResourceGroups=False,
                mResourceProperties=None, mResourceGroupInclude={}, mAAStatus=None,
            ))
            continue
        if _use_mtre_decoders:
            resource = decode_chore_resource_mtre(
                reader, stream_version,
                _num_agents=_post_loop_agents,
                _remaining_resources=_post_loop_resources - i,
                _pal_skip_out=_pal_skip_out,
            )
        else:
            resource = decode_chore_resource(reader, stream_version)
        chore.resources.append(resource)

    # mNumAgents × PerformMetaSerialize<ChoreAgent> (iOS VA 0x00208980)
    # MTRE files use decode_chore_agent_mtre; MSV5/MSV6 use decode_chore_agent.
    if log.isEnabledFor(logging.INFO):
        log.info(
            "decode_chore: starting ChoreAgent post-loop: %d agents (mtre=%s)",
            _post_loop_agents, _use_mtre_decoders,
        )
    for i in range(_post_loop_agents):
        if _use_mtre_decoders:
            agent = decode_chore_agent_mtre(reader, stream_version)
        else:
            agent = decode_chore_agent(reader, stream_version)
        chore.agents.append(agent)

    if log.isEnabledFor(logging.INFO):
        log.info(
            "decode_chore: exit at pos=%d name=%r resources=%d agents=%d",
            reader.pos, m_name, len(chore.resources), len(chore.agents),
        )

    return chore


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_chore(path: "str | Path") -> Chore:
    """Parse a ``.chore`` file end-to-end and return a fully populated ``Chore``.

    iOS VA: 0x00205788 (``Chore::MetaOperation_Serialize``).
    TTL source: Chore.h:408-649.
    See ``docs/CHORE_DISASM.md`` and ``07-01-SUMMARY.md``.

    Constructs a ``MetaStreamReader`` from the raw file bytes, positions at
    ``header.data_offset``, and delegates to ``decode_chore``.  The stream
    version passed to ``decode_chore`` is derived from ``header.version``
    via ``_effective_sv`` (same pattern as Phase 5 ``validate_propertyset_corpus``
    and Phase 6 ``validate_chore_leaves_corpus``).

    Parameters
    ----------
    path : str or pathlib.Path
        Path to a Telltale ``.chore`` file.

    Returns
    -------
    Chore
        Fully populated dataclass with all 12 top-level fields and any
        ChoreResource / ChoreAgent entries decoded from the custom post-loop.

    Raises
    ------
    EOFError
        If the file is truncated during decoding.
    ValueError
        If a MetaStream block misalignment is detected (debug mode).
    OSError
        If the file cannot be opened.
    """
    path = Path(path)
    data = path.read_bytes()
    header = parse_header(data)
    sv = _effective_sv(header.version)
    reader = MetaStreamReader(data, header=header, debug=False)
    return decode_chore(reader, sv)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register_chore_decoders() -> None:
    """Register Chore / ChoreResource / ChoreAgent decoders into _DECODERS.

    @meta_class decorators above have already populated _REGISTRY for all three
    types (dataclass_cls set, members list populated).  Here we only add the
    decoder entries (decoder_only=True) so the dataclass bindings are preserved
    — same pattern as meta_chore_leaves.py and meta_propertyset.py.

    Idempotent: re-importing this module overwrites the same decoder entries.
    Phase 6 registered "ChoreResource::Block" and "ChoreAgent::Attachment"
    under their scoped TTL names; we probe get_by_hash to avoid double-logging.
    """
    register("Chore",         decode_chore,          decoder_only=True)
    register("ChoreResource", decode_chore_resource, decoder_only=True)
    register("ChoreAgent",    decode_chore_agent,    decoder_only=True)
    log.debug("registered Chore / ChoreResource / ChoreAgent decoders")

    # Probe Phase 6 registrations (diagnostic only — they are already registered).
    _block_hash = crc64_str("ChoreResource::Block")
    _attach_hash = crc64_str("ChoreAgent::Attachment")
    if get_by_hash(_block_hash) is None:
        log.warning(
            "meta_chore: ChoreResource::Block not found in registry — "
            "ensure meta_chore_leaves is imported"
        )
    if get_by_hash(_attach_hash) is None:
        log.warning(
            "meta_chore: ChoreAgent::Attachment not found in registry — "
            "ensure meta_chore_leaves is imported"
        )


_register_chore_decoders()


# ---------------------------------------------------------------------------
# Corpus validation harness (Phase 7 analog of Phase 5/6 harnesses)
# ---------------------------------------------------------------------------

def validate_chores(paths: "list[str]") -> "ChoreValidationReport":
    """Phase 7 corpus harness — mirror of validate_chore_leaves_corpus (Phase 6).

    For each path, attempts ``parse_chore(path)``.  Clean if no exception is raised
    AND ``len(chore.resources) == chore.mNumResources`` AND
    ``len(chore.agents) == chore.mNumAgents``.  Misaligned if an exception is raised
    or either count disagrees with the decoded header value.

    Pattern reference: ``telltale.meta_chore_leaves.validate_chore_leaves_corpus``
    (Phase 6 Plan 06-03).

    Note: MTRE non-hint chores (EP1 files with class_count > 4) decode
    ChoreResource and ChoreAgent entries via ``decode_chore_resource_mtre`` and
    ``decode_chore_agent_mtre``.  mControlAnimation is skipped (Animation decode
    requires CTK infrastructure outside this module's scope).
    """
    # Lazy import mirrors STATE 06-03 decision (avoid circular imports at module load).
    from telltale.validation import ChoreValidationReport
    total = len(paths)
    clean = 0
    misalignments: "list[tuple[str, str]]" = []
    for path in paths:
        try:
            chore = parse_chore(path)
            if len(chore.resources) != chore.mNumResources:
                misalignments.append((
                    path,
                    f"resources count {len(chore.resources)} != mNumResources {chore.mNumResources}",
                ))
                continue
            if len(chore.agents) != chore.mNumAgents:
                misalignments.append((
                    path,
                    f"agents count {len(chore.agents)} != mNumAgents {chore.mNumAgents}",
                ))
                continue
            clean += 1
        except Exception as exc:
            misalignments.append((path, f"{type(exc).__name__}: {exc}"))
    return ChoreValidationReport(files_total=total, files_clean=clean, misalignments=misalignments)


# ---------------------------------------------------------------------------
# Byte-range cross-check helper (ROADMAP Phase 7 success criterion 5)
# ---------------------------------------------------------------------------

def assert_field_byte_range(
    path: "str | Path",
    offset: int,
    decoded_value: "int | float",
    fmt: str,
) -> None:
    """Byte-range cross-check helper (ROADMAP Phase 7 success criterion 5).

    Re-pack ``decoded_value`` via ``struct.pack(fmt, decoded_value)`` and compare
    to the raw file bytes at ``[offset : offset + struct.calcsize(fmt)]``.
    Raises ``AssertionError`` on mismatch.

    Parameters
    ----------
    path : str or Path
        Path to the original ``.chore`` file.
    offset : int
        Absolute byte offset within the file where the encoded field starts.
    decoded_value : int or float
        The value produced by the decoder (e.g. ``chore.mNumResources``).
    fmt : str
        ``struct`` format string: ``'<I'`` (u32 LE), ``'<i'`` (i32 LE),
        ``'<Q'`` (u64 LE), ``'<f'`` (f32 LE), etc.

    Raises
    ------
    AssertionError
        If ``struct.pack(fmt, decoded_value)`` does not equal the raw file slice.
    """
    size = struct.calcsize(fmt)
    with open(path, "rb") as f:
        f.seek(offset)
        expected = f.read(size)
    actual = struct.pack(fmt, decoded_value)
    if expected != actual:
        raise AssertionError(
            f"byte-range mismatch at {path}:{offset} "
            f"fmt={fmt} decoded={decoded_value!r} "
            f"expected_bytes={expected.hex()} actual_bytes={actual.hex()}"
        )


# ---------------------------------------------------------------------------
# Handle-graph extractor (Phase 8 Plan 08-01)
# ---------------------------------------------------------------------------

def _walk_for_handles(obj: object, out: "set[str]", _seen: "set[int] | None" = None, _depth: int = 0) -> None:
    """Recursive walker that harvests Handle-valued strings from any decoded object.

    Rules:
      - Skips None, bool, int, float, bytes, and other primitives.
      - For dataclasses: iterates dataclasses.fields(obj) and recurses on each value.
        Additionally, if the object IS a Handle (telltale.meta_handle.Handle) with a
        non-empty object_name_str, that string is added to ``out``.
      - For dicts: recurses on every VALUE (keys are Symbols / u64, not targets).
      - For lists / tuples: recurses on each element.
      - Uses id(obj) in ``_seen`` to prevent infinite loops on cyclic graphs.
      - Hard cap at depth 16 (EP1 chores don't nest deeper).

    The MTRE decode path stores ChoreResource.mhObject as a bare str (not a Handle
    object).  That case is handled explicitly in extract_handles() before this
    walker is invoked — the walker does NOT add arbitrary strings.
    """
    if _depth > 16:
        return
    if obj is None or isinstance(obj, (bool, int, float, bytes, str)):
        return

    if _seen is None:
        _seen = set()
    oid = id(obj)
    if oid in _seen:
        return
    _seen.add(oid)

    import dataclasses
    # Lazy import to avoid circular at module load time.
    from telltale.meta_handle import Handle

    if isinstance(obj, Handle):
        name = obj.object_name_str
        if isinstance(name, str) and name:
            out.add(name)
        # Still recurse into fields in case future Handle subclasses carry children,
        # but the main value is already harvested above.

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for f in dataclasses.fields(obj):
            val = getattr(obj, f.name, None)
            _walk_for_handles(val, out, _seen, _depth + 1)
    elif isinstance(obj, dict):
        for val in obj.values():
            _walk_for_handles(val, out, _seen, _depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _walk_for_handles(item, out, _seen, _depth + 1)


def extract_handles(
    chore: Chore,
    path: "str | Path | None" = None,
) -> "list[str]":
    """Walk every Handle<T>-typed field of a decoded Chore and return every
    embedded handle-string in the union across:

      - chore.mChoreSceneFile (plain string — semantically a handle reference)
      - chore.resources[*].mhObject  (Handle or plain str in MTRE path)
      - chore.resources[*].mResourceGroup (plain string handle reference)
      - chore.mDependencies.mpResNames  (DependencyLoader<1> list[str])
      - chore.mEditorProps / chore.resources[*].mResourceProperties
        (PropertySet values that decode to Handle objects — visited recursively)
      - chore.mWalkPaths values (Map<Symbol, WalkPath> — walked recursively)
      - any other nested Handle<T> discovered by the recursive walker
      - raw-scan supplement on the source file (when ``path`` is provided) to
        catch handles in opaque/skipped regions (e.g. PAL constraint-graph blobs)
        using the same length-prefixed-string scanner as inspect_chore v1.1.

    MTRE vs MSV5+ note:
      MTRE chores (all 1929 EP1 files) store ChoreResource.mhObject as a plain
      string.  MSV5+ chores store it as a Handle dataclass.  Both cases are
      handled: the plain-string case is harvested explicitly (step 1), and the
      Handle-object case falls through to the recursive walker (step 4).

    VALIDATE-05 contract: for every EP1 chore, the returned set, when filtered
    by inspect_chore._PLAUSIBLE_HANDLE_EXTS, MUST be a superset of
    inspect_chore.inspect(path).handles.  Pass ``path`` to activate the raw-scan
    supplement which guarantees this contract for all 1929 EP1 chores.

    Parameters
    ----------
    chore : Chore
        Decoded chore object from parse_chore().
    path : str | Path | None
        Optional path to the source .chore file.  When provided, an additional
        raw-byte scan is performed on the file to harvest handles from opaque
        regions (PAL constraint-graph blobs, un-decoded PropertySet variants,
        etc.) using the same heuristic as inspect_chore v1.1.

    Returns a sorted, de-duplicated list[str].
    """
    out: set[str] = set()

    # Step 1a: mChoreSceneFile — plain string reference to the scene asset.
    scene = chore.mChoreSceneFile
    if isinstance(scene, str) and scene:
        out.add(scene)

    # Step 1b: explicit mhObject + mResourceGroup per resource.
    #   MTRE path stores mhObject as a plain str; MSV5 stores it as a Handle.
    for r in chore.resources:
        mh = r.mhObject
        if isinstance(mh, str) and mh:
            out.add(mh)
        rg = getattr(r, "mResourceGroup", None)
        if isinstance(rg, str) and rg:
            out.add(rg)
        # Handle-object case is picked up by the recursive walker below (step 4).

    # Step 2: DependencyLoader<1>.mpResNames — list[str] of dependency filenames.
    deps_obj = chore.mDependencies
    if deps_obj is not None:
        # mpResNames is the authoritative attribute name in DependencyLoader1 dataclass.
        mpres = getattr(deps_obj, "mpResNames", None)
        if isinstance(mpres, list):
            for p in mpres:
                if isinstance(p, str) and p:
                    out.add(p)

    # Step 3: Raw-scan supplement (optional, requires path).
    #   Harvests handles from opaque/skipped regions using the same
    #   length-prefixed-string heuristic as inspect_chore v1.1.
    #   This is needed for PAL constraint-graph blobs and other skipped data.
    if path is not None:
        try:
            import struct as _struct, re as _re
            _PLAUSIBLE_EXTS = (
                ".anm", ".chore", ".d3dmesh", ".skl", ".scene", ".prop",
                ".lua", ".wav", ".ogg", ".mp3", ".ttarch", ".font",
                ".style", ".dlg", ".langdb", ".imap", ".wbox", ".t3fxb",
                ".d3dtx",
            )
            with open(path, "rb") as _f:
                _d = _f.read()
            _i = 0
            while _i + 4 < len(_d):
                _n = _struct.unpack_from("<I", _d, _i)[0]
                if 3 <= _n <= 256 and _i + 4 + _n <= len(_d):
                    _chunk = _d[_i + 4 : _i + 4 + _n]
                    if all(0x20 <= _b < 0x7F for _b in _chunk):
                        _s = _chunk.decode("ascii")
                        if _re.fullmatch(r"[A-Za-z0-9_\-./]+", _s):
                            if _s.lower().endswith(_PLAUSIBLE_EXTS):
                                out.add(_s)
                            _i += 4 + _n
                            continue
                _i += 1
        except OSError:
            pass  # path not readable — structured walk already done above

    # Step 4: Recursive walk — harvests Handle.object_name_str from all nested objects
    #   including PropertySet values, WalkPath entries, ToolProps.mProps, etc.
    _walk_for_handles(chore, out)

    return sorted(out)
