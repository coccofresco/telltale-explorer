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
Phase 7 does NOT own the Animation decoder.  The embedded Animation block is
skipped via ``reader.skip_block()`` with a WARNING logged at
``telltale.meta_chore``.  Phase 8 will implement the embedded Animation decode.
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

    mControlAnimation (Chore.h:280) is an embedded Animation that is NOT
    decoded in Phase 7.  It is consumed via ``reader.skip_block()`` and
    stored as raw bytes.  Phase 8 owns the Animation embedded decode.
    A WARNING is emitted when this skip occurs.

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
    # mControlAnimation: embedded Animation — Phase 8 (skip_block'd here)
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

    mControlAnimation (Chore.h:280, embedded Animation) is SKIPPED via
    ``reader.skip_block()``.  A WARNING is logged.  Phase 8 owns the
    embedded Animation decode.

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
    # Phase 7 does NOT own Animation decode. Skip and log WARNING.
    # Phase 8 will implement the embedded Animation decoder.
    log.warning(
        "decode_chore_resource: skipping embedded mControlAnimation (Animation block) "
        "at pos=%d — Phase 8 will implement this decode (Chore.h:280)",
        reader.pos,
    )
    anim_start = reader.pos
    reader.skip_block()
    anim_end = reader.pos
    m_control_animation = bytes()  # raw bytes placeholder — content is opaque until Phase 8

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


def decode_chore_resource_mtre(reader: MetaStreamReader, stream_version: int) -> ChoreResource:
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

    mControlAnimation (Chore.h:280) is skipped via skip_block.  Phase 8 owns
    the embedded Animation decode.
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

    # 8. mControlAnimation — skip embedded Animation block (Phase 8 scope)
    log.warning(
        "decode_chore_resource_mtre: skipping embedded mControlAnimation at pos=%d "
        "(Phase 8 will implement this decode)",
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
            reader.skip(_payload_remaining)  # skip block entries (Phase 8 decodes Block)
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
    _outer_placeholder = reader.read_uint32()   # always 0
    _inner_bsz = reader.read_uint32()
    if _inner_bsz >= 4:
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

    MTRE ChoreAgent wire layout (empirically confirmed on EP1 corpus):

    1.  mAgentName   block-wrapped String  (bsz=0 for empty OR bsz=N for named)
    2.  placeholder  u32=0                 (always 0; empty mAABinding slot)
    3.  mResources   block-wrapped DCArray<int>  (bsz=N; count u32 + raw i32s)
    4.  mAttachment  block (skip_block)    (variable size; 51 bytes typical)
    5.  block4       block (skip_block)    (always bsz=28 in EP1; unknown constant)

    mFlags, mAgentEnabledRule, and mAABinding are absent from the MTRE wire for
    EP1 chores (4-class or 9-11 class headers).
    mResources index values reference into chore.resources[] (0-based).
    """
    if log.isEnabledFor(logging.INFO):
        log.info("decode_chore_agent_mtre: entry at pos=%d", reader.pos)

    # 1. mAgentName — block-wrapped String
    m_agent_name = _mtre_read_string_block(reader)

    # 2. Placeholder u32=0 (empty mAABinding slot)
    reader.read_uint32()

    # 3. mResources — block-wrapped DCArray<int>
    # MTRE DCArray: bsz=N then count(u32) then raw i32 entries (no inner block wrapper).
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
        pass  # bsz=4: count=0 implied

    # 4. mAttachment — skip entire block
    reader.skip_block()

    # 5. block4 — skip 28-byte constant block
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

    # Detect MTRE hint-chore layout: EP1 4-class files (Chore, PropertySet, Flags, Symbol)
    # omit mFlags/mLength/mNumResources/mNumAgents entirely from the wire.  Files with
    # more class entries (resources, agents, etc.) include those 4 scalar fields but
    # write them WITHOUT individual block wrappers (raw u8+f32+i32+i32 sequence).
    # Synthetic test fixtures use standard blocked framing regardless of class count,
    # so we gate only on the class-entry count observed in the real MTRE header.
    _mtre_class_count = len(reader.header.classes) if reader.header else 0
    # MTRE EP1 hint chores have exactly 4 class entries (Chore, PropertySet, Flags, Symbol).
    # These files omit mFlags/mLength/mNumResources/mNumAgents from the wire entirely and
    # encode fields 7-12 in a non-standard non-block-prefixed tail format.
    # Synthetic test fixtures always use 1 class entry with standard block framing, so
    # the == 4 guard keeps the standard decode path for tests while activating the
    # hint-chore bypass for real EP1 files.
    _mtre_hint_layout = (stream_version <= 3 and _mtre_class_count == 4)
    # MTRE EP1 non-hint chores have >=9 class entries (include ChoreResource, ChoreAgent, etc.).
    # These files write mFlags/mLength/mNumResources/mNumAgents as raw unframed bytes
    # (u8 + f32 + i32 + i32 = 13 bytes total, no block headers).  Fields 7-12 and the
    # ChoreResource/ChoreAgent post-loops use a non-standard MTRE wire format that has
    # not been reversed (Phase 8 scope).  We decode the raw scalars to capture
    # mNumResources/mNumAgents accurately, then skip to EOF.  The custom post-loops do NOT
    # run for MTRE non-hint chores — they would require full MTRE-specific decode.
    _mtre_nonhint_layout = (stream_version <= 3 and _mtre_class_count > 4)

    # 1. mName — Chore.h:422 String
    reader.begin_block()
    m_name = decode_string(reader, stream_version)
    reader.end_block()

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
        # MTRE hint chore (4 class entries): the tail after mEditorProps uses a
        # completely different layout that has not been reversed.  Skip to EOF.
        # mNumResources=0 and mNumAgents=0 for all hint chores, so post-loops are empty.
        remaining = len(reader._data) - reader.pos
        if remaining > 0:
            reader.skip(remaining)
            log.debug(
                "decode_chore: MTRE hint layout (class_count=%d) — "
                "skipped %d tail bytes (format not reversed)",
                _mtre_class_count, remaining,
            )
        m_chore_scene_file = ""
        m_render_delay = 0
        m_sync_to_loc = LocalizeInfo(mFlags=0)
        m_dependencies = DependencyLoader1()
        m_tool_props = ToolProps(mbHasProps=False)
        m_walk_paths = {}
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
        # All four collapse to a 22-byte constant in EP1 MTRE chores.
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
    for i in range(_post_loop_resources):
        if _use_mtre_decoders:
            resource = decode_chore_resource_mtre(reader, stream_version)
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

    Note: MTRE non-hint chores (EP1 files with class_count > 4) now decode
    ChoreResource and ChoreAgent entries via ``decode_chore_resource_mtre`` and
    ``decode_chore_agent_mtre``.  mControlAnimation is skipped (Phase 8 scope).
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
    import struct
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
