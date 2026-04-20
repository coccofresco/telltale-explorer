"""
PhonemeTable-related @meta_class dataclasses + decoders.

Registers PhonemeTable::PhonemeEntry + AnimOrChore with the Phase 2 registry
so telltale.meta_containers.dispatch_container can decode
Map<Symbol, PhonemeTable::PhonemeEntry> for every ep1 `.ptable` file.

This module is the first dataclass-shaped Phase 4 consumer; Phase 6
follows the same pattern for WalkPath / ChoreResource::Block / etc.

TTL canonical names (verified by CRC64 against ep1 ptable headers):

    AnimOrChore              -> 0xa5b4e0529a022754  (in header)
    PhonemeTable::PhonemeEntry -> 0x998e73c393f6a122  (in header)

Sources:
    TelltaleToolLib/ToolLibrary/Types/AnimOrChore.h  (standalone struct)
    TelltaleToolLib/ToolLibrary/Types/PhonemeTable.h (nested struct PhonemeTable::PhonemeEntry)

Byte layout (from parse_ptable.py lines 85-113 - empirically verified
on all 74 ep1 `.ptable` files, 888 entries):

    AnimOrChore (blocked as a whole):
        [u32 outer_block_size]
        mhAnim (Handle<Animation>)  [u32 block_size][String bytes]
        mhChore (Handle<Chore>)     [u32 block_size][String bytes]

    PhonemeTable::PhonemeEntry (NOT blocked as a whole - members walked inline):
        AnimOrChore mAnimation  (per above, outer block included)
        float mContributionScalar   (raw f32, NOT blocked; always 0.0 in EP1 MTRE;
                                     mTimeScalar is absent on the EP1 wire - only 1 float)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from telltale.metaclass import meta_class, meta_member
from telltale.meta_intrinsics import register
from telltale.meta_handle import Handle, decode_handle
from telltale.metastream import MetaStreamReader

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AnimOrChore dataclass
# ---------------------------------------------------------------------------

@meta_class("AnimOrChore")
@dataclass
class AnimOrChore:
    """Standalone struct from AnimOrChore.h: two Handles, both block-wrapped.

    TTL name: "AnimOrChore"  CRC64: 0xa5b4e0529a022754
    """
    mhAnim: Optional[Handle] = meta_member("mhAnim", Handle)
    mhChore: Optional[Handle] = meta_member("mhChore", Handle)


# ---------------------------------------------------------------------------
# PhonemeTable::PhonemeEntry dataclass
# ---------------------------------------------------------------------------
# NOTE: The TTL class name includes the scope operator (::) because nested
# C++ structs serialise under their fully-qualified stripped name.
# Verified: crc64_str("PhonemeTable::PhonemeEntry") == 0x998e73c393f6a122
# which matches byte 3 of the ep1 ptable header class list.

@meta_class("PhonemeTable::PhonemeEntry")
@dataclass
class PhonemeEntry:
    """PhonemeTable::PhonemeEntry from PhonemeTable.h.

    TTL name: "PhonemeTable::PhonemeEntry"  CRC64: 0x998e73c393f6a122

    Wire layout in EP1 MTRE (stream_version=3):
        AnimOrChore mAnimation  (blocked)
        float mContributionScalar   (raw f32, NOT blocked; always 0.0)

    Note: PhonemeTable.h declares a second float mTimeScalar, but EP1
    MTRE only serialises ONE float on the wire.  parse_ptable.py confirms
    this empirically across all 888 entries in 74 files.
    """
    mAnimation: Optional[AnimOrChore] = meta_member("mAnimation", AnimOrChore)
    mExtra: float = meta_member("mContributionScalar", float)


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def decode_anim_or_chore(
    reader: MetaStreamReader,
    stream_version: int,
) -> AnimOrChore:
    """Decode the AnimOrChore struct with its outer block + two blocked Handles.

    Frame (matches parse_ptable.py lines 86-104 exactly):
        [u32 outer_block_size]
          [u32 h1_block_size][Handle<Animation> payload]
          [u32 h2_block_size][Handle<Chore> payload]
        <end of outer block>
    """
    reader.begin_block()    # AnimOrChore outer block
    reader.begin_block()    # mhAnim Handle block
    mhAnim = decode_handle(reader, stream_version)
    reader.end_block()
    reader.begin_block()    # mhChore Handle block
    mhChore = decode_handle(reader, stream_version)
    reader.end_block()
    reader.end_block()      # closes AnimOrChore outer block
    return AnimOrChore(mhAnim=mhAnim, mhChore=mhChore)


def decode_phoneme_entry(
    reader: MetaStreamReader,
    stream_version: int,
) -> PhonemeEntry:
    """Decode a PhonemeTable::PhonemeEntry: AnimOrChore substruct + trailing f32.

    The PhonemeEntry itself is NOT block-wrapped -- its members are walked
    inline. AnimOrChore IS blocked (by decode_anim_or_chore). The trailing
    f32 is raw 4 bytes, no block prefix. See parse_ptable.py lines 106-107.
    """
    mAnimation = decode_anim_or_chore(reader, stream_version)
    mExtra = reader.read_float32()
    return PhonemeEntry(mAnimation=mAnimation, mExtra=mExtra)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register_ptable_decoders() -> None:
    """Idempotent registration of PhonemeTable::PhonemeEntry + AnimOrChore decoders.

    @meta_class has already inserted both dataclasses into _REGISTRY with
    dataclass_cls set; here we only populate _DECODERS (decoder_only=True),
    the same pattern as telltale.meta_math.register_math_types.
    """
    register("AnimOrChore", decode_anim_or_chore, decoder_only=True)
    register("PhonemeTable::PhonemeEntry", decode_phoneme_entry, decoder_only=True)
    log.debug("registered decoders for AnimOrChore + PhonemeTable::PhonemeEntry")


_register_ptable_decoders()
