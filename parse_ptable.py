"""
PhonemeTable (.ptable) decoder for Telltale games (MTRE era).

Decodes the MetaStream v3 (MTRE) PhonemeTable container:

    PhonemeTable {
        String mName;                          (blocked)
        Map<Symbol, PhonemeEntry> mAnimations; (blocked)
    }
    PhonemeEntry {
        AnimOrChore mAnimation {               (blocked)
            Handle<Animation> mhAnim;          (blocked, serialized as String in MTRE)
            Handle<Chore>     mhChore;         (blocked, serialized as String in MTRE)
        }
        float mExtra;   // always 0.0f in Tales of Monkey Island - not blocked
    }

Verified on all 74 ep1 ptable files (888 entries, 100% CRC-matched keys).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List

from telltale import metastream


def _u32(d: bytes, p: int) -> int: return struct.unpack_from("<I", d, p)[0]
def _u64(d: bytes, p: int) -> int: return struct.unpack_from("<Q", d, p)[0]
def _f32(d: bytes, p: int) -> float: return struct.unpack_from("<f", d, p)[0]


@dataclass
class PhonemeEntry:
    phoneme_id: int    # u64 CRC64 of the phoneme base name (e.g. crc64("aa"))
    anim_name: str     # name of the .anm file played for this phoneme
    chore_name: str    # name of the .chore file (empty for every ep1 ptable)
    extra: float       # always 0.0 in Tales of Monkey Island


@dataclass
class PhonemeTable:
    name: str
    entries: List[PhonemeEntry]


def _read_handle_string(d: bytes, p: int) -> tuple[str, int]:
    """Handle<T> in MTRE (stream version < 5) serializes as a String.

    Returns the decoded string and the position of the 4-byte strlen field's end.
    """
    slen = _u32(d, p); p += 4
    s = d[p:p+slen].decode("latin1")
    return s, p + slen


def parse_ptable(path: str) -> PhonemeTable:
    """Parse a .ptable file and return (name, list of PhonemeEntry)."""
    with open(path, "rb") as f:
        d = f.read()
    h = metastream.parse_header(path)
    p = h.data_offset

    # mName block
    name_blk_sz = _u32(d, p); name_end = p + name_blk_sz; p += 4
    name, p = _read_handle_string(d, p)
    p = name_end

    # mAnimations (Map) block
    map_blk_start = p
    map_blk_sz = _u32(d, p); p += 4
    map_end = map_blk_start + map_blk_sz

    num = _u32(d, p); p += 4
    entries: List[PhonemeEntry] = []
    for _ in range(num):
        # Symbol key: u64 CRC + u32 empty-debug-string length (MTRE)
        sym = _u64(d, p); p += 8
        dbg_len = _u32(d, p); p += 4
        if dbg_len != 0:
            raise ValueError(f"unexpected debug strlen {dbg_len} in Symbol at {p-4:#x}")

        # PhonemeEntry (members walked; no outer block)
        #   mAnimation (AnimOrChore) -- blocked
        mAnim_start = p
        mAnim_sz = _u32(d, p); p += 4
        mAnim_end = mAnim_start + mAnim_sz

        #     mhAnim (Handle<Animation>) -- blocked, String in MTRE
        mhA_start = p
        mhA_sz = _u32(d, p); p += 4
        anim_name, p = _read_handle_string(d, p)
        p = mhA_start + mhA_sz

        #     mhChore (Handle<Chore>) -- blocked, String in MTRE (empty for ep1)
        mhC_start = p
        mhC_sz = _u32(d, p); p += 4
        chore_name, p = _read_handle_string(d, p)
        p = mhC_start + mhC_sz

        if p != mAnim_end:
            raise ValueError(f"AnimOrChore block misalignment: {p:#x} != {mAnim_end:#x}")

        #   trailing float (mContributionScalar or mTimeScalar; always 0.0 in TMI)
        extra = _f32(d, p); p += 4

        entries.append(PhonemeEntry(sym, anim_name, chore_name, extra))

    if p != map_end:
        raise ValueError(f"Map block misalignment: {p:#x} != {map_end:#x}")

    return PhonemeTable(name=name, entries=entries)


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        pt = parse_ptable(path)
        print(f"{pt.name}  ({len(pt.entries)} entries)")
        for e in pt.entries:
            print(f"  0x{e.phoneme_id:016x}  {e.anim_name}")
