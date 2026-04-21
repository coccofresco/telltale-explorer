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

Rewired (Phase 8 / INFRA-05) to run on top of
telltale.metastream.MetaStreamReader + the Phase 4 meta_ptable registered
decoder chain.  Public API (signature, dataclass types, field names) is
unchanged from the v1.1 implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from telltale import metastream
from telltale.metastream import MetaStreamReader
from telltale.meta_intrinsics import decode_symbol
import telltale.meta_ptable as _meta_ptable  # noqa: F401 — force registration
from telltale.meta_ptable import decode_phoneme_entry


# Map header.version strings to the effective stream version integer
# used for container-level decoder branching (MTRE Symbol-key debug-strlen).
_VERSION_TO_SV: dict[str, int] = {
    "MBIN": 2,
    "MTRE": 3,
    "MSV5": 5,
    "MSV6": 6,
}


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
    """Compatibility shim retained for test_meta_handle.py parity tests.

    Reads a u32-length-prefixed latin1 string from raw bytes *d* at offset
    *p*.  Returns (decoded_str, end_position).  This function is never called
    from parse_ptable itself — it is preserved solely for tests that compare
    their output against this reference decoder.
    """
    slen = int.from_bytes(d[p:p + 4], "little")
    p += 4
    s = d[p:p + slen].decode("latin1")
    return s, p + slen


def parse_ptable(path: str) -> PhonemeTable:
    """Parse a .ptable file and return (name, list of PhonemeEntry).

    Reads all file bytes exclusively via telltale.metastream.MetaStreamReader
    primitives (read_uint32, read_uint64, read_bytes, read_float32) and
    block-stack operations (begin_block / end_block).  The inner PhonemeEntry
    members are decoded by telltale.meta_ptable.decode_phoneme_entry which is
    already validated on all 74 EP1 ptables by Phase 4.
    """
    with open(path, "rb") as f:
        data = f.read()

    header = metastream.parse_header(data)
    sv = _VERSION_TO_SV.get(header.version, 3)
    reader = MetaStreamReader(data, header=header, debug=False)

    # mName block: [u32 block_size][u32 slen][slen bytes latin1]
    reader.begin_block()
    slen = reader.read_uint32()
    name = reader.read_bytes(slen).decode("latin1")
    reader.end_block()

    # mAnimations block: [u32 block_size][u32 count][count * (Symbol, PhonemeEntry)]
    # Symbol key in MTRE: u64 CRC + u32 empty-debug-string length
    reader.begin_block()
    num = reader.read_uint32()
    entries: List[PhonemeEntry] = []
    for _ in range(num):
        sym = decode_symbol(reader, sv, include_mtre_debug_strlen=(sv <= 4))
        pe = decode_phoneme_entry(reader, sv)
        anim_name = (
            pe.mAnimation.mhAnim.object_name_str
            if pe.mAnimation and pe.mAnimation.mhAnim
            else ""
        )
        chore_name = (
            pe.mAnimation.mhChore.object_name_str
            if pe.mAnimation and pe.mAnimation.mhChore
            else ""
        )
        entries.append(PhonemeEntry(
            phoneme_id=sym,
            anim_name=anim_name or "",
            chore_name=chore_name or "",
            extra=pe.mExtra,
        ))
    reader.end_block()

    return PhonemeTable(name=name, entries=entries)


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        pt = parse_ptable(path)
        print(f"{pt.name}  ({len(pt.entries)} entries)")
        for e in pt.entries:
            print(f"  0x{e.phoneme_id:016x}  {e.anim_name}")
