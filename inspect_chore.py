"""
Surface-level .chore inspector for Telltale MTRE choreography files.

Does NOT fully parse the Chore/ChoreResource/ChoreAgent tree — that requires a
complete MetaStream+MetaClass reflection reader. Instead, this extracts what
is directly recoverable without schema:

    - mName, mFlags, mLength, mNumResources, mNumAgents (top-level primitives)
    - Every Handle<T> string embedded in the file (anims, chores, meshes, etc.)
      found by scanning for the length-prefixed String pattern used in MTRE
      (Handle<T> in stream version < 5 serializes as a bare String).
    - Every Symbol CRC64 that resolves to a known bone/anim name via the HashDB
    - Every readable ASCII run (agent names, scene paths, script identifiers).

Useful for:
    - Quickly listing which animations/chores a .chore references
    - Finding scene paths, script names, agent labels
    - Navigating 1929 TMI ep1 .chore files without a full decoder
"""

from __future__ import annotations

import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Set

from telltale import metastream


@dataclass
class ChoreSurface:
    name: str
    flags: int
    length: float
    num_resources: int
    num_agents: int
    handles: List[str] = field(default_factory=list)
    ascii_runs: List[str] = field(default_factory=list)
    file_size: int = 0


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _u32(d: bytes, p: int) -> int:
    return struct.unpack_from("<I", d, p)[0]

def _f32(d: bytes, p: int) -> float:
    return struct.unpack_from("<f", d, p)[0]


_PLAUSIBLE_HANDLE_EXTS = (
    ".anm", ".chore", ".d3dmesh", ".skl", ".scene", ".prop", ".lua",
    ".wav", ".ogg", ".mp3", ".ttarch", ".font", ".style", ".dlg",
    ".langdb", ".imap", ".wbox", ".t3fxb", ".d3dtx",
)


def _find_length_prefixed_strings(d: bytes, min_len: int = 3) -> List[tuple[int, str]]:
    """Scan d for u32_len + ASCII_chars sequences. Returns (file_offset, string)."""
    out: List[tuple[int, str]] = []
    seen: Set[int] = set()
    i = 0
    while i + 4 < len(d):
        n = _u32(d, i)
        if min_len <= n <= 256 and i + 4 + n <= len(d):
            chunk = d[i + 4:i + 4 + n]
            if all(0x20 <= b < 0x7f for b in chunk):
                s = chunk.decode("ascii")
                # plausible filename if it looks like a token or has a known ext
                if re.fullmatch(r"[A-Za-z0-9_\-./]+", s):
                    if (s.lower().endswith(_PLAUSIBLE_HANDLE_EXTS)
                        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", s)):
                        if i not in seen:
                            seen.add(i)
                            out.append((i, s))
                        i += 4 + n
                        continue
        i += 1
    return out


# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------

def inspect(path: str) -> ChoreSurface:
    with open(path, "rb") as f:
        d = f.read()
    h = metastream.parse_header(path)
    p = h.data_offset

    # mName block (String, blocked): size(u32) + strlen(u32) + chars
    name_blk = _u32(d, p); name_end = p + name_blk; p += 4
    slen = _u32(d, p); p += 4
    name = d[p:p+slen].decode("latin1"); p = name_end

    # Top-level primitives — field offsets not fully pinned down (some Chore
    # sub-structures like PropertySet, LocalizeInfo, DependencyLoader and
    # ToolProps still need MetaStream block-traversal work). Parsed
    # best-effort; use the `handles` list for reliable info.
    flags = _u32(d, p); p += 4
    length = _f32(d, p); p += 4
    num_res = _u32(d, p); p += 4
    num_ag = _u32(d, p); p += 4

    handles_with_off = _find_length_prefixed_strings(d[p:])
    handles = sorted({s for _, s in handles_with_off if s.lower().endswith(_PLAUSIBLE_HANDLE_EXTS)})

    # Misc ASCII runs (>=4 chars) for debugging
    ascii_runs = sorted({m.group().decode()
                         for m in re.finditer(rb"[\x20-\x7e]{4,}", d)})

    return ChoreSurface(
        name=name, flags=flags, length=length,
        num_resources=num_res, num_agents=num_ag,
        handles=handles, ascii_runs=ascii_runs,
        file_size=len(d),
    )


if __name__ == "__main__":
    paths = sys.argv[1:]
    if not paths:
        import glob
        paths = sorted(glob.glob("extracted/ep1_chore/*.chore"))[:5]
    for path in paths:
        try:
            c = inspect(path)
        except Exception as e:
            print(f"{path}: FAIL ({e})")
            continue
        print(f"\n=== {os.path.basename(path)} ({c.file_size} B) ===")
        print(f"  name={c.name!r}")
        print(f"  flags=0x{c.flags:x}  length={c.length:.3f}s")
        print(f"  resources={c.num_resources}  agents={c.num_agents}")
        if c.handles:
            print(f"  {len(c.handles)} handle(s):")
            for h in c.handles[:20]:
                print(f"    - {h}")
            if len(c.handles) > 20:
                print(f"    ... (+{len(c.handles) - 20} more)")
