"""
Surface-level .chore inspector for Telltale MTRE choreography files.

Rewritten in Phase 8 (Plan 08-03) to use the full telltale.chore.parse_chore
decoder + extract_handles instead of hand-rolled length-prefix string scanning.

Extracts:
    - mName, mFlags, mLength, mNumResources, mNumAgents (top-level primitives,
      now sourced from the fully decoded Chore dataclass)
    - Every Handle<T> string embedded in the file, filtered by known asset
      extensions (_PLAUSIBLE_HANDLE_EXTS), sorted and deduplicated
    - Every readable ASCII run (agent names, scene paths, script identifiers)

Useful for:
    - Quickly listing which animations/chores a .chore references
    - Finding scene paths, script names, agent labels
    - Navigating 1929 TMI ep1 .chore files without a full decoder
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from typing import List


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
# Constants
# ------------------------------------------------------------

_PLAUSIBLE_HANDLE_EXTS = (
    ".anm", ".chore", ".d3dmesh", ".skl", ".scene", ".prop", ".lua",
    ".wav", ".ogg", ".mp3", ".ttarch", ".font", ".style", ".dlg",
    ".langdb", ".imap", ".wbox", ".t3fxb", ".d3dtx",
)


# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------

def inspect(path: str) -> ChoreSurface:
    from telltale.chore import parse_chore, extract_handles

    with open(path, "rb") as f:
        d = f.read()
    file_size = len(d)

    chore = parse_chore(path)

    handles = sorted({
        h for h in extract_handles(chore, path)
        if h.lower().endswith(_PLAUSIBLE_HANDLE_EXTS)
    })

    ascii_runs = sorted({
        m.group().decode()
        for m in re.finditer(rb"[\x20-\x7e]{4,}", d)
    })

    return ChoreSurface(
        name=chore.mName,
        flags=chore.mFlags,
        length=chore.mLength,
        num_resources=chore.mNumResources,
        num_agents=chore.mNumAgents,
        handles=handles,
        ascii_runs=ascii_runs,
        file_size=file_size,
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
