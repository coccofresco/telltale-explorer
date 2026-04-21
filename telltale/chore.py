"""Public API for Telltale choreography (.chore) decoding.

This module is the canonical entry point for users of the Telltale Explorer
library.  It re-exports the full decoder contract from telltale.meta_chore,
which is the internal implementation module.

Typical usage:

    from telltale.chore import parse_chore, extract_handles

    chore = parse_chore("path/to/file.chore")
    print(chore.mName, len(chore.resources), len(chore.agents))
    for h in extract_handles(chore):
        print(h)

Public names
------------
parse_chore(path)      — entry point; accepts str or pathlib.Path.
extract_handles(chore) — returns every Handle<T>-embedded string in the decoded
                         Chore.  Pass the source path as a second argument to
                         activate the raw-scan supplement and guarantee a
                         superset of inspect_chore v1.1 handle coverage.
Chore                  — dataclass for the top-level choreography struct
                         (12 fields + resources + agents).
ChoreResource          — dataclass per entry in Chore.resources.
ChoreAgent             — dataclass per entry in Chore.agents.
validate_chores        — corpus harness (optional public surface; useful for
                         downstream tooling and CI).

Schema authority
----------------
The decoder's field-walk order matches Chore::MetaOperation_Serialize in the
Tales of Monkey Island iOS binary (VA 0x00205788 — see docs/CHORE_DISASM.md).
Where TelltaleToolLib disagrees with the iOS binary, iOS wins.

For the full on-disk schema see docs/FORMAT_CHOREOGRAPHY.md.

Stability guarantee
-------------------
This module's public names (listed in ``__all__``) form a stable API surface.
Internal module organisation (telltale.meta_chore, telltale.meta_chore_leaves,
etc.) may evolve without notice — import only from telltale.chore.
"""
from __future__ import annotations

from telltale.meta_chore import (
    parse_chore,
    extract_handles,
    validate_chores,
    Chore,
    ChoreResource,
    ChoreAgent,
)

__all__ = [
    "parse_chore",
    "extract_handles",
    "validate_chores",
    "Chore",
    "ChoreResource",
    "ChoreAgent",
]
