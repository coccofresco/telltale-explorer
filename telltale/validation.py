"""
Validation reporting types for the Telltale Explorer decoder pipeline.

This module is intentionally dependency-free: it must not import from
``telltale.metastream`` or any other ``telltale.*`` module, so that the
Phase 5/6/8 validation harnesses (which will import ``ChoreValidationReport``
from here) cannot introduce a circular import with the MetaStream reader.

The primary export is :class:`ChoreValidationReport`, a minimal
accounting dataclass with two mutation helpers and a one-line ``summary()``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

log = logging.getLogger(__name__)


@dataclass
class ChoreValidationReport:
    """Running tally of a decoder-progressive validation pass.

    Attributes
    ----------
    files_total : int
        Number of files the harness attempted to parse.
    files_clean : int
        Number of files that parsed with zero byte-misalignment.
    misalignments : list[dict]
        One dict per failing file, with keys ``file``, ``offset``,
        ``expected``, ``actual``, ``message``.
    """

    files_total: int = 0
    files_clean: int = 0
    misalignments: List[Dict[str, Any]] = field(default_factory=list)

    def record_clean(self, file: str) -> None:
        """Record a cleanly-parsed file.  Increments both counters."""
        self.files_total += 1
        self.files_clean += 1

    def record_misalignment(
        self,
        file: str,
        offset: int,
        expected: int,
        actual: int,
        message: str,
    ) -> None:
        """Record a byte-misaligned file.  Increments ``files_total`` only."""
        self.files_total += 1
        self.misalignments.append(
            {
                "file": file,
                "offset": offset,
                "expected": expected,
                "actual": actual,
                "message": message,
            }
        )

    def summary(self) -> str:
        """Return a one-line human summary.

        Format: ``"{files_clean}/{files_total} clean ({N} misaligned)"``.
        """
        return (
            f"{self.files_clean}/{self.files_total} clean "
            f"({len(self.misalignments)} misaligned)"
        )
