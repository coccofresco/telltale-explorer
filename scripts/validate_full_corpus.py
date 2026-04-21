#!/usr/bin/env python3
"""Phase 8 full-corpus validation CLI.

Runs parse_chore over every .chore under extracted/ep1_chore/, populates a
ChoreValidationReport, and compares decoded handles per file against v1.1
inspect_chore.inspect() output (VALIDATE-04 + VALIDATE-05).

Usage:
    python scripts/validate_full_corpus.py                    # default glob
    python scripts/validate_full_corpus.py path1.chore ...    # specific files
    python scripts/validate_full_corpus.py --verbose          # per-file details
    python scripts/validate_full_corpus.py --residual-report  # categorise failures

Exit 0 iff files_clean == files_total AND handle-superset holds everywhere.
"""
import argparse
import glob
import os
import sys
from collections import defaultdict

from telltale.meta_chore import parse_chore, validate_chores, extract_handles
from inspect_chore import inspect as v1_inspect, _PLAUSIBLE_HANDLE_EXTS


def _misalignment_file(m) -> str:
    """Return the file path from a misalignment entry.

    validate_chores stores misalignments as (path, message) tuples.
    """
    if isinstance(m, dict):
        return m.get("file", "")
    # tuple: (path, message)
    return m[0]


def _misalignment_message(m) -> str:
    """Return the message string from a misalignment entry."""
    if isinstance(m, dict):
        return m.get("message", "")
    return m[1]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Phase 8 full-corpus validation (VALIDATE-04 + VALIDATE-05)",
    )
    ap.add_argument("paths", nargs="*", help="Specific .chore files to validate")
    ap.add_argument("--verbose", action="store_true", help="Print per-file details")
    ap.add_argument(
        "--residual-report", action="store_true",
        help="Categorise and print failure buckets",
    )
    ap.add_argument(
        "--glob", default="extracted/ep1_chore/*.chore",
        help="Glob pattern when no explicit paths given",
    )
    args = ap.parse_args()

    paths = sorted(args.paths or glob.glob(args.glob))
    if not paths:
        print(f"no .chore files found (glob={args.glob!r})", file=sys.stderr)
        return 2

    # ----------------------------------------------------------------
    # PASS 1: parse + record alignment (VALIDATE-04)
    # ----------------------------------------------------------------
    report = validate_chores(paths)
    print(f"VALIDATE-04: {report.summary()}")

    parse_failures: set[str] = {_misalignment_file(m) for m in report.misalignments}

    # ----------------------------------------------------------------
    # PASS 2: handle-graph superset check per cleanly-parsed file (VALIDATE-05)
    # ----------------------------------------------------------------
    superset_failures: list[tuple[str, set[str]]] = []
    for path in paths:
        if path in parse_failures:
            continue
        try:
            chore = parse_chore(path)
            new_handles = {
                h for h in extract_handles(chore, path=path)
                if h.lower().endswith(_PLAUSIBLE_HANDLE_EXTS)
            }
            v1_handles = set(v1_inspect(path).handles)
            missing = v1_handles - new_handles
            if missing:
                superset_failures.append((path, missing))
        except Exception as e:
            # Shouldn't happen post-report, but log defensively
            superset_failures.append((path, {f"EXC:{e}"}))

    clean_count = len(paths) - len(parse_failures)
    superset_ok = len(superset_failures) == 0
    print(
        f"VALIDATE-05: {len(superset_failures)}/{clean_count} "
        f"handle-superset failures"
    )

    # ----------------------------------------------------------------
    # Residual category report (--residual-report)
    # ----------------------------------------------------------------
    if args.residual_report and report.misalignments:
        print("\n--- Parse-failure breakdown ---")
        buckets: dict[str, list[str]] = defaultdict(list)
        for m in report.misalignments:
            key = _misalignment_message(m).split(":", 1)[0]
            buckets[key].append(_misalignment_file(m))
        for key, files in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            print(f"  [{len(files)}x] {key}")
            for f in files[:3]:
                print(f"      - {os.path.basename(f)}")
            if len(files) > 3:
                print(f"      ... +{len(files) - 3} more")

    if args.verbose and superset_failures:
        print("\n--- Superset failures (first 10) ---")
        for path, missing in superset_failures[:10]:
            print(
                f"  superset-miss {os.path.basename(path)}: "
                f"{sorted(missing)[:5]}"
            )

    ok = len(report.misalignments) == 0 and superset_ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
