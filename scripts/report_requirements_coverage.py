#!/usr/bin/env python3
import argparse
from pathlib import Path

from check_requirements_guard import (
    ROOT,
    REQUIREMENTS_PATH,
    TRACEABILITY_PATH,
    _load_requirement_ids,
    _load_traceability,
)


def _filter_ids(ids: set[str], prefix: str | None) -> set[str]:
    if not prefix:
        return set(ids)
    return {req_id for req_id in ids if req_id.startswith(prefix)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report requirement coverage from .github/requirements_traceability.yaml, "
            "with emphasis on integration coverage."
        )
    )
    parser.add_argument(
        "--prefix",
        help="Optional requirement ID prefix filter, for example REQ-WSP or REQ-ADM.",
    )
    args = parser.parse_args()

    requirement_ids = _filter_ids(_load_requirement_ids(), args.prefix)
    traceability = _load_traceability()

    integration_covered = set()
    unit_covered = set()
    any_covered = set()
    tracked = set()

    for req_id in sorted(requirement_ids):
        entry = traceability.get(req_id, {})
        integration_refs = list(entry.get("integration_tests", []))
        legacy_refs = [
            ref for ref in entry.get("tests", [])
            if ref.startswith("tests/integration/")
        ]
        unit_refs = list(entry.get("unit_tests", []))
        legacy_unit_refs = [
            ref for ref in entry.get("tests", [])
            if ref.startswith("tests/unit/")
        ]

        if req_id in traceability:
            tracked.add(req_id)
        if integration_refs or legacy_refs:
            integration_covered.add(req_id)
            any_covered.add(req_id)
        if unit_refs or legacy_unit_refs:
            unit_covered.add(req_id)
            any_covered.add(req_id)

    total = len(requirement_ids)
    if total == 0:
        print("No matching requirements.")
        return 0

    def pct(count: int) -> float:
        return (100.0 * count / total) if total else 0.0

    integration_uncovered = sorted(requirement_ids - integration_covered)
    untracked = sorted(requirement_ids - tracked)

    print(f"Requirements file: {Path(ROOT / REQUIREMENTS_PATH)}")
    print(f"Traceability file: {Path(ROOT / TRACEABILITY_PATH)}")
    if args.prefix:
        print(f"Filter: {args.prefix}")
    print(f"Total requirements: {total}")
    print(
        f"Integration-covered: {len(integration_covered)}/{total} = {pct(len(integration_covered)):.1f}%"
    )
    print(f"Unit-covered: {len(unit_covered)}/{total} = {pct(len(unit_covered)):.1f}%")
    print(f"Any-test-covered: {len(any_covered)}/{total} = {pct(len(any_covered)):.1f}%")
    print(f"Tracked in manifest: {len(tracked)}/{total} = {pct(len(tracked)):.1f}%")
    print()
    print("Integration-covered requirement IDs:")
    print(", ".join(sorted(integration_covered)) if integration_covered else "(none)")
    print()
    print("Requirements without integration coverage:")
    print(", ".join(integration_uncovered) if integration_uncovered else "(none)")
    print()
    print("Requirements missing from traceability manifest:")
    print(", ".join(untracked) if untracked else "(none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
