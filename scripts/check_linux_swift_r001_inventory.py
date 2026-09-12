#!/usr/bin/env python3
"""Validate and report the LSW-R001 Python-to-Linux-Swift parity baseline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs/LinuxSwift_r001_inventory.json"
REQUIREMENTS_PATH = ROOT / "docs/REQUIREMENTS.md"
REQ_RE = re.compile(r"`(REQ-[A-Z]+-\d+)`")
TEST_DEF_RE = re.compile(
    r"^\s*(?:(?:async\s+)?def|(?:@Test\s+)?func)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def requirement_ids() -> set[str]:
    return set(REQ_RE.findall(REQUIREMENTS_PATH.read_text(encoding="utf-8")))


def test_exists(reference: str) -> str | None:
    if "::" not in reference:
        return f"invalid test reference {reference!r}"
    rel_path, name = reference.split("::", 1)
    path = ROOT / rel_path
    if not path.is_file():
        return f"missing test file {rel_path}"
    definitions = set(TEST_DEF_RE.findall(path.read_text(encoding="utf-8")))
    if name not in definitions:
        return f"missing test {name} in {rel_path}"
    return None


def implementation_exists(reference: str) -> str | None:
    path = ROOT / reference.split("::", 1)[0]
    if not path.exists():
        return f"missing implementation path {reference}"
    return None


def inventory_source_files(inventory: dict[str, object]) -> set[str]:
    return {
        file
        for group in inventory["source_ownership"]
        for file in group["files"]
    }


def repository_source_files(inventory: dict[str, object]) -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for root in inventory["source_roots"]
        for path in (ROOT / root).glob("*.swift")
    }


def validate(inventory: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if inventory.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if inventory.get("reference_product") != "python":
        errors.append("reference_product must be python")
    for blocker in inventory.get("baseline_blockers", []):
        if blocker.get("status") not in {"failing", "blocked", "qualified-host-pending"}:
            errors.append(f"invalid baseline blocker status {blocker.get('status')!r}")
        if not blocker.get("lane") or not blocker.get("detail"):
            errors.append("baseline blockers require lane and detail")

    mapped_sources = inventory_source_files(inventory)
    actual_sources = repository_source_files(inventory)
    duplicates = Counter(
        file for group in inventory["source_ownership"] for file in group["files"]
    )
    for file, count in sorted(duplicates.items()):
        if count != 1:
            errors.append(f"source ownership must be unique: {file} appears {count} times")
    for file in sorted(actual_sources - mapped_sources):
        errors.append(f"unmapped Swift source: {file}")
    for file in sorted(mapped_sources - actual_sources):
        errors.append(f"inventory names missing Swift source: {file}")

    expected_requirements = requirement_ids()
    mapped_requirements: list[str] = []
    for feature in inventory["feature_groups"]:
        feature_id = feature.get("id", "<unnamed>")
        mapped_requirements.extend(feature.get("requirements", []))
        linux = feature.get("linux_swift", {})
        applicability = linux.get("applicability")
        status = linux.get("status")
        if applicability not in {"required", "not-applicable"}:
            errors.append(f"{feature_id}: invalid Linux applicability {applicability!r}")
        if status not in {"verified", "partial", "missing", "failing", "not-applicable"}:
            errors.append(f"{feature_id}: invalid Linux status {status!r}")
        if applicability == "required" and status == "not-applicable":
            errors.append(f"{feature_id}: required Linux feature cannot be not-applicable")
        if applicability == "not-applicable" and status != "not-applicable":
            errors.append(f"{feature_id}: not-applicable feature must have not-applicable status")
        if applicability == "not-applicable" and not linux.get("reason"):
            errors.append(f"{feature_id}: not-applicable feature needs a product-scope reason")
        for key in ("python_implementations", "swift_implementations"):
            for reference in feature.get(key, []):
                issue = implementation_exists(reference)
                if issue:
                    errors.append(f"{feature_id}: {issue}")
        for key in ("python_tests", "swift_tests", "parity_tests"):
            for reference in feature.get(key, []):
                issue = test_exists(reference)
                if issue:
                    errors.append(f"{feature_id}: {issue}")
        if applicability == "required":
            if not feature.get("python_implementations"):
                errors.append(f"{feature_id}: required feature lacks Python implementation evidence")
            if not feature.get("swift_implementations"):
                errors.append(f"{feature_id}: required feature lacks Swift implementation evidence")
            if not feature.get("python_tests"):
                errors.append(f"{feature_id}: required feature lacks Python test evidence")

    duplicate_requirements = Counter(mapped_requirements)
    for req_id, count in sorted(duplicate_requirements.items()):
        if count != 1:
            errors.append(f"requirement ownership must be unique: {req_id} appears {count} times")
    for req_id in sorted(expected_requirements - set(mapped_requirements)):
        errors.append(f"unmapped requirement: {req_id}")
    for req_id in sorted(set(mapped_requirements) - expected_requirements):
        errors.append(f"inventory names unknown requirement: {req_id}")
    return errors


def report(inventory: dict[str, object]) -> None:
    print("LSW-R001 Linux Swift parity baseline")
    print("requirement | applicability | status | feature group")
    for feature in inventory["feature_groups"]:
        linux = feature["linux_swift"]
        for req_id in feature["requirements"]:
            print(f"{req_id} | {linux['applicability']} | {linux['status']} | {feature['id']}")
    for blocker in inventory.get("baseline_blockers", []):
        print(f"baseline | {blocker['status']} | {blocker['lane']} | {blocker['detail']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="Print one Linux Swift row per requirement.")
    args = parser.parse_args()
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    errors = validate(inventory)
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    if args.report:
        report(inventory)
    else:
        statuses = Counter(feature["linux_swift"]["status"] for feature in inventory["feature_groups"])
        print(
            "LSW-R001 inventory passed: "
            f"{len(repository_source_files(inventory))} Swift sources and "
            f"{len(requirement_ids())} requirements; "
            + ", ".join(f"{status}={count}" for status, count in sorted(statuses.items()))
            + f"; baseline-blockers={len(inventory.get('baseline_blockers', []))}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
