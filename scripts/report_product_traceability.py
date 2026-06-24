#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from check_requirements_guard import (
    ARCH_TRACEABILITY_PATH,
    REQUIREMENTS_PATH,
    ROOT,
    TRACEABILITY_PATH,
    _load_architecture_ids,
    _load_architecture_traceability,
    _load_requirement_ids,
    _load_traceability,
)
from product_traceability_support import (
    PRODUCTS,
    TRACEABILITY_TEST_KEYS,
    classify_test_file,
    classify_test_ref,
    count_test_defs,
    iter_test_files,
    normalize_rel_path,
)


def _filter_ids(ids: set[str], prefix: str | None) -> set[str]:
    if not prefix:
        return set(ids)
    return {item_id for item_id in ids if item_id.startswith(prefix)}


def _classify_traceability_refs(entry: dict[str, list[str]], product: str | None) -> tuple[bool, bool, bool]:
    integration = False
    unit = False
    for key in TRACEABILITY_TEST_KEYS:
        refs = entry.get(key, [])
        for ref in refs:
            if product and classify_test_ref(ref) != product:
                continue
            rel_path = normalize_rel_path(ref.split("::", 1)[0])
            if key == "integration_tests" or (key == "tests" and rel_path.startswith("tests/integration/")):
                integration = True
            if key == "unit_tests" or (key == "tests" and not rel_path.startswith("tests/integration/")):
                unit = True
    return integration, unit, integration or unit


def _coverage_stats(
    all_ids: set[str],
    traceability: dict[str, dict[str, list[str]]],
    product: str | None,
) -> dict[str, object]:
    integration_covered: set[str] = set()
    unit_covered: set[str] = set()
    any_covered: set[str] = set()
    tracked: set[str] = set()

    for item_id in sorted(all_ids):
        entry = traceability.get(item_id, {})
        if item_id in traceability:
            tracked.add(item_id)
        integration, unit, any_cov = _classify_traceability_refs(entry, product)
        if integration:
            integration_covered.add(item_id)
        if unit:
            unit_covered.add(item_id)
        if any_cov:
            any_covered.add(item_id)

    return {
        "total": len(all_ids),
        "tracked": tracked,
        "integration_covered": integration_covered,
        "unit_covered": unit_covered,
        "any_covered": any_covered,
    }


def _suite_stats() -> dict[str, dict[str, int]]:
    stats = {product: {"files": 0, "tests": 0} for product in PRODUCTS}
    for path in iter_test_files():
        product = classify_test_file(path)
        if not product:
            continue
        stats[product]["files"] += 1
        stats[product]["tests"] += count_test_defs(path)
    return stats


def _print_suite_stats() -> None:
    print("Per-product suite statistics")
    print("===========================")
    print("Primary-product ownership is derived from test path and a small set of explicit overrides.")
    print()
    for product, stat in _suite_stats().items():
        print(f"{product}:")
        print(f"  test files: {stat['files']}")
        print(f"  test defs:  {stat['tests']}")
    print()


def _print_coverage_block(
    *,
    title: str,
    manifest_path: str,
    total_ids: set[str],
    traceability: dict[str, dict[str, list[str]]],
    product: str | None,
    show_ids: bool,
) -> None:
    stats = _coverage_stats(total_ids, traceability, product)
    total = int(stats["total"])
    tracked = set(stats["tracked"])
    integration_covered = set(stats["integration_covered"])
    unit_covered = set(stats["unit_covered"])
    any_covered = set(stats["any_covered"])

    def pct(count: int) -> float:
        return (100.0 * count / total) if total else 0.0

    label = product or "all products"
    print(f"{title} ({label})")
    print("=" * (len(title) + len(label) + 3))
    print(f"Manifest: {Path(ROOT / manifest_path)}")
    print(f"Total IDs: {total}")
    print(f"Tracked in manifest: {len(tracked)}/{total} = {pct(len(tracked)):.1f}%")
    print(
        f"Integration-covered: {len(integration_covered)}/{total} = {pct(len(integration_covered)):.1f}%"
    )
    print(f"Unit-covered: {len(unit_covered)}/{total} = {pct(len(unit_covered)):.1f}%")
    print(f"Any-test-covered: {len(any_covered)}/{total} = {pct(len(any_covered)):.1f}%")

    if show_ids:
        uncovered = sorted(total_ids - any_covered)
        integration_uncovered = sorted(total_ids - integration_covered)
        print()
        print("Any-test-covered IDs:")
        print(", ".join(sorted(any_covered)) if any_covered else "(none)")
        print()
        print("Integration-uncovered IDs:")
        print(", ".join(integration_uncovered) if integration_uncovered else "(none)")
        print()
        print("Uncovered IDs:")
        print(", ".join(uncovered) if uncovered else "(none)")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report per-product testing statistics and traceability for the Python, macOS, and iOS products."
        )
    )
    parser.add_argument(
        "--product",
        choices=PRODUCTS,
        help="Limit requirement/architecture reporting to one product view.",
    )
    parser.add_argument(
        "--kind",
        choices=("all", "requirements", "architecture"),
        default="all",
        help="Choose which traceability family to report.",
    )
    parser.add_argument(
        "--prefix",
        help="Optional ID prefix filter, for example REQ-WSP or ARC-CMP-00.",
    )
    parser.add_argument(
        "--show-ids",
        action="store_true",
        help="Print covered and uncovered IDs in addition to the summary counts.",
    )
    parser.add_argument(
        "--no-suite-stats",
        action="store_true",
        help="Skip the top-level per-product suite statistics block.",
    )
    args = parser.parse_args()

    if not args.no_suite_stats:
        _print_suite_stats()

    products_to_report = [args.product] if args.product else [None, *PRODUCTS]

    if args.kind in {"all", "requirements"}:
        requirement_ids = _filter_ids(_load_requirement_ids(), args.prefix)
        requirement_traceability = _load_traceability()
        for product in products_to_report:
            _print_coverage_block(
                title="Requirement traceability",
                manifest_path=TRACEABILITY_PATH,
                total_ids=requirement_ids,
                traceability=requirement_traceability,
                product=product,
                show_ids=args.show_ids,
            )

    if args.kind in {"all", "architecture"}:
        architecture_ids = _filter_ids(_load_architecture_ids(), args.prefix)
        architecture_traceability = _load_architecture_traceability()
        for product in products_to_report:
            _print_coverage_block(
                title="Architecture traceability",
                manifest_path=ARCH_TRACEABILITY_PATH,
                total_ids=architecture_ids,
                traceability=architecture_traceability,
                product=product,
                show_ids=args.show_ids,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
