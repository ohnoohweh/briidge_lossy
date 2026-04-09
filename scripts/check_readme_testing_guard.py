#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README_MAIN_PATH = "README.md"
README_PATH = "docs/README_TESTING.md"
REQUIREMENTS_PATH = "docs/REQUIREMENTS.md"
ARCHITECTURE_PATH = "docs/ARCHITECTURE.md"
REQ_TRACEABILITY_PATH = ".github/requirements_traceability.yaml"
ARCH_TRACEABILITY_PATH = ".github/architecture_traceability.yaml"


def _git_changed_files(*diff_args: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", *diff_args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _normalize(files: list[str]) -> list[str]:
    return sorted(set(f.replace("\\", "/") for f in files))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail when tests/architecture/requirements changes are missing "
            "their required testing/traceability document updates."
        )
    )
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument(
        "--base-ref",
        help="Compare changes against this git ref, for example origin/main or a commit SHA.",
    )
    scope.add_argument(
        "--staged",
        action="store_true",
        help="Check staged changes in the index.",
    )
    args = parser.parse_args()

    try:
        if args.staged:
            changed = _git_changed_files("--cached")
        else:
            changed = _git_changed_files(f"{args.base_ref}...HEAD")
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or str(exc))
        return 2

    changed = _normalize(changed)
    changed_tests = [path for path in changed if path.startswith("tests/")]
    changed_architecture = ARCHITECTURE_PATH in changed
    changed_requirements = REQUIREMENTS_PATH in changed
    readme_touched = README_PATH in changed
    readme_main_touched = README_MAIN_PATH in changed
    req_traceability_touched = REQ_TRACEABILITY_PATH in changed
    arch_traceability_touched = ARCH_TRACEABILITY_PATH in changed

    if changed_tests and not readme_touched:
        sys.stderr.write(
            "README_TESTING.md must be updated when the testing suite changes.\n"
            f"Changed test files: {', '.join(changed_tests)}\n"
            f"Expected updated file: {README_PATH}\n"
        )
        return 1

    if changed_tests and not req_traceability_touched:
        sys.stderr.write(
            "requirements_traceability.yaml must be updated when tests change so "
            "requirement links stay current.\n"
            f"Changed test files: {', '.join(changed_tests)}\n"
            f"Expected updated file: {REQ_TRACEABILITY_PATH}\n"
        )
        return 1

    if changed_tests and not arch_traceability_touched:
        sys.stderr.write(
            "architecture_traceability.yaml must be updated when tests change so "
            "architecture-component links stay current.\n"
            f"Changed test files: {', '.join(changed_tests)}\n"
            f"Expected updated file: {ARCH_TRACEABILITY_PATH}\n"
        )
        return 1

    if changed_architecture and not arch_traceability_touched:
        sys.stderr.write(
            "architecture_traceability.yaml must be updated when ARCHITECTURE.md changes.\n"
            f"Expected updated file: {ARCH_TRACEABILITY_PATH}\n"
        )
        return 1

    if changed_requirements and not req_traceability_touched:
        sys.stderr.write(
            "requirements_traceability.yaml must be updated when REQUIREMENTS.md changes.\n"
            f"Expected updated file: {REQ_TRACEABILITY_PATH}\n"
        )
        return 1

    if (changed_tests or changed_architecture or changed_requirements) and not readme_main_touched:
        sys.stderr.write(
            "README.md must be updated when tests/architecture/requirements change so "
            "the contributor snapshot remains current.\n"
            f"Expected updated file: {README_MAIN_PATH}\n"
        )
        return 1

    print("README/traceability guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
