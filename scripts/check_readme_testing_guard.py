#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README_PATH = "docs/README_TESTING.md"


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
            "Fail when tests/ changed without a matching docs/README_TESTING.md update."
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
    readme_touched = README_PATH in changed

    if changed_tests and not readme_touched:
        sys.stderr.write(
            "README_TESTING.md must be updated when the testing suite changes.\n"
            f"Changed test files: {', '.join(changed_tests)}\n"
            f"Expected updated file: {README_PATH}\n"
        )
        return 1

    print("README_TESTING guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
