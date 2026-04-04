#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = "docs/REQUIREMENTS.md"
TRACEABILITY_PATH = "docs/requirements_traceability.yaml"
CONTRACT_CHANGE_PREFIXES = ("src/", "tests/")
CONTRACT_CHANGE_FILES = {
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT_PROCESS.md",
}
REQ_ID_RE = re.compile(r"`(REQ-[A-Z]+-\d+)`")
YAML_REQ_RE = re.compile(r"^(REQ-[A-Z]+-\d+):\s*$")
YAML_TEST_RE = re.compile(r"^\s*-\s+(.+?)\s*$")
TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)


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


def _load_requirement_ids() -> set[str]:
    text = (ROOT / REQUIREMENTS_PATH).read_text(encoding="utf-8")
    return set(REQ_ID_RE.findall(text))


def _load_traceability() -> dict[str, list[str]]:
    path = ROOT / TRACEABILITY_PATH
    lines = path.read_text(encoding="utf-8").splitlines()
    out: dict[str, list[str]] = {}
    current_req = None
    in_tests = False
    for line in lines:
        req_match = YAML_REQ_RE.match(line)
        if req_match:
            current_req = req_match.group(1)
            out.setdefault(current_req, [])
            in_tests = False
            continue
        if current_req is None:
            continue
        stripped = line.strip()
        if stripped == "tests:":
            in_tests = True
            continue
        if not stripped:
            continue
        if not line.startswith(" "):
            current_req = None
            in_tests = False
            continue
        if in_tests:
            test_match = YAML_TEST_RE.match(line)
            if test_match:
                out[current_req].append(test_match.group(1))
    return out


def _validate_traceability(requirement_ids: set[str], traceability: dict[str, list[str]]) -> list[str]:
    errors: list[str] = []
    for req_id, tests in sorted(traceability.items()):
        if req_id not in requirement_ids:
            errors.append(f"{TRACEABILITY_PATH}: unknown requirement id {req_id}")
        if not tests:
            errors.append(f"{TRACEABILITY_PATH}: {req_id} must list at least one test")
        for test_ref in tests:
            if "::" not in test_ref:
                errors.append(f"{TRACEABILITY_PATH}: invalid test reference {test_ref!r} for {req_id}")
                continue
            rel_path, test_name = test_ref.split("::", 1)
            file_path = ROOT / rel_path
            if not file_path.exists():
                errors.append(f"{TRACEABILITY_PATH}: missing test file {rel_path} for {req_id}")
                continue
            text = file_path.read_text(encoding="utf-8")
            defs = set(TEST_DEF_RE.findall(text))
            if test_name not in defs:
                errors.append(f"{TRACEABILITY_PATH}: missing test {test_name} in {rel_path} for {req_id}")
    return errors


def _is_contract_change(path: str) -> bool:
    return path.startswith(CONTRACT_CHANGE_PREFIXES) or path in CONTRACT_CHANGE_FILES


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail when implementation/architecture/test changes are not accompanied by "
            "REQUIREMENTS.md updates, and validate requirement traceability links."
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
    changed_contract = [path for path in changed if _is_contract_change(path)]
    requirements_touched = REQUIREMENTS_PATH in changed
    traceability_touched = TRACEABILITY_PATH in changed

    if changed_contract and not requirements_touched:
        sys.stderr.write(
            "REQUIREMENTS.md must be updated when implementation, tests, or architecture docs change.\n"
            f"Changed contract files: {', '.join(changed_contract)}\n"
            f"Expected updated file: {REQUIREMENTS_PATH}\n"
        )
        return 1

    if requirements_touched and not traceability_touched:
        sys.stderr.write(
            "requirements_traceability.yaml must be updated when REQUIREMENTS.md changes.\n"
            f"Expected updated file: {TRACEABILITY_PATH}\n"
        )
        return 1

    requirement_ids = _load_requirement_ids()
    traceability = _load_traceability()
    errors = _validate_traceability(requirement_ids, traceability)
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1

    print("Requirements guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
