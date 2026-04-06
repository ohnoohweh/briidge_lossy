## Summary

Replace the POSIX-only `scripts/run.sh` with a cross-platform Python launcher `scripts/run.py`, update `README.md` with usage examples, and remove the legacy `scripts/run.sh`.

## Problem

- The existing `scripts/run.sh` is POSIX-only and cannot be used on Windows without WSL or a POSIX shell, creating friction for Windows contributors and users.

## Changes

- Added `scripts/run.py` — cross-platform Python launcher that defaults to the running interpreter (`sys.executable`) and restarts the process when exit code `75` is returned.
- Modified `README.md` — document usage examples for `scripts/run.py` on Linux and Windows, and list flags `--interval`, `--no-redirect`, `--command`.
- Deleted `scripts/run.sh` — removed legacy POSIX-only launcher.

## Why This Matters

This makes the launcher usable across Windows, Linux, and macOS without requiring a separate shell or wrapper, simplifies debugging on Windows, and keeps restart semantics consistent with the previous script.

## Validation

```bash
# Run the launcher (uses current interpreter by default)
python scripts/run.py --no-redirect

# Requirements and readme guards
python scripts/check_requirements_guard.py --base-ref main
python scripts/check_readme_testing_guard.py --base-ref main
```

Results: Requirements guard passed. README_TESTING guard passed.

## Reviewer Notes

- Focus review on: correct default command selection (`sys.executable`), restart-on-exit-code-75 behavior, and README wording/placement.
- Suggested reviewers: (@ohnoohweh)

---

Checklist before merging:

- [ ] Tests run locally and CI is expected to pass
- [ ] `docs/REQUIREMENTS.md` updated when behavior/tests changed
- [ ] `README.md` updated when requirement/test set changed
- [ ] `.github/requirements_traceability.yaml` updated when requirement IDs changed
- [ ] Linked to any relevant design/architecture docs in `docs/`
