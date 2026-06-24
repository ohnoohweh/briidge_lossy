---
name: obstaclebridge-project
description: ObstacleBridge repository workflow for commits, pushes, PR descriptions, guard validation, and Python/Swift parity. Use when Codex changes this repo, prepares or pushes commits, investigates PR checks, writes PR text, changes Python runtime code used by `python -m obstacle_bridge`, changes Swift macOS/iOS runtime code, or touches tests, requirements, traceability, README, or architecture docs.
---

# ObstacleBridge Project

Use this skill to keep ObstacleBridge changes mergeable and parity-aware.

## Before Changing Runtime Code

Identify whether the change affects a shared behavior surface:

- Python runtime entrypoints and modules used by `python -m obstacle_bridge`
- Swift macOS app, Swift host runner, Swift shared runtime, or iOS Network Extension
- overlay transports, SecureLink, ChannelMux, TUN routing, admin snapshots, WebAdmin APIs, config persistence, or generated hook behavior

When one implementation changes, check the other implementation for the same behavior. Python and Swift should stay in parity unless the user explicitly asks for a platform-only experiment. If parity is intentionally deferred, document the reason and make it visible in design or requirements notes.

## Python/Swift Parity Rule

For behavior that exists in both Python and Swift:

- Keep code behavior aligned in both directions: Python changes require a Swift parity review; Swift changes require a Python parity review.
- Keep test coverage equivalent in intent, even when the test mechanics differ. A Python unit test may pair with a Swift probe, source guard, simulator/device harness, or host-runner integration test.
- Prefer focused parity tests that pin the exact observed drift point, for example the same input producing the same bytes, state transition, route decision, snapshot field, or reconnect edge.
- Update `.github/requirements_traceability.yaml`, `.github/architecture_traceability.yaml`, `docs/README_TESTING.md`, and README statistics when tests or traceability change.
- Keep `README.md` focused on current state and coverage statistics. Do not clutter it with commit-by-commit change history merely to satisfy guards; update the relevant current snapshot, stable testing strategy, or durable project guidance instead.
- Refresh README statistics with:

```bash
./.venv/bin/python scripts/report_product_traceability.py
./.venv/bin/python scripts/report_python_swift_drift.py
```

## Guard Workflow Before Push

Before pushing, run guards against the same base GitHub Actions will use when possible.

For an existing branch push, use the previous remote branch head:

```bash
base="$(git rev-parse @{u})"
```

For a PR or branch whose CI log reports a base SHA, use that exact SHA. If unsure, also run against `origin/main`.

Run:

```bash
./.venv/bin/python scripts/check_requirements_guard.py --base-ref "$base"
./.venv/bin/python scripts/check_readme_testing_guard.py --base-ref "$base"
```

If either guard fails, update the requested companion file before pushing. Common guard chains:

- `src/`, `tests/`, or `docs/ARCHITECTURE.md` changed: update `docs/REQUIREMENTS.md` and `README.md`.
- tests changed: update `docs/README_TESTING.md`, `.github/requirements_traceability.yaml`, and `.github/architecture_traceability.yaml`.
- `docs/REQUIREMENTS.md` changed: update `.github/requirements_traceability.yaml` and `README.md`.
- `docs/ARCHITECTURE.md` changed: update `.github/architecture_traceability.yaml`.

When a guard asks for `README.md`, prefer refreshing statistics from the reporting scripts or adjusting durable guidance. Avoid adding temporary notes such as "this commit adds..." or one-off change history.

When edits are not committed yet, staged checks can catch the same chain before commit:

```bash
git add <intended-files>
./.venv/bin/python scripts/check_requirements_guard.py --staged
./.venv/bin/python scripts/check_readme_testing_guard.py --staged
```

After committing, rerun the `--base-ref` guards before pushing. Do not push while either guard is failing locally.

## Validation Expectations

Run the smallest meaningful test set that proves the change, plus any parity partner tests. Examples:

- Python-only behavior: focused `pytest` for the touched unit/integration file.
- Swift runtime behavior: focused Swift probe or host-runner test plus the Python counterpart.
- Traceability/statistics changes: both guard scripts and the reporting scripts when numbers changed.
- PR-check fixes: inspect the Actions log, reproduce with the same base SHA, fix locally, rerun guards, then push.

Include the exact commands and short results in the final response or PR description.

## PR Descriptions

When generating a PR description, use `docs/PULL_REQUEST_TEMPLATE.md` as the structure. Fill every section with real content:

- Summary
- Problem
- Changes
- Why This Matters
- Validation
- Reviewer Notes
- checklist

Do not invent validation. List only commands actually run, and call out anything intentionally not run.

## Commit And Push Discipline

Before committing or pushing:

- Inspect `git status -sb` and the diff.
- Stage only intended files.
- Keep unrelated local/user changes out of the commit.
- Run focused tests and both guards before pushing.
- After push, check PR guard status when a PR exists:

```bash
gh pr checks <pr-number> --json name,state,bucket,link,workflow
```

If a guard fails after push, inspect the check log, reproduce locally with the CI base SHA, and fix the full guard chain before pushing again.
