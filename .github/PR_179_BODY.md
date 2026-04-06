## Summary

Document the Windows WebSocket proxy fallback fix, refresh the test catalog and README statistics, and align the WebSocket design note and PR checklist with the validated behavior.

## Problem

- The existing `scripts/run.sh` is POSIX-only and cannot be used on Windows without WSL or a POSIX shell, creating friction for Windows contributors and users.

## Changes

- Updated `src/obstacle_bridge/bridge.py` — Windows `system` proxy lookup now falls back to direct WebSocket connect when no endpoint is returned.
- Updated `tests/unit/test_ws_payload_mode.py` — unit coverage now asserts the direct-connect fallback instead of expecting a runtime error.
- Updated `tests/integration/test_overlay_e2e.py` — added the mixed-listener WebSocket secure-link regression and strengthened secure-link debug coverage for the relevant mixed-listener cases.
- Updated `README.md` — refreshed the test statistics snapshot and linked the reader guide to the WebSocket design note and testing guide.
- Updated `docs/README_TESTING.md` — recorded the current suite totals and added explicit acceptance criteria for WebSocket bootstrap changes.
- Updated `docs/WEBSOCKET_DESIGN.md` — documented the Windows no-endpoint direct-connect bootstrap behavior as an intentional transport decision.

## Why This Matters

This closes the gap between the runtime fix, the regression coverage, and the durable project documentation. The reader-facing README now reflects the current suite size, the testing guide states the acceptance bar for WebSocket bootstrap changes, and the design note records why the Windows direct-connect fallback is intentional.

## Validation

```bash
# Full regression rerun
python -m pytest -q -n 16 tests/integration/test_overlay_e2e.py

# Full unit suite
python -m pytest -q tests/unit
```

Results: the full unit suite passed locally (`114 passed, 8 subtests passed`). A parallel Windows integration rerun still showed instability, while the targeted WebSocket secure-link regression coverage passed and the remaining admin live WebSocket failure is being left to CI signal and follow-up.

## Reviewer Notes

- Focus review on: the Windows no-endpoint direct-connect fallback, the mixed-listener secure-link WebSocket regression coverage, and the README/testing-guide wording/placement.
- Suggested reviewers: (@ohnoohweh)

---

Checklist before merging:

- [ ] Tests run locally and CI is expected to pass
- [ ] `docs/REQUIREMENTS.md` updated when behavior/tests changed
- [ ] `README.md` updated when requirement/test set changed
- [ ] `.github/requirements_traceability.yaml` updated when requirement IDs changed
- [ ] Linked to any relevant design/architecture docs in `docs/`
