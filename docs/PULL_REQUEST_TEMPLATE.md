## Summary

(One-paragraph summary of what the PR changes and why.)

## Problem

(Concrete, observable problem this PR fixes. Include minimal repro steps if relevant.)

## Changes

- (What changed in code, config, tests, docs)
- (List files touched and a short reason per file when useful)

## Why This Matters

(Short description of the risk/benefit and any compatibility considerations.)

## Validation

Run the exact commands you used to validate this PR and paste short results.

```bash
# example: run focused unit tests
pytest -q tests/unit/test_secure_link_psk.py -k "test_some_case"
# example: run requirements guard
python3 scripts/check_requirements_guard.py --base-ref origin/main
```

Results: (e.g. `3 passed`, `Requirements guard passed`)

## Reviewer Notes

- Focus review on: (list 2-4 focus points)
- Suggested reviewers: (@handle)

---

Checklist before merging:

- [ ] Tests run locally and CI is expected to pass
- [ ] `docs/REQUIREMENTS.md` updated when behavior/tests changed
- [ ] `README.md` updated when requirement/test set changed
- [ ] `.github/requirements_traceability.yaml` updated when requirement IDs changed
- [ ] Linked to any relevant design/architecture docs in `docs/`
