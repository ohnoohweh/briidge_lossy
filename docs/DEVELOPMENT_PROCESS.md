# Development Process

This project currently evolves in short iterations:

1. request
2. implementation
3. test

That loop is effective for progress, but by itself it does not guarantee that the project remains understandable over time. The purpose of this document is to define how a change should be turned from a prompt into durable project knowledge.

## Process measures

These measures describe how the project is developed and validated. They are intentionally kept outside [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md) because they are not operator-visible delivery promises.

- `PROC-TST-001`: User-visible transport behavior should be defended primarily by integration tests, and the relevant regression suites should be executed before documentation or repository guards are treated as evidence of correctness.
  Measure:
  - run the most relevant targeted tests during iteration
  - run `pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"` before push or PR when the shared integration harness is materially affected
  - keep the top-level [README.md](/home/ohnoohweh/quic_br/README.md) coverage snapshot aligned with the current product requirement set, but keep detailed requirement and design prose in the dedicated docs instead of duplicating it in the snapshot
- `PROC-TST-002`: Important local invariants and component contracts should be defended by unit tests.
  Measure:
  - add or update focused tests under `tests/unit/` when internal state handling, parser behavior, or component-local contracts change
- `PROC-TST-003`: Known bugs and regressions should become regression tests whenever practical.
  Measure:
  - reproduce the bug in the smallest suitable unit or integration scenario
  - add or preserve the reproducer before the fix so the unchanged test fails against the buggy behavior and passes after the fix
  - keep that scenario in the regular regression flow after the fix lands
- `PROC-TST-004`: The integration harness should remain executable in regular parallel local and CI workflows, with OS-specific expectations executed on the OS where they are observable.
  Measure:
  - keep the worker-safe port allocation tests green
  - run Linux shared coverage with `pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"`
  - run Windows-specific coverage with `pytest -q -n 4 tests/integration/test_overlay_e2e.py -m "windows_only"`

## Core idea

Each meaningful feature or bugfix should leave evidence in four places:

- requirements: what observable behavior is expected
- architecture: which component is responsible for realizing it
- implementation: the code that realizes it
- tests: the evidence that it works and keeps working

## Iteration flow

### 1. Capture intent

Before or during implementation, express the requested behavior as one or more requirement statements.

Good requirement style:

- observable from outside the implementation
- transport- or topology-specific when needed
- explicit about expected success and failure behavior
- stable enough to remain meaningful after refactoring

Example:

- "A myudp listener shall support multiple concurrent peer clients and show them as distinct peers in the admin API."
- "Auxiliary activity on a shared listener endpoint, such as a plain HTTP read on a WebSocket listener, shall stay scoped to the originating request and shall not disturb other peers."

The durable home for these statements is [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md).

### 2. Place the change in the architecture

If a feature is not trivial, identify which component is responsible.

Typical component questions:

- Which runtime owns the state?
- Which API or callback is the boundary?
- Which component should not know about this concern?

The durable home for this reasoning is [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md).

When a component has local design tradeoffs, protocol asymmetries, library constraints, or boundary-specific behavior, document those actively in the corresponding component design note such as `..._DESIGN.md` rather than leaving that reasoning only in code review or commit history.

Typical examples are [WEBSOCKET_DESIGN.md](/home/ohnoohweh/quic_br/docs/WEBSOCKET_DESIGN.md) and [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md).

### 3. Implement

Implementation is the realization step, not the source of truth for intent.

Code should answer:

- how the feature works
- where state is stored
- how control and data move through the system

Code should not be the only place where behavior is defined.

### 4. Add or update tests

The test strategy follows a V-model-inspired layering:

- product requirements are primarily defended by integration tests
- architectural invariants and local component rules are primarily defended by unit tests
- development-process discipline is tracked by the `PROC-TST-*` measures above rather than by product requirement IDs

For each change, ask:

- which user-visible behavior must be proved by integration tests?
- which internal invariants deserve unit tests?
- which old bug must become a regression test?

For bug fixes specifically, prefer an explicit red-before-green loop:

- write or isolate the smallest reproducer that fails against the unfixed behavior
- implement the fix without weakening that test expectation
- rerun the same unchanged test and keep it as permanent regression evidence

## Definition of done for one iteration

An iteration should normally be considered complete when:

- the requested behavior is captured as a requirement or requirement update
- the responsible component is obvious from the architecture description
- the code implements the behavior
- at least one integration test proves the externally visible result
- unit tests exist for non-trivial internal invariants when appropriate
- bug-fix regressions have an unchanged reproducer test that was observed red before the fix and green after it
- the relevant test suites have been executed before relying on repository guards
- the testing catalog or traceability notes reflect the new behavior

## How to judge the test step

The test step is not only about pass/fail. It should be judged on three dimensions.

### Consistency

Consistency asks whether the project artifacts agree with each other.

Check alignment between:

- request and requirement
- requirement and integration test
- architecture and implementation
- unit tests and component responsibilities
- README behavior statements and observed runtime behavior

If these disagree, another iteration is needed even if tests pass.

### Completeness

Completeness asks whether the intended scope is sufficiently covered.

For this project, useful completeness dimensions are:

- transport: `myudp`, `tcp`, `ws`, `quic`
- topology: single peer, listener, multi-peer
- traffic: UDP, TCP, mixed
- peer interaction: one peer active while another peer connects, fails auth, disconnects, or exercises an auxiliary endpoint path such as WS static HTTP
- lifecycle: startup, reconnect, restart, disconnect
- admin visibility: status, peers, connections, auth
- degradation: delay, loss, dropped data/control, concurrency

If an important dimension affected by the change is untested, another iteration is likely needed.

### Correctness

Correctness asks whether the requirement, the test expectation, and the implementation are actually right.

Passing tests alone do not prove correctness if the test itself checks the wrong thing.

Correctness improves when:

- the requirement is explicit
- integration tests check externally visible behavior
- unit tests protect critical invariants
- real observations from the running system match the documented expectation

## Conflict resolution order

When different artifacts disagree, resolve in this order:

1. [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
2. integration tests
3. [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md)
4. unit tests
5. implementation

If a requirement is missing, add it first instead of letting code or tests silently define truth.

## Practical guidance for future changes

After implementing a new feature or fixing a bug:

- run the most relevant targeted tests early while iterating so regressions are detected from runtime behavior, not from documentation or guard failures
- when [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py) changes, run the full integration gate `pytest -q -n 16 tests/integration/test_overlay_e2e.py` before pushing or opening a PR
- when [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py) changes, strongly prefer the same full integration run before pushing or opening a PR, even if targeted `-k` runs were used during iteration
- when integration requirements are OS-specific, mark them explicitly and keep CI split so Linux runs the shared suite while Windows runs the Windows-only subset
- record the observable behavior in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- keep [requirements_traceability.yaml](/home/ohnoohweh/quic_br/.github/requirements_traceability.yaml) aligned so changed requirements still point at real tests
- update [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md) if responsibilities changed
- add or adjust integration tests in [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
- add or adjust unit tests if a local invariant changed
- update [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md) traceability when a new requirement is covered
- update [README.md](/home/ohnoohweh/quic_br/README.md) when requirements, implementation, or the test set changes so its links and requirement-coverage snapshot remain current; do not treat it as the durable home for detailed requirement narratives

Repository guards now enforce three parts of this discipline, but they should be treated as the final safety net rather than the primary detector of degradation:

- behavior, test, or architecture changes must update [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- requirements, implementation, or test-set changes must update [README.md](/home/ohnoohweh/quic_br/README.md) so its snapshot counts and links stay current
- requirement changes must update [requirements_traceability.yaml](/home/ohnoohweh/quic_br/.github/requirements_traceability.yaml), and the referenced tests must exist

This keeps the project understandable even when development continues in prompt-driven iterations.

### Shift-left local hooks (before push)

To catch documentation/traceability drift before pushing, enable the local git hooks once per clone:

```bash
./scripts/install_local_hooks.sh
```

This wires `core.hooksPath=.githooks` and runs the following checks on every commit:

- `python scripts/check_readme_testing_guard.py --staged`
- `python scripts/check_requirements_guard.py --staged`

The checks enforce that test/architecture/requirements changes come with matching updates in:

- [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md)
- [.github/requirements_traceability.yaml](/home/ohnoohweh/quic_br/.github/requirements_traceability.yaml)
- [.github/architecture_traceability.yaml](/home/ohnoohweh/quic_br/.github/architecture_traceability.yaml)
- [README.md](/home/ohnoohweh/quic_br/README.md) coverage snapshot

## Mitigating legacy single-peer assumptions

When behavior suggests one peer is accidentally coupled to another, derive follow-up work from the requirement first and then inspect the code with that failure mode in mind.

- treat `peer_id`, transport-session identity, or request scope as mandatory keys for mutable listener-side state; avoid process-global shortcuts for peer-owned routing, cleanup, or publication decisions
- review endpoint-adjacent code paths first: listener bootstrap, websocket `process_request` / pre-upgrade HTTP paths, handshake failure handling, disconnect cleanup, and listener-side admin snapshot aggregation
- require at least one regression that keeps a healthy peer active while another peer or auxiliary request exercises the suspected legacy path
- prefer mixed-transport and mixed-protocol regressions when the listener shares code paths, because they expose unintended coupling faster than single-transport happy paths
- when a code path truly needs process-wide effects, document that boundary explicitly so later changes do not mistake a legacy shortcut for intended architecture

## Pull Request Style and Templates

To keep PRs consistent and easy to review, follow this PR structure and use the project PR template (see `.github/PULL_REQUEST_TEMPLATE.md`). Reviewers will expect this layout and rely on it when triaging changes:

- **Summary**: Short, high-level description of the change and its intent.
- **Problem**: Concrete, observable problem statement the change fixes (include a minimal reproduction if relevant).
- **Changes**: Bulleted list of what changed (files, behavioral changes, tests added/modified).
- **Why This Matters**: Short paragraph describing the risk/benefit and why the change is needed.
- **Validation**: Exact commands used to validate the change (tests run, guard checks) and the observed results.
- **Reviewer Notes**: Focus areas for reviewers (backwards-compatibility, safety, performance, tests to examine).

Checklist for opening PRs:

- Use the repository PR template in `.github/PULL_REQUEST_TEMPLATE.md`.
- Run the most relevant unit and integration tests and include the commands + short results in the `Validation` section.
- If implementation or tests change, update `docs/REQUIREMENTS.md`, `README.md`, and `.github/requirements_traceability.yaml` as required by the repository guards.
- Link to related architecture or design notes in `docs/` when the change affects component responsibilities.
- Keep the PR body factual and actionable — reviewers should be able to understand what to review and why in under a minute.

Maintainers may update the PR template to reflect evolving review preferences; when in doubt, model new PRs off of recently merged PRs that had small, corrective changes (for example the WebSocket keep-alive demux PR). This keeps reviewer expectations consistent across the project.
