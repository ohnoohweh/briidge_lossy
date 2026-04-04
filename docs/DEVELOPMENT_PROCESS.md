# Development Process

This project currently evolves in short iterations:

1. request
2. implementation
3. test

That loop is effective for progress, but by itself it does not guarantee that the project remains understandable over time. The purpose of this document is to define how a change should be turned from a prompt into durable project knowledge.

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

The durable home for these statements is [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md).

### 2. Place the change in the architecture

If a feature is not trivial, identify which component is responsible.

Typical component questions:

- Which runtime owns the state?
- Which API or callback is the boundary?
- Which component should not know about this concern?

The durable home for this reasoning is [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md).

### 3. Implement

Implementation is the realization step, not the source of truth for intent.

Code should answer:

- how the feature works
- where state is stored
- how control and data move through the system

Code should not be the only place where behavior is defined.

### 4. Add or update tests

The test strategy follows a V-model-inspired layering:

- requirements are primarily defended by integration tests
- architectural invariants and local component rules are primarily defended by unit tests

For each change, ask:

- which user-visible behavior must be proved by integration tests?
- which internal invariants deserve unit tests?
- which old bug must become a regression test?

## Definition of done for one iteration

An iteration should normally be considered complete when:

- the requested behavior is captured as a requirement or requirement update
- the responsible component is obvious from the architecture description
- the code implements the behavior
- at least one integration test proves the externally visible result
- unit tests exist for non-trivial internal invariants when appropriate
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
- record the observable behavior in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- keep [requirements_traceability.yaml](/home/ohnoohweh/quic_br/docs/requirements_traceability.yaml) aligned so changed requirements still point at real tests
- update [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md) if responsibilities changed
- add or adjust integration tests in [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
- add or adjust unit tests if a local invariant changed
- update [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md) traceability when a new requirement is covered
- update [README.md](/home/ohnoohweh/quic_br/README.md) when requirements, implementation, or the test set changes so its links and requirement-coverage snapshot remain current

Repository guards now enforce three parts of this discipline, but they should be treated as the final safety net rather than the primary detector of degradation:

- behavior, test, or architecture changes must update [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- requirements, implementation, or test-set changes must update [README.md](/home/ohnoohweh/quic_br/README.md)
- requirement changes must update [requirements_traceability.yaml](/home/ohnoohweh/quic_br/docs/requirements_traceability.yaml), and the referenced tests must exist

This keeps the project understandable even when development continues in prompt-driven iterations.
