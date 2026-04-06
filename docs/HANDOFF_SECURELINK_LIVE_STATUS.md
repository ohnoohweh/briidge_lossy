# Secure-Link Live Status Handoff

## Branch

- Branch: `fix/ws-securelink-server-auth-state`
- Remote branch: `origin/fix/ws-securelink-server-auth-state`

## Commits On This Branch

- `fde5d29` - `Fix secure-link server auth state`
- `5d946a2` - `Fix WS text payload frame sizing`

## Problem Statements Addressed

### 1. Secure-link state asymmetry

Observed against the live deployment:

- client reported `secure_link.state = authenticated`
- server reported `secure_link.state = handshaking`
- both sides showed the same `session_id`

Root cause found in runtime behavior:

- the client promoted to authenticated immediately after processing `SERVER_HELLO`
- the server promoted to authenticated only after receiving the first protected `DATA` frame

Implemented fix:

- after the client validates `SERVER_HELLO`, it now sends one internal zero-length protected `DATA` frame as proof of PSK possession
- the server authenticates on decrypt of that frame
- the empty proof payload is not delivered upward as application data
- auth-fail handling was hardened so stale queued frames cannot revive or overwrite a failed session

### 2. Forwarded peer admin access caused fallback to `handshaking`

Observed with local own-server exposure:

- local config exposes peer admin via `127.0.0.1:18081`
- opening the peer admin page through that forwarded path caused the overlay to reconnect
- after reconnect, the peer temporarily fell back to `handshaking`

Root cause found in logs:

- the forwarded admin response traversed the WS overlay in `semi-text-shape` mode
- raw overlay payload stayed within the configured raw `ws_max_size`
- encoded WebSocket frame expanded beyond `65535`
- local WS client closed with code `1009` / `MESSAGE_TOO_BIG`

Implemented fix:

- WS receive limits now account for payload-mode expansion in text modes
- `binary`, `base64`, `json-base64`, and `semi-text-shape` now compute effective encoded frame limits consistently
- the manual server parser and the client `websockets.connect(..., max_size=...)` path now use the encoded-frame limit, not the raw payload budget

## Live Validation Already Performed

### Direct secure-link validation

After deploying the branch on both local and remote instances:

- local `/api/peers` showed the WS peer as `authenticated`
- remote `/api/peers` showed the same WS peer as `authenticated`
- both sides reported the same `session_id`

### Forwarded admin validation

After deploying commit `5d946a2` on both sides:

- forwarded peer admin endpoint `http://127.0.0.1:18081/` stayed reachable
- accessing the forwarded peer admin page no longer forced the secure-link state back to `handshaking`
- direct `/api/peers` snapshots remained authenticated on both sides while the forwarded admin path was in use
- the previous `1009` / `MESSAGE_TOO_BIG` error was no longer the active failure mode during this scenario

### Mixed live scenario

Additional live operator observation:

- a second peer using `myudp` was connected in parallel
- this appeared to work without obvious interference with the WS secure-link session

## Focused Automated Validation Already Run

- `pytest tests/unit/test_secure_link_psk.py`
  - result: green
- `pytest tests/unit/test_ws_payload_mode.py`
  - result: green

These are targeted validations only. The broader unit and integration suites were not brought to green in this workstream.

## Files Changed So Far

- `src/obstacle_bridge/bridge.py`
- `tests/unit/test_secure_link_psk.py`
- `tests/unit/test_ws_payload_mode.py`

## Important Remaining Follow-Up Work

### 1. Add integration tests that fail on unfixed `origin/main`

Desired outcome:

- add integration coverage that reproduces the learned failures on the unfixed runtime behavior currently on remote `main`
- verify the new tests fail against the unfixed baseline for the right reason

Candidate scenarios based on what was learned live:

- secure-link PSK over WS should show both sides authenticated without requiring first real application payload
- accessing forwarded peer admin over an own-server TCP exposure while WS payload mode is `semi-text-shape` should not drop or reset the overlay due to frame expansion

### 2. Wire the runtime changes through the test scenarios

After the failing integration tests exist:

- run the same tests against this fixed branch
- show they pass cleanly

### 3. Show explicit evidence of green test runs

For the Linux continuation:

- capture the exact command lines used
- preserve concise evidence for failing-before / passing-after behavior

### 4. Document the learnings in design documents

Update the relevant design material to capture:

- why server-side PSK authentication previously lagged until first protected data
- why the client proof frame now exists
- why WS text payload modes require encoded-frame-aware sizing rather than raw payload-only sizing
- any implications for operator-visible admin exposure over forwarded own-server mappings

Likely document targets:

- `docs/SECURE_LINK_DESIGN.md`
- `docs/WEBSOCKET_DESIGN.md`
- optionally `docs/ARCHITECTURE.md` if the cross-layer interaction needs architectural visibility

### 5. Update the test catalog

Likely target:

- `docs/README_TESTING.md`

Update it to include the new integration coverage and the rationale each test protects.

### 6. Think about other WS payload modes

This follow-up should explicitly consider whether equivalent risk exists for:

- `base64`
- `json-base64`

The current fix computes encoded-frame limits generically for all supported text modes, but integration coverage should confirm those modes behave correctly in realistic forwarded-service scenarios.

## Known Separate Item

There was still an earlier observation that remote `/api/status` aggregate summary could look inconsistent relative to `/api/peers`. That issue was not the focus of this branch and should be treated separately from the two secure-link / forwarded-admin regressions fixed here.