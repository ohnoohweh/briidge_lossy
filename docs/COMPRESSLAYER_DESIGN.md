# Compress Layer Design

## Purpose

This document describes the delivered transport-independent compression layer placed:

- below `ChannelMux`
- above secure-link
- above transport sessions (`myudp`, `tcp`, `ws`, `quic`)

Goals:

- reduce on-wire size for compressible mux payloads
- keep non-compressible payloads uncompressed
- avoid adding a second wrapper frame format around mux payloads
- preserve existing mux semantics after receive-side decompression

## Scope

This document covers:

- delivered wire signaling using the mux `mtype` high bit (`0x80`)
- tx/rx compress-or-bypass behavior
- default-on runtime/config behavior
- client/server asymmetric setting interoperability
- safety limits and failure handling
- observability, API/WebAdmin exposure, and current test coverage
- remaining follow-up work after the delivered baseline

This document does not attempt to:

- invent a tunnel-specific compression algorithm
- prove the most efficient compression strategy for every traffic shape
- select a universal best codec beyond the current dependency-free baseline

That boundary is intentional. ObstacleBridge uses a state-of-the-art, broadly available compression primitive from the Python runtime (`zlib`/DEFLATE), applies it conservatively per frame, and relies on measurements/tests to tune policy rather than developing a bespoke traffic-tunneling compressor.

## Layering

Current stack:

- `ChannelMux`
- `CompressLayerSession`
- secure-link
- transport session

Boundary intent:

- `ChannelMux` continues to operate on logical mux messages
- secure-link still protects bytes end-to-end
- compression happens before encryption, because ciphertext is intentionally high entropy and normally uncompressible
- the compression layer is mux-aware only at the frame-header level; it does not own channel routing, service publication, or secure-link authentication

## Wire model

### Existing mux header

`ChannelMux` uses:

- `chan_id:2`
- `proto:1`
- `counter:2`
- `mtype:1`
- `data_len:2`

encoded as `>HBHBH`.

### Compression signaling without extra wrapper

The compression layer reuses `mtype`:

- uncompressed frame: keep existing `mtype` (`0x00..0x07`)
- compressed frame: set `mtype = 0x80 + base_mtype`

Mapping:

- `DATA` `0x00` -> compressed `0x80`
- `OPEN` `0x01` -> compressed `0x81`
- `CLOSE` `0x02` -> compressed `0x82`
- `REMOTE_SERVICES_SET_V1` `0x03` -> compressed `0x83`
- `REMOTE_SERVICES_SET_V2` `0x04` -> compressed `0x84`
- `DATA_FRAG` `0x05` -> compressed `0x85`
- `REMOTE_SERVICES_SET_V2_CHUNK` `0x06` -> compressed `0x86`
- `OPEN_CHUNK` `0x07` -> compressed `0x87`

Important:

- only the compression layer should emit or consume `0x80..0x87`
- `ChannelMux` sees base `MType` values (`0x00..0x07`) after receive-side decompression
- unknown compressed base types fail closed instead of being forwarded as ambiguous mux messages

## Compression behavior

### Algorithm

Current implementation:

- `zlib` (DEFLATE) from the Python standard library

Rationale:

- no new dependency
- available on all target platforms
- mature, widely deployed compression primitive
- supports straightforward bounded decompression handling

Future codec expansion can be considered later, but it is not required for the current baseline.

### TX path

For each mux frame from `ChannelMux`:

1. parse the mux header in `CompressLayerSession`
2. evaluate compression eligibility from the sender's effective local settings
3. attempt `zlib` compression when eligible
4. if compressed payload is smaller, emit the compressed frame (`mtype | 0x80`)
5. otherwise emit the original frame unchanged

Current defaults:

- compression is enabled by default
- algorithm: `zlib`
- minimum payload size: `64` bytes
- compression level: `3`
- default allow list: `DATA`, `DATA_FRAG`

No-gain rule:

- require strict gain (`len(compressed) < len(original_payload)`)
- incompressible or already-compressed payloads are sent uncompressed

### RX path

On incoming protected bytes from secure-link:

1. parse the mux header in `CompressLayerSession`
2. if `mtype < 0x80`, pass through unchanged
3. if `mtype >= 0x80`, compute `base_mtype = mtype - 0x80`
4. validate that `base_mtype` is a known mux frame type
5. decompress payload within the configured safety cap
6. rebuild the mux header with `base_mtype` and decompressed length
7. pass the rebuilt uncompressed mux frame to `ChannelMux`

## Safety and correctness constraints

### Bounded decompression

Decompression fails closed for malformed or excessive expansion payloads:

- enforce maximum decompressed size <= effective mux payload cap
- reject invalid compressed bytes
- count decode failures through diagnostics
- avoid forwarding partially decoded data after failure

### Per-frame stateless compression

Compression uses independent per-frame state:

- no cross-frame dictionary reuse
- simple behavior across reconnect/rekey boundaries
- lower risk from long-lived shared compression contexts
- no dependency on traffic history for correctness

### Compatibility and mixed settings

Current delivered model:

- compression is default-on for current peers
- peer-client configuration controls whether a peer connection actively uses compression
- peer-server/listener sessions keep a passive compression decoder so they can detect client-selected compression even when server-side outbound compression was disabled locally
- sender policy decides whether a specific outbound frame is compressed
- receiver behavior is self-describing per frame via the `mtype` high bit
- client and server compression thresholds, levels, and allowed types do not need to match for successful decoding

Peer-server deployments:

- peer-client settings control the client-to-server effective send profile
- the peer server decodes each received frame based on wire signaling, not on mirrored local thresholds or levels
- after a peer sends a valid compressed frame, the peer server marks only that peer connection compression-active and compresses replies for that peer using the baseline `zlib` policy
- different concurrent peer clients can therefore send different compressed/uncompressed mixes to the same listener process

Unsupported path:

- sending `0x80..0x87` compressed frames to an older or explicitly non-compression-wrapper peer is not a supported mixed-version mode
- if mixed-version compatibility becomes a requirement, explicit capability/profile negotiation is the next protocol step

## Client-Directed Effective Settings

The implemented baseline does not add separate `compress_offer` or `compress_selected` control frames. Instead, the data plane is self-signaling:

- every compressed frame carries `mtype = 0x80 + base_mtype`
- every uncompressed frame keeps the base `mtype`
- the receiver can decode or pass through each frame independently

This achieves the required asymmetric-setting behavior without a separate startup handshake:

- a peer client can use `compress_layer_min_bytes=64` while a peer server uses `compress_layer_min_bytes=4096`
- client-to-server frames still decode on the server when the client decides compression is beneficial
- reverse-direction server-to-client frames start using compression for that peer after the server has seen a valid compressed frame from the client
- per-peer server state can report compression/decompression counters independently

Future explicit negotiation remains useful for broader scenarios such as mixed-version compatibility, multi-codec selection, or administrative policy clamps. That is tracked as follow-up rather than as a blocker for the delivered client-directed behavior.

## Runtime integration

`CompressLayerSession` is an `ISession` wrapper that:

- wraps the secure-link session when both features are enabled
- forwards lifecycle and metric calls
- intercepts outbound mux frames in `send_app(...)`
- intercepts inbound protected payloads before they reach `ChannelMux`
- maintains per-session compression/decompression counters

Runner composition:

- `session = base transport`
- `session = _maybe_wrap_secure_link(...)`
- `session = _maybe_wrap_compress_layer(...)`
- `ChannelMux.from_args(..., session=session, ...)`

CLI/config surface:

- `--compress-layer` enables the wrapper explicitly
- `--no-compress-layer` disables peer-client outbound compression; on peer servers/listeners, the runtime still keeps a passive decoder so client-selected compression can be detected per peer
- `--compress-layer-algo` selects the algorithm (`zlib` currently)
- `--compress-layer-min-bytes` sets the sender-side eligibility threshold
- `--compress-layer-level` sets the zlib compression level
- `--compress-layer-types` sets the sender-side allow-list

Operational note:

- compression is enabled by default
- in peer-server deployments, tune client-side compression settings first because they control the client-to-server send profile
- peer-server compression settings do not need to mirror the client; compression statistics and server replies activate per peer only after that peer sends a valid compressed frame

## Observability

Per-session and per-peer counters:

- `compress_attempts_total`
- `compress_applied_total`
- `compress_skipped_no_gain_total`
- `compress_input_bytes_total`
- `compress_output_bytes_total`
- `decompress_ok_total`
- `decompress_fail_total`

Derived ratio:

- `compress_input_bytes_total` counts payload bytes considered by attempted compression.
- `compress_output_bytes_total` counts emitted payload bytes for those attempts, including original uncompressed payload bytes when compression is skipped because it does not reduce size.
- `compression_saving_ratio = 1 - (output_bytes / input_bytes)` across attempted compression candidates.

Admin/API behavior:

- `/api/status` omits compression state/statistics; compression telemetry is peer-scoped
- `/api/peers` exposes peer-scoped compression counters and peer traffic rates for active peer rows
- on peer servers, peer rows show compression only for connections where the peer client has activated compression
- WebAdmin shows compression statistics only inside peer rows and hides them while a peer is still connecting

## Delivered Coverage

Unit coverage includes:

- `mtype` mapping round-trip (`base <-> base|0x80`)
- compress-or-bypass decision logic
- malformed compressed payload rejection
- decompression size cap enforcement
- pass-through behavior for uncompressed frames
- passive peer-server activation after receiving a valid compressed frame
- server-side reply compression for a peer that activated compression, even when local server compression settings are disabled or stricter
- admin payload and runner configuration behavior for compression settings/statistics

Integration coverage includes:

- existing overlay e2e cases running with default-on compression
- secure-link PSK plus compression happy-path forwarding and statistics
- disabled-compression operation as an explicit opt-out path
- mismatched peer-client/peer-server compression settings proving client-selected send policy, server-side passive decode activation, and server reply compression for the activated peer
- reconnect/restart scenarios that preserve forwarding after wrapper/session reset

Latest local validation for the shared Linux overlay suite:

- `RUN_OVERLAY_E2E=1 pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"` -> `134 passed`
- `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -k "admin_config_challenge_masks_and_saves_secrets_encrypted or onboarding_invite_api_masks_psk_and_returns_apply_updates or admin_reconnect_targets_selected_peer_id or default_entrypoint_config_bootstrap_and_webadmin_notice or compress_layer_mismatched_peer_settings"` -> `5 passed, 135 deselected`
- `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -k secure_link_psk` -> `25 passed, 111 deselected`

## Risks and mitigations

- CPU overhead under incompressible traffic: mitigated with `min-bytes` threshold and strict no-gain bypass
- decode-failure ambiguity: mitigated with fail-closed behavior and explicit counters/log reason
- mixed-version interoperability: peer clients define active compression use and peer servers keep a passive decoder, so mixed local settings are supported for compression-capable peers; fully mixed binary-version rollout still requires validating that older peers never receive compressed `0x80 + mtype` frames unexpectedly
- complexity near mux framing boundary: mitigated by keeping the wrapper narrowly scoped, stateless per frame, and transparent to `ChannelMux` after receive-side restoration

## Current State and Follow-Up

Delivered baseline:

- default-on compression wrapper
- zlib/DEFLATE algorithm
- high-bit mux `mtype` signaling
- no-gain bypass
- bounded receive-side decompression
- CLI/config/API/WebAdmin surfaces
- peer-scoped statistics
- asymmetric peer-client/peer-server settings support
- unit and integration traceability

Phase 2 follow-up, if needed:

- explicit capability/profile negotiation for mixed-version deployments
- optional codec negotiation if additional algorithms are introduced
- policy clamps and reject reasons for centrally managed server deployments
- telemetry fields for negotiated/effective profiles when such a handshake exists

Phase 3 follow-up, if needed:

- benchmark-led default tuning across representative traffic shapes
- adaptive sender policy for high-CPU or persistently no-gain traffic
- optional additional codecs when dependency, packaging, and platform support are acceptable
