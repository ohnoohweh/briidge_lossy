# MyUDP Design

## Purpose

This document records the `myudp` transport design and the defined myUDP2
datagram-batching extension. The currently shipped codec is implemented in
[bridge_transport_udp.py](../src/obstacle_bridge/bridge_transport_udp.py).

The whitepaper explains why a UDP-based reliable overlay exists at all. This note stays closer to the runtime:

- frame layout
- RTT measurement
- retransmission behavior
- receiver gap tracking
- the specific resend invariant that every transmitted frame must carry fresh transport timestamps
- the myUDP2 batch carriage that lets one UDP datagram carry multiple reliable data records

The batching extension is a required wire-format change. It is specified here
before implementation so the Python and Swift codecs can change together.

## Scope

This document covers:

- the `Protocol` envelope used by `myudp`
- `DATA`, `CONTROL`, and `IDLE` frame responsibilities
- how RTT samples are derived from echoed transport timestamps
- how receiver gap tracking feeds retransmission
- why stale raw-frame resend is incorrect even when the application payload is unchanged

It does not redefine:

- product requirements in [REQUIREMENTS.md](./REQUIREMENTS.md)
- mux semantics in [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md)
- secure-link behavior in [SECURE_LINK_DESIGN.md](./SECURE_LINK_DESIGN.md)

## Delivered framing and target framing

`myudp` currently has one timestamp-bearing layer:

1. The protocol envelope header.

The delivered codec uses `DataPacket` payloads with upper-payload fragment
metadata. That is the behavior being replaced. Its timestamp rule remains a
myUDP2 invariant:

- RTT-relevant transport timestamps live in the outer protocol envelope, not in the `DataPacket` payload.
- `DataPacket` payloads are intentionally semantic-only and do not carry transport timestamps.

The delivered `DataPacket.build_payload(...)` encodes:

- packet counter
- frame type
- total length or fragment offset
- chunk length
- payload bytes

The transport envelope added by `Protocol.build_frame(...)` then wraps that payload with:

- `ptype`
- payload length
- `tx_ns`
- `echo_ns`

That means a resend is not correct unless the outer protocol envelope is rebuilt.

## myUDP2 stream boundary

myUDP2 is a reliable ordered byte-stream transport, with the same session
contract as TCP, WebSocket, and QUIC. It does not know about ChannelMux frames,
compression frames, SecureLink frames, service UDP datagrams, or any other
upper-layer message boundary.

The transport itself is not a cryptographic layer. When SecureLink is enabled,
the stream is secure because SecureLink protects the bytes before they reach the
serializer; myUDP must neither inspect nor alter those protected bytes.

The stack on send and receive is therefore:

```text
send:     ChannelMux -> Compression -> SecureLink -> StreamSerializer -> myUDP2 -> UDP
receive:  UDP -> myUDP2 -> StreamDeserializer -> SecureLink -> Compression -> ChannelMux
```

`StreamSerializer` and `StreamDeserializer` are the message/stream adaptation
layer immediately above myUDP2. For every upper-layer payload, the serializer
writes one bounded record to the byte stream:

```text
stream record = payload_length:u32 (big-endian) + payload bytes
```

The deserializer buffers arbitrary contiguous bytes from myUDP2, validates the
length against the configured upper-record limit, and emits each complete
payload to SecureLink, Compression, or ChannelMux as appropriate. A record can
span any number of myUDP2 chunks or UDP datagrams; a myUDP2 chunk can contain
parts of one record, one complete record, or parts of several records.

This keeps upper layers message-oriented where their protocols require it,
without making those message boundaries a myUDP responsibility. The serializer
and deserializer own their per-peer buffer, maximum-record validation, reset on
transport epoch change, and malformed-stream failure policy.

At the myUDP2 API, the operations are only:

- append bytes to the outbound reliable stream
- deliver newly contiguous inbound bytes to the deserializer
- report transport state, flow control, and transport quality

There is no `send_application_payload()` semantic boundary, per-message total
length, upper-message reassembly, or application-datagram callback inside
myUDP2.

## Datagram boundaries and streaming carriage

UDP preserves datagram boundaries. It does not combine multiple `sendto` calls
into one receive event, and it does not provide TCP or WebSocket stream
semantics. A sender must explicitly coalesce records before its UDP send; a
receiver must explicitly unpack them after one UDP receive.

Today one `DATA` payload occupies one protocol envelope and therefore one UDP
datagram. This spends the 19-byte protocol header per small segment and leaves
the rest of the path MTU unused. myUDP2 changes the `DATA` payload from one
stream chunk to a length-delimited collection of stream chunks. The protocol
envelope, including its timestamps, remains exactly once per UDP datagram.

```text
UDP datagram
└── Protocol envelope: ptype, payload_len, tx_ns, echo_ns
    └── DATA batch payload
        ├── batch version
        ├── record count
        └── repeated record
            ├── record length
            └── DataPacket chunk: counter, chunk length, bytes
```

The record body is a myUDP2 stream chunk, not a nested timestamped protocol
frame and not an upper-layer frame. Its counter identifies a reliable contiguous
range in the stream; its bytes are opaque to myUDP2. One envelope timestamp pair
describes the actual UDP send that carried every record in that batch.

The existing `FRAME_FIRST`/`FRAME_CONT`, total-length, offset, and transport
reassembly state are removed from myUDP2. Those fields describe upper-message
boundaries and belong in the serializer/deserializer layer instead.

This is a protocol-wide myUDP2 replacement: all Python and Swift endpoints
must emit and accept the batch form. There is no old one-record wire fallback,
capability negotiation, or ambiguous parser mode.

### Frozen myUDP2 wire contract

The following values are frozen. The machine-readable golden vectors are in
[MYUDP2_WIRE_VECTORS.json](./MYUDP2_WIRE_VECTORS.json); the Python and Swift
batch-codec implementations use those vectors unchanged.

| Item | Value |
| --- | --- |
| UDP payload budget | `1452` bytes for the conservative IPv6-safe 1500-byte MTU assumption |
| Protocol header | `ptype:u8`, `payload_len:u16`, `tx_ns:u64`, `echo_ns:u64`, all big-endian; exactly 19 bytes |
| `ptype` values | `IDLE=0`, `DATA_BATCH=1`, `CONTROL=2` |
| Batch header | `version:u8`, `record_count:u8`; version is `1`, count is `1..64` |
| Batch record | `record_len:u16` followed by one complete chunk record; `record_len` includes the chunk header and bytes |
| Chunk record | `counter:u16`, `chunk_len:u16`, `bytes[chunk_len]`; counter is `1..65535`, chunk length is `1..1425` |
| Batch validity | exactly `record_count` records and no trailing bytes; every record length is at least 5 bytes and exactly matches its chunk length |
| `CONTROL` payload | unchanged: `last_in_order:u16`, `highest_rx:u16`, `missed_count:u16`, then `missed_count` `u16` counters |
| `IDLE` payload | empty |
| Stream serializer | `payload_len:u32 + payload bytes`, big-endian; payload length is `0..65535`, including an allowed empty payload |
| MTU calculation | batch payload is at most `1452 - 19 = 1433` bytes; the batch header and every record length are included in that limit |

The maximum 1425-byte chunk is the one-record case:
`1433 - batch_header(2) - record_len(2) - chunk_header(4)`. A multi-record
batch has a smaller remaining chunk budget after each complete preceding record.
`CONTROL` and `IDLE` are never embedded in a data batch.

### Batch parsing rules

The batch header must contain an explicit format/version value and bounded
record count. Every record must have an explicit unsigned length. A receiver
must reject the entire UDP datagram when any of these conditions holds:

- the batch header is incomplete or names an unsupported version
- the record count is zero or exceeds the implementation limit
- a record length is zero, too short for a `DataPacket` header, or extends past the batch payload
- a record fails normal `DataPacket` validation
- bytes remain after the declared final record

No record is handed to the reliable receive state until the complete batch has
validated. This avoids accepting a prefix from a malformed datagram and makes
Python and Swift rejection behavior deterministic.

After validation, records are fed to the receive/gap logic in wire order. Batch
order is only a parsing order: contiguous stream delivery still comes from
packet counters, and an out-of-order record still enters `pending` and
contributes to `missing` exactly as it does outside a batch. Once counters are
contiguous, their opaque bytes are appended to the inbound stream and emitted to
the deserializer without waiting for an upper-layer record boundary.

### MTU budget and sender scheduling

The sender packs only `DATA` records. `IDLE` and `CONTROL` remain individual
datagrams so keepalive, RTT refresh, ACK, and loss feedback are never delayed
behind a data batch.

The effective datagram budget is the smallest configured safe UDP payload for
the active path. With the repository's conservative 1500-byte MTU assumption,
the UDP payload limit is 1452 bytes (`1500 - 40` IPv6 header `- 8` UDP header).
The batch payload budget is therefore:

```text
1452 - protocol_header_bytes(19) - batch_header_bytes
```

The implementation must derive this from one shared codec constant rather than
duplicate the number in the Python and Swift schedulers. Any lower path-MTU or
encapsulation budget must be applied before batch packing.

For each send opportunity, the scheduler appends complete data records while
the next record fits. It sends immediately when the queue is empty, the budget
is full, or a short bounded batching delay expires. The delay is a latency cap,
not a throughput promise: the first queued record must never wait indefinitely
for another record. The exact cap and maximum-record count are configuration
constants shared by both runtimes and exposed in transport diagnostics.

The serializer appends stream bytes; myUDP2 divides those bytes into chunks that
fit the available batch budget. If the remaining budget is smaller than the
next queued byte range, myUDP2 creates a smaller final chunk to fill the current
batch and starts the next chunk in the next batch. This is the requested
"split the last data frame" behavior, but it applies to opaque stream bytes,
not an upper-layer message.

The encoded chunk record itself must not be split across datagrams. The sender
chooses its chunk size before encoding the record, so each record is wholly
contained in exactly one batch. This avoids a second transport reassembly
grammar and leaves one unambiguous counter/ACK identity for every byte range.

### ACK, retransmission, and observability

Batching changes carriage, not reliability identity:

- every data record gets its own counter and its own `send_meta` entry
- `CONTROL` acknowledges and reports loss by those individual counters
- a lost UDP datagram makes each contained record eligible for normal recovery
- a retransmission rebuilds only the missing record, optionally with other eligible records that fit a new batch
- every new batch, including one containing retransmissions, gets a freshly built outer envelope with fresh `tx_ns` and `echo_ns`

The last rule preserves the RTT invariant. A batch must never be stored or
replayed as a raw retransmission unit. Persistent-missing state, first-send
transmit-delay timing, and attempt counters stay attached to individual stream
chunks, not to the batch that first carried them.

Batch metrics must distinguish UDP-datagram behavior from record behavior:

- records per datagram and batch payload utilization
- batching-delay sample and configured cap
- records retransmitted and datagrams carrying retransmissions
- malformed-batch rejection count
- path-MTU/budget rejection count

This gives myUDP the efficient carriage of a stream transport while retaining
explicit UDP message boundaries, independent loss recovery, and deterministic
application-message reassembly.

## Frame roles

myUDP2 uses three protocol-level frame classes:

- `IDLE`: keepalive and RTT refresh path
- `DATA`: opaque reliable stream chunks with packet counters
- `CONTROL`: ACK/loss feedback path carrying `last_in_order`, `highest_rx`, and a bounded missing-counter list

The receive side uses packet counters to track:

- which stream chunks have become contiguous and can be delivered upward
- what is pending out of order
- which counters are considered missing

The send side uses `CONTROL.missed` to decide which outstanding `DATA` counters need retransmission.

One recovery rule is especially important under loss:

- once a counter has been reported missing by the peer, omission from later feedback is not treated as a positive ACK by itself

That rule exists because `CONTROL` frames are lossy too. A sender must not assume that a previously missing counter is repaired merely because one later feedback sample did not mention it.

The missing list is also intentionally bounded by `CONTROL_MAX_MISSED`.
When feedback reaches that cap, omission from the list is even less trustworthy as evidence of repair, because the receiver may be truncating loss feedback rather than signaling successful delivery.

## RTT measurement

The RTT algorithm is deliberately lightweight.

When sending any protocol frame, `Protocol.build_frame(...)` stamps:

- `tx_ns`: local monotonic send time for this frame
- `echo_ns`: a local estimate derived from the most recently received peer frame

The current echo formula is:

```text
echo_ns = last_rx_tx_ns + (now_tx_ns - last_rx_wall_ns)
```

where:

- `last_rx_tx_ns` is the peer frame's original `tx_ns`
- `last_rx_wall_ns` is the local monotonic time when that peer frame was received
- `now_tx_ns` is the local monotonic time for the outgoing frame being built

On receive, if `echo_ns != 0`, the implementation treats:

```text
RTT sample = now_monotonic_ns - echo_ns
```

and feeds that sample into the transport EWMA.

So the RTT signal depends on the transport envelope timestamps of the frame that actually went onto the wire.

## Why resend must rebuild the frame

Resending a previously serialized raw datagram is wrong for RTT accounting.

If an older raw frame image is reused unchanged, then:

- `tx_ns` stays frozen at the original send attempt
- `echo_ns` stays frozen at the original echo basis
- the receiver sees a packet that looks like it was just received but claims to have been sent much earlier
- any RTT sample derived from its echoed timestamp path is biased by retransmission delay rather than representing the true transport turn

That makes the transport observability misleading in exactly the cases where we most need it:

- loss recovery
- reorder-heavy paths
- long retransmission windows
- device-to-host forensic log analysis

The correct resend invariant is:

- every actual wire send gets a freshly rebuilt protocol envelope with fresh `tx_ns`
- `echo_ns` is recomputed from the sender's latest receive-side view at the time of resend

The application payload bytes may be identical across attempts, but the transport envelope must not be identical.

## Transmit delay measurement

`myudp` now tracks a second transport-quality metric in addition to RTT:

- `transmit_delay_ms`

This metric is intentionally not the same as raw one-way propagation latency.
It is an estimate of the effective one-way delivery delay that a reliable stream
chunk experienced before it became acknowledged.

Current design rules:

- the first on-wire `tx_ns` for a stream chunk is stored when that counter is first emitted
- if the frame had to wait because `max_in_flight` was saturated, the sender also keeps the earlier local queue-entry timestamp
- retransmission does not overwrite those first-attempt timing references
- when feedback cumulatively acknowledges the frame and it leaves the send buffer, the sender computes:

```text
transmit_delay_sample_ms = ack_elapsed_ms - 0.5 * current_rtt_est_ms
```

where:

- `ack_elapsed_ms` is the local monotonic time since the start of the frame's effective send path
- `current_rtt_est_ms` is the sender's current RTT EWMA at ACK time

The effective send-path start is defined as:

- immediate send with no pre-buffering: the first emitted frame's stamped `tx_ns`
- queued send after in-flight saturation: the time when the segment first entered the local wait queue

The sample is clamped at `>= 0` and then fed into its own EWMA:

- `transmit_delay_sample_ms`
- `transmit_delay_est_ms`

This definition intentionally includes queueing and loss-recovery cost from the sender's point of view:

- if a frame is delivered on the first attempt with no local queue wait, transmit delay tends to stay close to one-way path plus normal sender/receiver scheduling cost
- if the sender had to pre-buffer because the in-flight window was full, that local queue wait is included
- if a frame requires retransmission, the metric grows because the first-attempt timing reference is preserved

That behavior is deliberate. The metric answers:

- "how long did this stream range effectively take to get through the tunnel and become acknowledged?"

not:

- "what was the propagation delay of the last successful wire attempt?"

For operator observability that is usually the more useful number, because it rises under:

- congestion
- scheduler delay
- retransmission pressure
- ACK/recovery inefficiency

RTT and transmit delay should therefore be read together:

- RTT: transport round-trip responsiveness based on the frame that actually went onto the wire
- transmit delay: effective one-way stream-chunk delivery delay, including sender-side pre-buffering and retransmission cost

The key consistency rule between the two metrics is:

- `tx_ns` in the protocol envelope must always reflect the actual emission time of that specific wire image, both for the first send and for every retransmission
- transmit-delay bookkeeping may preserve older first-attempt or queue-entry timing locally, but that local bookkeeping must never replace the on-wire `tx_ns` used for RTT

## Missing metadata and stale raw frames

The sender keeps two different representations of an in-flight stream chunk:

- semantic resend metadata in `send_meta`
- the last serialized raw bytes in `send_buf`

The semantic metadata is the authoritative source for retransmission because it lets the runtime rebuild a fresh frame.

The last raw bytes in `send_buf` are only a record of the most recent send image. They are not safe to replay as a fallback for RTT-correct retransmission.

Current design rule:

- if `send_meta[counter]` is missing, the transport skips retransmission for that counter instead of replaying the stale raw datagram from `send_buf[counter]`

That is a deliberate fail-safe:

- skipping one retransmit is preferable to polluting RTT and transport-debug signals with forged stale send timing
- a missing `send_meta` entry is itself diagnostic information and should be logged rather than hidden by a misleading raw resend

## Persistent Missing-Frame Retry

The current transport now distinguishes between:

- generic unconfirmed send state
- peer-reported missing counters

Generic unconfirmed state still matters for broad reliability, but peer-reported gaps need stronger handling because they are already known to be blocking forward progress somewhere on the far side.

Current design rule:

- once the peer reports a counter as missing, that counter enters a persistent missing set
- while it remains unconfirmed, the sender schedules another resend on roughly an RTT cadence
- the sender does not clear that obligation merely because a later `CONTROL` packet omits the counter
- the obligation is cleared only by real sender-side confirmation, primarily cumulative ACK progress that moves `last_in_order` past the counter

This protects the protocol against a very practical failure mode:

- frame `5000` is missing
- the receiver keeps operating at the edge of the flight window and continues to report evolving loss feedback
- one or more `CONTROL` packets are themselves lost or incomplete in diagnostic terms
- without persistent retry state, the sender can stop focusing on the oldest blocking frame even though that frame was never actually acknowledged

The intended resend behavior for a reported gap is therefore:

1. The first missing report triggers immediate retransmission eligibility.
2. If the frame still is not cumulatively acknowledged, the sender retries it again after about one RTT.
3. This continues until the sender has positive confirmation that the frame is no longer outstanding.

This is intentionally more robust than “resend only when the newest feedback still mentions the same counter”.

## Receiver gap tracking

The receiver maintains:

- `expected`
- `pending`
- `missing`

Behavior:

- an in-order stream chunk advances `expected` and releases its bytes upward
- an ahead-of-expected chunk is parked in `pending`
- skipped counters are inserted into `missing`
- when the missing chunk arrives later, delivery resumes and any contiguous pending chunks are drained into the byte stream

This state is what the sender sees indirectly through `CONTROL` feedback.

The retransmit path therefore depends on two contracts holding at once:

1. The receiver must report the correct missing counters.
2. The sender must rebuild fresh frames for those counters when retransmitting.

If either side is wrong, recovery may still appear to work at the payload layer while the RTT/debug picture becomes untrustworthy.

## Reset semantics

Sender reset and receiver gap tracking are intentionally separate concerns.

Resetting sender-side retransmission state should clear:

- queued/in-flight send bookkeeping
- resend attempt counters
- outstanding raw/send metadata

It should not silently rewrite receiver-side `expected`, `pending`, or `missing`
state unless the design is explicitly resetting the receive epoch too. A receive
epoch reset also clears the paired `StreamDeserializer` buffer: bytes from a
previous reliable stream must never be prefixed to a new transport epoch.

That separation matters because reconnect and recovery bugs often show up as a mixture of:

- stale sender retransmission state
- still-valid receiver gap state
- misleading logs that make the two look equivalent

## Testing guidance

The missing-doc case that triggered this note is a good example of where unit tests are the right tool.

The most important unit-level transport invariants are:

- retransmission must rebuild a fresh protocol envelope
- retransmitted frames for the same packet counter must differ on the wire from the original send image
- the retransmit path should produce a later `tx_ns` than the original send
- once receive history exists, retransmit should also carry a non-zero freshly computed `echo_ns`
- if semantic resend metadata is missing, the runtime should skip stale raw-frame replay
- once a counter has been reported missing, later omission from feedback must not silently clear the resend obligation
- a peer-reported missing counter should continue to be retransmitted on an RTT cadence until cumulative ACK state confirms it
- acknowledged stream chunks should produce a transmit-delay sample from first-send time minus half the current RTT
- the averaged transmit-delay metric should become observable through the runtime status/dashboard path
- tests should cover operation near the in-flight window limit so head-of-line recovery is validated under pressure, not only in tiny toy sequences
- a batch must deliver multiple chunk records as one UDP datagram without changing per-counter ACK or loss behavior
- a serializer record must decode correctly when split across arbitrary chunk and datagram boundaries, including a split at every byte of its length prefix
- one chunk may carry bytes from adjacent serializer records, and the deserializer must emit the original records in order
- malformed or oversized serializer records must fail the affected stream/epoch without leaking partial bytes to SecureLink, Compression, or ChannelMux
- Python and Swift codecs must produce and accept the same batch bytes and serializer-record bytes

Those checks are stronger than an end-to-end “payload still arrived” integration result, because payload delivery can succeed even while the RTT signal is already corrupted.

The current focused regression anchor for these invariants is [tests/unit/test_requirements_unit_gaps.py](../tests/unit/test_requirements_unit_gaps.py).

## myUDP2 delivery status and work packages

The myUDP2 wire change is not eligible for a distributed-network deployment
until the remaining work packages are complete. There is no runtime
wire-format fallback between Python and Swift.

### Stream serializer boundary

Each peer has a bounded `StreamSerializer` and `StreamDeserializer` immediately
above myUDP2. Outbound upper-layer writes are four-byte length-prefixed records;
contiguous inbound stream bytes recreate those complete records, including empty
records and every split point in the prefix. Oversized or malformed records fail
the affected stream/epoch without releasing partial bytes upward, and an epoch
reset clears deserializer bytes together with reliable receive state.

### Python stream chunks and batching

The Python myudp runtime carries opaque stream chunks in `DATA_BATCH` payloads;
the live UDP client and listener do not emit or accept `FRAME_FIRST`/
`FRAME_CONT` application payload framing. The batch scheduler coalesces queued
stream records, uses remaining batch budget for a smaller final chunk, and
never splits an encoded chunk across datagrams. Receive processing advances
strictly by chunk counter and passes contiguous bytes directly to the stream
deserializer, so upper-layer message boundaries are not a transport concern.

ACK, missing feedback, persistent retry, fresh timestamp rebuild, and
transmit-delay accounting remain per chunk. A lost multi-chunk datagram is
recovered as separately rebuilt one-chunk retransmit batches. `IDLE` and
`CONTROL` keep their independent unbatched path. Transport metrics and
peer-status payloads include DATA_BATCH datagram/chunk totals and malformed
batch totals. Focused tests cover parser rejection, reorder, duplicate
suppression, lost multi-chunk batch recovery, counter rollover, batch budget,
and serializer reset.

The retained `Session` frame helper exists only for isolated historical tests;
it is not selected by either live UDP runtime role. The shared Swift port uses
the same wire contract, with no compatibility fallback.

### Upper-layer budgets and diagnostics

`get_stream_record_limit()` is the upper-layer session contract. ChannelMux uses
it for TCP read sizing and UDP/TUN fragment decisions; Compression forwards the
limit unchanged; SecureLink reduces it by its protected-frame header and AEAD
tag before data reaches myUDP2. This keeps ChannelMux service semantics stable
while allowing a record to span any number of chunks and batches.

The myUDP status payload exposes `myudp.budget` with the stream-record, chunk,
batch, and queue budgets. Its live diagnostics distinguish batch datagrams,
chunks, stream bytes, queued stream bytes and age, retransmitted chunks,
malformed batches, and malformed stream records. SecureLink and Compression
therefore receive only completed stream records and retain their existing
authentication, rekey, and decompression contracts.

The Swift peer runtime publishes the corresponding batch, chunk, stream-byte,
retry, malformed-batch, and malformed-stream counters; platform release
qualification remains separate from this implementation contract. Its owner
queues a same-turn burst before its serial-queue flush, so small records share a
DATA_BATCH without delaying control or retransmission datagrams. Shared-source
Swift probes and matching Python unit tests cover frozen encoding/decoding,
burst coalescing, reordered delivery, missing-chunk retry, malformed-batch
rejection, epoch reset, send-window release, and counter rollover.

The retired message-fragment wire grammar is not part of the myUDP runtime or
its exported API. DATA_BATCH stream chunks are the sole reliable-data contract;
the maintained Python and Swift batch/stream probes replace former
frame/reassembly checks.

### WP7: Extend Python E2E qualification

Extend [test_overlay_e2e.py](../tests/integration/test_overlay_e2e.py) rather
than creating an unrepresentative synthetic-only gate. Add myUDP2 cases for
small-record coalescing, final-chunk splitting, records crossing chunk and batch
boundaries, secure-link plus compression, bidirectional concurrency, listener
multi-peer traffic, IPv4/IPv6, and deterministic loss/reorder/duplicate faults.

Definition of Done:

- The complete existing Python myUDP delay/loss matrix still passes, including
  control loss, persistent gaps, large transfers, and missed-list pressure.
- New cases prove the intended batching behavior from observed UDP datagrams and
  prove byte-for-byte upper-layer delivery.
- New cases inject loss of a multi-record batch and show recovery of every
  affected counter without duplicate upper-layer records.
- SecureLink and Compression E2E cases pass with records split at arbitrary
  stream boundaries.
- Listener and concurrent-channel E2E cases show independent peers do not share
  serializer, counter, or reassembly state.
- Each new E2E fault case emits a sanitized PCAP/PCAPNG fixture and an expected
  Wireshark decode summary, so capture analysis is repeatable rather than a
  manual interpretation of opaque UDP bytes.

### WP8: Mixed-runtime and distributed-network release gate

Run the expanded Python E2E suite in all-Python mode and in both existing mixed
directions: Swift server/Python client and Python server/Swift client. Then run
the same release candidate against separate network hosts, not only loopback,
with captured transport diagnostics and packet traces.

Definition of Done:

- All WP7 E2E cases pass in all-Python and both mixed-runtime directions with no
  retries, skipped cases, or expected failures.
- macOS and iOS native builds, focused native probes, and Python/Swift parity
  guards pass from the release candidate commit.
- Distributed-host runs cover IPv4 and IPv6 where available, NAT/peer learning,
  SecureLink plus Compression, bidirectional concurrent traffic, and induced
  loss/reorder/duplicate conditions.
- Captured diagnostics show no malformed batch or serializer-stream errors, no
  stuck missing counters, no cross-epoch byte delivery, and bounded batching delay.
- The release artifact includes the versioned Wireshark Lua dissector, analysis
  profile, Decode As port mapping, display-filter reference, and sanitized
  PCAP/PCAPNG samples for normal batching, loss/retransmission, reorder, and
  malformed-batch rejection.
- Wireshark and `tshark` decode the release-candidate captures with the expected
  batch/chunk/counter fields; the generated summary agrees with the E2E runtime
  counters and does not expose decoded SecureLink or ChannelMux payload bytes.
- Requirements and README guards pass against the release branch base, and the
  test report identifies the exact commit, runtimes, hosts, network conditions,
  commands, and artifacts.

No production or externally distributed-network rollout is permitted before
WP8 is complete. A successful local build, a manual device connection, or a
single happy-path transfer is not an alternative to this E2E gate.
