# StatsBoard Design

## Purpose

`StatsBoard` is the Python runtime's in-memory status aggregator. It does not
render a terminal dashboard and it does not write per-event trace records.
Its job is to keep the bounded aggregate fields consumed by WebAdmin current:
traffic totals and rates, aggregate open-channel counts, selected overlay
metrics, connection state, and myUDP retransmission totals.

`StatsBoard` is deliberately a process-level summary. It is not the owner of
per-peer or per-transport diagnostic detail. Those details remain available
from the Runner's connection and peer snapshot builders.

## Ownership and lifecycle

`Runner` creates exactly one `StatsBoard` for each runtime process. After it
creates every configured overlay session and its corresponding `ChannelMux`, it
wires the board and starts one sampling task:

```text
Runner
  ├─ overlay session: myudp ──┐
  ├─ overlay session: ws    ──┼─ peer-byte callbacks ──> StatsBoard totals
  ├─ ChannelMux: myudp      ──┼─ local-byte callbacks ─> StatsBoard totals
  └─ ChannelMux: ws         ──┘
                                every second
                                  └─> rate samples + status snapshot
```

Shutdown cancels that task before the sessions and muxes stop. The board keeps
no sockets, transport tasks, peer queues, or payload data; it stores scalar
counters, a few endpoint/state values, and references used to read snapshots.

## Data sources

### Traffic totals and rates

Each configured overlay session calls `on_peer_rx_bytes` and
`on_peer_tx_bytes`. Every `ChannelMux` is constructed with `on_local_rx_bytes`
and `on_local_tx_bytes`, which call `on_app_rx_bytes` and `on_app_tx_bytes`.
The board adds those values to process-wide totals. Its single one-second task
calculates kB/s from each total's delta and retains the latest rate until the
next sample.

The names describe the bridge direction rather than a client/server role:

| Board field | Source direction |
| --- | --- |
| `traffic.app.rx_*` | local application/interface to the overlay peer |
| `traffic.app.tx_*` | overlay peer to the local application/interface |
| `traffic.peer.rx_*` / `traffic.peer.tx_*` | bytes reported by the overlay session |

Consequently, board traffic is a sum across all configured transports and all
peers handled by those sessions. It is suitable for a process-wide headline,
not for assigning bytes to one client.

### Channel counts

The board receives a `RunnerMuxAggregate`, which sums `udp_open_count`,
`tcp_open_count`, and `tun_open_count` across every `ChannelMux`. A mux counts
its active UDP channels, TCP channels, and distinct active TUN devices. This
makes `open_connections` an aggregate over all overlay protocols and all
connected peers.

### Connection and transport metrics

The Runner binds the board to the first configured overlay session
(`self._sessions[0]`). Its generic `SessionMetrics` provides the top-level RTT,
transmit-delay, queue, ACK, batching, and stream error fields. If that first
session is myUDP, the board also retains its inner myUDP session for
retransmission histogram data and its peer protocol reference.

Runner lifecycle callbacks calculate whether any configured session is
application-ready and pass that result to `on_state_change`. The board also
checks its bound session once per sample, so the headline status is principally
the first configured session's status between lifecycle updates.

This is an intentional current boundary: the top-level `transport` object is
not a reduction of RTT, ACK, or loss metrics from multiple transports, and it
does not select a server-side peer. Consumers that need transport- or
peer-specific values use the peer and connection projections described below.

## Client topology: one connection

For a typical client with one active overlay, all board sources describe that
single session and its mux channels:

```text
local TCP/UDP/TUN service
       │ ChannelMux local callbacks
       ▼
  StatsBoard traffic + rates ────────────> WebAdmin /api/status
       ▲
       │ overlay session callbacks and SessionMetrics
myUDP, WebSocket, TCP, or QUIC session
```

The board's endpoint, state, transport metrics, retransmission histogram (for
myUDP), and channel counts therefore refer to the same connection, subject to
the one-second rate sampling interval.

## Server topology: many peers and transports

A listener can serve several peers through one myUDP listener and can run more
than one overlay protocol at the same time, for example `myudp,ws`. Each
protocol has its own session and mux; a myUDP session can in turn own many
peer/channel mappings.

```text
myUDP listener ─ peer A ─┐
               ├ peer B ─┼─> myUDP ChannelMux ─┐
               └ peer C ─┘                     │
                                                 ├─> RunnerMuxAggregate ─> StatsBoard counts
WebSocket listener ─ peer D ─> WS ChannelMux ───┘
          \____________________________________> StatsBoard traffic totals
```

In this topology, the board's traffic and open-channel fields include every
peer and every configured protocol. It does not merge peer identities into a
single artificial peer and it does not expose a combined RTT or retransmit
value. The first configured session remains the source for the board's
top-level transport fields. This avoids inventing a mathematically misleading
latency or loss value across unrelated paths.

WebAdmin presents the complementary detail through these Runner-owned sources:

- `/api/connections` and the `connections` live topic use the aggregate mux
  connection snapshot, retaining rows from every mux and peer.
- `/api/peers` and the `peers` live topic use per-session/per-peer runtime
  snapshots, including protocol and connection identity.
- `/api/status` and the `status` live topic use `StatsBoard.snapshot_status()`
  as their aggregate transport/traffic base, then the Runner adds all session
  `connection_layers`, secure-link/compression summaries, and other bounded
  runtime state.

## Data sinks

The direct sink is `Runner.get_status_snapshot()`. `AdminWebUI` reads that
snapshot for `GET /api/status` and for the `status` live topic, normally at a
one-second topic interval. The status builder removes aggregate connection and
traffic fields when it prepares the browser status payload because dedicated
connection and peer topics own those richer projections; the board remains the
authoritative bounded source used by the Runner's status construction.

The board has no log sink: counter updates and snapshot construction must not
emit `stats_board` records into the WebAdmin trace ring. Runtime Analysis uses
the separate bounded runtime-metrics accumulator and is not fed by
`StatsBoard` debug logging.

## Operational properties and limits

- Counters are monotonic for one process lifetime and reset on process restart.
- Rates are last-interval values, sampled once per second; they are not packet
  timestamps or a rolling percentile.
- The board intentionally stores no payloads, peer names beyond its configured
  endpoint display, or unbounded event history.
- For multi-transport/multi-peer diagnosis, start with WebAdmin peer and
  connection views rather than interpreting the board's headline transport
  metrics as an aggregate quality score.
