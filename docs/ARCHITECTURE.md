# Architecture

This document describes the main runtime components and how they contribute to the overall behavior of the project.

## Architectural layers

The system can be understood in five layers:

1. transport/session layer
2. reliability and framing layer
3. channel/service multiplexing layer
4. runner and process orchestration layer
5. admin web and observability layer

## Stable component IDs

The following component IDs are intended to stay stable so requirements, tests, and future design notes can point to architecture elements without depending on section wording.

| Component ID | Component | Primary scope |
|---|---|---|
| `ARC-CMP-001` | Transport and session layer | Transport-specific peer connectivity, listener/client state, and per-peer transport ownership |
| `ARC-CMP-002` | Reliability and framing layer | Reliable overlay framing, retransmission, RTT, inflight, and missed-frame tracking |
| `ARC-CMP-003` | Channel and service multiplexing layer | `own_servers`, `remote_servers`, channel routing, and peer-scoped service isolation |
| `ARC-CMP-004` | Runner and process orchestration layer | CLI/config composition, lifecycle wiring, restart/shutdown coordination, and process startup |
| `ARC-CMP-005` | Admin web and observability layer | HTTP API/UI, auth/session control, runtime snapshots, logs, and operator visibility |

## 1. Transport and session layer

Primary responsibility:

- establish peer-to-peer connectivity over `myudp`, `tcp`, `ws`, or `quic`

Main contribution:

- creates the underlying transport session
- owns peer connectivity state
- provides send/receive hooks into the higher framing layer

Important behaviors:

- single-peer client mode
- listener mode
- multi-peer listener behavior for transports that support multiple concurrent peer clients

Representative implementation area:

- [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)

## 2. Reliability and framing layer

Primary responsibility:

- turn raw transport datagrams or frames into reliable overlay behavior

Main contribution:

- DATA and CONTROL framing
- retransmission
- missed-frame tracking
- RTT and inflight tracking

Important behaviors:

- cope with delay and loss on `myudp`
- keep counters and state needed for admin visibility
- preserve message integrity for large payloads

This layer is especially important for the `myudp` requirements in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md).

## 3. Channel and service multiplexing layer

Primary responsibility:

- map overlay traffic to exposed TCP/UDP services

Main contribution:

- `own_servers` handling
- `remote_servers` handling
- per-channel open/data/close behavior
- per-peer service scoping

Important behaviors:

- multiple concurrent TCP channels on one peer
- mixed UDP and TCP services on one peer
- per-peer isolation in listener mode
- cleanup on disconnect

This is the main realization layer for listener and mixed-service requirements.

## 4. Runner and process orchestration layer

Primary responsibility:

- compose the configured transports, mux, and admin systems into one runnable process

Main contribution:

- reads configuration and CLI arguments
- starts the right transport sessions
- wires callbacks and lifecycle events
- coordinates shutdown and restart behavior

Important behaviors:

- reconnect support
- restart handling
- process-safe event binding
- configuration persistence

## 5. Admin web and observability layer

Primary responsibility:

- make runtime state observable and manageable

Main contribution:

- health/status/peers/connections APIs
- configuration API and UI
- debug logs and log retrieval
- authentication and session control

Important behaviors:

- show connected peers and listener state
- show per-connection and aggregate transfer state
- isolate authenticated sessions per client
- support troubleshooting and regression validation

## Component responsibilities

### Transport runtimes

Expected to own:

- transport-specific sockets/connections
- connect/listen behavior
- per-peer transport state where required

Expected not to own:

- service publication logic
- application protocol semantics

### Reliability/session logic

Expected to own:

- frame numbering
- missed-frame tracking
- retransmission decisions
- RTT and inflight metrics

Expected not to own:

- UI concerns
- service binding policy

### ChannelMux and related service machinery

Expected to own:

- mapping between overlay channels and local TCP/UDP services
- peer-scoped remote service state
- listener lifecycle for published services

Expected not to own:

- transport-specific socket semantics beyond the abstraction it consumes

### Runner

Expected to own:

- composition
- startup/shutdown lifecycle
- config and argument integration

Expected not to own:

- detailed transport framing policy
- detailed admin rendering logic

### Admin web

Expected to own:

- HTTP API
- auth session control
- presentation of runtime state

Expected not to own:

- transport behavior itself

## Test implications

This architecture implies a testing split:

- integration tests primarily defend requirements at the transport, listener, reconnect, and admin behavior level
- unit tests primarily defend component contracts such as ChannelMux scoping, snapshot formatting, runner event wiring, and websocket-specific behavior

The first traceability mappings for integration and unit coverage are maintained in [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md), and should refer to the stable component IDs above where architecture-level traceability is needed.
