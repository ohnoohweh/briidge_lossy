# Linux Swift Deviation Ledger

This document records only differences between the Linux native product,
applicable requirements, and the Python reference runtime. Delivered behavior
is specified and evidenced elsewhere; it is not repeated here. A work package
is removed from this ledger when its definition of done (DoD) is met and its
evidence is traceable.

## Requirement deviations

| Package | Requirement deviation | Definition of done |
| --- | --- | --- |
| `LSW-005` | Packet-device access has adapter evidence, but full privileged Linux TUN data-plane qualification is incomplete. | An authorized-host test proves `/dev/net/tun` ingress and egress across an authenticated ChannelMux peer, including epoch teardown, with no packet acceptance before readiness and no fallback to Python. |
| `LSW-006` | Native helper route, DNS, underlay-preservation, firewall, and teardown behavior lacks complete end-to-end kernel qualification with the native TUN data path. | An authorized-host test proves configured address, IPv4/IPv6 routes, peer exclusions, DNS, optional firewall, hook apply/remove, and clean recovery after interruption; it verifies traffic through the created TUN and leaves no helper-owned kernel state after controlled stop or recovery. |
| `LSW-TEL-001` | Local lifecycle logging and private bounded spool persistence are implemented, but Linux has no end-to-end collector qualification for its HTTPS/mTLS delivery path. | A Linux client with generated credentials delivers ordered batches to the reference HTTPS collector, retries a rejected/unavailable collector without blocking runtime callbacks, acknowledges only accepted ranges, and exposes only bounded/redacted delivery state. |
| `LSW-005B.2` | QUIC is limited to an outbound reliable-stream boundary. Listener ownership, custom trust-root interoperability, multi-candidate peer-family mapping, and reconnect/stale-completion qualification remain absent. The native client also cannot negotiate a supported TLS signature algorithm with the Python aioquic listener used by the interoperability harness, so cases 10--11 are excluded from the routine Linux-native matrix while remaining explicitly selectable for diagnosis. | The selected backend passes Python-peer interoperability for configured trust roots and multi-candidate IPv4/IPv6 family policy; safe listener ownership and authenticated ChannelMux service flow have integration evidence, or unsupported portions remain explicitly rejected with a documented product decision. |
| `LSW-PROXY-001` | Proxy support is limited to one HTTP CONNECT bootstrap. Proxy authentication challenges, proxy chains, and HTTP/2 proxy transport are unavailable. | Each supported advanced proxy mode has explicit configuration admission, credential redaction, failure diagnostics, and Python-peer integration coverage; modes intentionally not supported fail before connection with actionable diagnostics. |
| `LSW-PKG-001` | The Linux archive/installer has no repository metadata, automated upgrade, or privilege-provisioning path. | The supported packaging format declares artifact identity, upgrade/rollback behavior, unprivileged foreground and scoped-helper privilege provisioning, state/config ownership, and an install/upgrade/uninstall qualification test. |

## Python reference deviations

| Package | Difference from `python -m obstacle_bridge` | Definition of done |
| --- | --- | --- |
| `LSW-005` / `LSW-006` | Python has the established Linux TUN route/DNS lifecycle qualification; native Swift lacks equivalent full kernel packet-carry evidence. | Native Swift passes the same intent-level elevated qualification: authenticated packet carriage, routing/DNS policy, interruption recovery, and cleanup. |
| `LSW-TEL-001` | Python has reference collector/client integration evidence; Linux has only local spool and adapter-level acknowledgement evidence. | The Linux HTTPS/mTLS client completes the reference collector qualification without moving network I/O onto forwarding or packet callbacks. |
| `LSW-PROXY-001` | Python supports proxy behaviors outside Linux's single CONNECT bootstrap. | Linux supports the selected Python modes with equivalent redaction/failure semantics, or the requirements explicitly narrow the common product contract. |
| `LSW-R007.6` | Python has broader restart/lifecycle qualification. Linux still lacks common-path privileged-TUN restart evidence and can leave a bridge child after server shutdown. | Native shutdown and restart tests prove child reaping and controlled-stop records for normal and privileged-helper paths; authorized Linux, signed macOS, and physical iOS qualifications cover their applicable owners. |

## Architecture and qualification deviations

| Package | Deviation | Definition of done |
| --- | --- | --- |
| `LSW-SC.2L-F` | QUIC and WebSocket lack direct protected stale-completion qualification and complete owner-specific Core-effect translation evidence. The current QUIC SecureLink test stops below the SecureLink callback in lower packet parsing. | TCP, WebSocket, and QUIC each translate typed Core connect/send/receive/close/timer effects through their own owner; Python-peer tests prove reconnect, stale-completion rejection, cancellation, and epoch fencing for all three. |
| `LSW-SC.2L-G` | The Linux SC.2 composition cannot receive final full-overlay qualification while `LSW-SC.2L-F` remains open. | The Linux-host matrix covers Admin, service catalog, SecureLink, UDP, TCP, QUIC, and WebSocket callers against Python peers; the source inventory maps every admitted contract to caller and test. |
| `LSW-SC.3` | Apple resource adapters still need per-file dependency classification and an enforced repository boundary. | Every retained Apple file has a classification, the boundary is machine-checked, and no portable behavior remains in an Apple-only adapter. |
| `LSW-SC.4` | Transitional shims, flat Xcode references, and source inventory/traceability cleanup remain. | The inventory is the enforced ownership authority; transitional shims and obsolete references are removed, and CI rejects boundary regressions. |
| `LSW-R007.5` | Sustained-load and external-termination correlation evidence is absent on signed physical iPhone and released Linux hosts. | Authorized released-host and physical-device lanes publish bounded-load, termination, and retained-health evidence with clear environment qualifications. |
| `LSW-009` | The Darwin Swift helper cannot receive signed macOS real-`utun` packet-carry and route/DNS cleanup qualification from the Linux host. | A signed macOS lane proves helper packet carriage, route/DNS apply/remove, and cleanup; its result is tracked independently of Linux compilation. |

## Completion rule

Do not retain a completed work package in this document. Move its durable
contract and evidence to the relevant requirement, test guide, and source
inventory, then remove its row from this ledger.

## Linux native/Python overlay interoperability matrix

The `bridge-py-integration-gate` runs the same `test_overlay_e2e.py --mode
basic` catalog in `python-python` and
`python-server-linux-native-client` modes. The catalog is the supported
single-client, Python-listener boundary. Both modes run myUDP cases 01--05,
TCP cases 06--07, and WebSocket cases 08--09. Python/Python additionally runs
outbound QUIC cases 10--11. The Linux-native mode excludes those QUIC cases
until its client can negotiate a supported TLS signature algorithm with the
Python aioquic listener; explicit case selection remains available for focused
qualification. The selected cases cover IPv4 and IPv6 overlay endpoints plus
UDP and TCP application services without changing either product for the test
harness.

The localhost reconnect variants and the two-client/listener catalogs do not
run in this matrix. They require native restart, listener, or multi-peer
orchestration that the client-only runtime mode does not represent. They remain
separate work, rather than being treated as coverage supplied by this matrix.
