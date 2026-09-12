# Linux Swift Source Map

## Purpose and authority

This is the LSW-R001 source-ownership baseline for the common Swift migration.
The machine-readable authority is
[LinuxSwift_r001_inventory.json](./LinuxSwift_r001_inventory.json). It assigns
every checked-in Swift file under these source roots exactly once:

- `swift/Sources/ObstacleBridgePortable`;
- `swift/Sources/ObstacleBridgeLinuxAdapters`; and
- `ios/native/ObstacleBridgeShared`.

Run the verifier from the repository root:

```bash
./.venv/bin/python scripts/check_linux_swift_r001_inventory.py
./.venv/bin/python scripts/check_linux_swift_r001_inventory.py --report
```

The first command fails when a source is unassigned, assigned more than once,
or removed without updating the inventory. The report expands the feature
baseline to one Linux Swift status row for every active requirement. It is the
authoritative answer to whether a feature is `verified`, `partial`, `missing`,
or product-scoped `not-applicable`; it is not a claim that current Linux Swift
behavior is in parity.

## Source ownership

| Target owner | Disposition | Files | Meaning |
| --- | --- | ---: | --- |
| `ObstacleBridgeCore` | `extract` | 28 | Move platform-neutral values, codecs, state machines, models, and orchestration out of the flat Apple source bucket and Linux adapter target. |
| `ObstacleBridgeCore` | `split-contract` | 18 | Preserve behavior in core while moving crypto providers, compression backends, OS networking, packet devices, resolver calls, and Admin HTTP mechanics below explicit contracts. |
| `ObstacleBridgeAppleAdapters` | `retain-or-split` | 11 | Keep `Network`, Network Extension, Darwin TUN, XPC, ServiceManagement, Security, and Objective-C bridge mechanisms Apple-specific. |
| `ObstacleBridgeLinuxAdapters` | `retain-or-thin` | 6 | Keep POSIX descriptors, listener/server I/O, timers, and Linux HTTP serving; remove common protocol policy as its core owner lands. |
| `ObstacleBridgeCore` | `delete-after-migration` | 1 | Retire the reduced portable myUDP codec when the Python-complete common myUDP engine replaces it. |

The checked inventory currently contains 64 Swift files. Its file-level entries
are intentionally exact rather than glob-based, so a new source file is a
failing ownership decision instead of silently becoming portable or Linux-only.

## Python-led feature baseline

The same inventory contains the LSW-R001 feature groups. Every active
`REQ-*` identifier is assigned once to a group with:

- Python implementation and test references;
- current Swift implementation and test references when any exist;
- direct Python-versus-Swift evidence where it exists; and
- an explicit Linux Swift applicability, status, and gap reason.

The Linux Python runtime is the normative behavior reference. Apple Swift may
be extraction material, and current Linux Swift probes are evidence for their
named scenarios, but neither can override Python behavior or fill an unmapped
row.

The baseline deliberately records Linux Swift as partial or missing for most
Linux-applicable feature groups. In particular, it exposes the missing Linux
QUIC backend and the incomplete myUDP reliability, WebSocket, SecureLink,
ChannelMux/TUN, lifecycle/listener, and Admin/configuration surfaces. The four
`not-applicable` groups are scoped by their requirements to Python packaging,
Windows proxy behavior, iOS proxy-provider behavior, or iOS packet flow; they
are not generic Linux feature waivers.

## Frozen Python decisions

Before a duplicated Swift implementation is removed, its behavior must match
the Python result for the following already-observed differences:

| Area | Python decision | Current Swift gap |
| --- | --- | --- |
| myUDP trailing bytes | Accept a declared frame and let the caller retain outer trailing bytes. | The portable Linux decoder requires exact outer length. |
| myUDP CONTROL missing list | Derive the bounded list capacity from the wire payload budget. | The portable Linux codec hard-caps the list at 64 entries. |
| myUDP ring boundary | Use Python half-ring comparison semantics. | The Linux transport differs at distance 32767. |
| Canonical JSON | Preserve Python protocol byte ordering. | Linux service/catalog serialization relies on generic sorted keys. |

New observed drift belongs in this table and in a reproducing direct parity test
before it is fixed. A successful source guard, compilation, or mixed-runtime
smoke test does not resolve a frozen decision.

## LSW-R001 accepted baseline boundary

The executable baseline is accepted, not functional parity. The Linux SwiftPM
myUDP Python-peer fixture suite passes with
the required stream-record envelopes and independent transport counters. The
raw Apple ChannelMux parity runner imports `CryptoKit`, so its qualified
evidence host is the existing `bridge-py-integration-macos-swift-probe` CI job;
it must not be treated as a Linux pass or a skipped parity claim. R005 removes
that Apple-only crypto dependency.

Those baseline lanes pass in one revision on their qualified hosts. Later
packages close feature rows in this inventory; they must not relabel a partial
or missing row as verified without implementation and executable evidence.
