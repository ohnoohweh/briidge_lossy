# macOS Swift Buffer Ownership Inventory

## Scope

macOS shares the Core and Apple-shared transport owners with iOS. Their
ChannelMux, SecureLink, MyUDP, overlay, WebAdmin, proxy, and bounded send
contracts are defined in [the iOS inventory](IOS_MEMORY_BUFFER_INVENTORY.md).
This document records macOS-only payload owners.

| Owner | Retain boundary | Release boundary | Bound |
| --- | --- | --- | --- |
| Worker IPC stream decoder | `ObstacleBridgeWorkerIPCStreamDecoder.append` retains partial Unix-socket/pipe bytes. | Complete frames are decoded and removed; an over-limit append clears the buffer and throws. | At most two maximum protocol frames, including headers. |
| Native peer/admin bootstrap reads | `readExactly` accumulates a protocol-declared header or frame body. | Return to the caller or throw on malformed/closed/deadline-limited input. | Worker IPC frame-size validation caps the body at 1 MiB; control bootstrap applies its smaller control limit. |
| Native log/proxy worker control reads | Supervisor read helpers allocate exactly the validated header/body length. | Returned frame ownership transfers to the request handler; descriptor/worker stop drops local state. | Validated Worker IPC maximum frame size and request deadline. |
| Host-runner diagnostic log tail | Tail construction reads only the configured bounded tail window. | Result is projected into a response and released after the request. | Managed diagnostic log rotation and tail limits. |

## Contract

Persistent desktop payload owners must use `ObstacleBridgeBoundedDataFIFO`, a
byte-capped protocol buffer, or a validated fixed-size read. Network.framework
senders use one in-flight write plus a bounded pending owner queue. A new raw
persistent `Data` queue requires an explicit source-guard rationale, bounds,
and test. The Worker IPC stream decoder regression deliberately overfills the
decoder and proves both rejection and retained-byte release.
