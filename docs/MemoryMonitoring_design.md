# Memory Monitoring Design

## Status

Python products now publish bounded process-memory monitoring through
`runtime_metrics.memory_bytes`. Linux Python reads current RSS from
`/proc/self/status` `VmRSS`; unsupported Python platforms publish the stable
unavailable shape. The `--memory-warning-limit-bytes` option supplies an
optional process-local warning threshold, and WebAdmin renders the result.

Swift products publish the same object through their existing cached status
projection. Linux Swift reads current RSS from `/proc/self/status` `VmRSS`;
macOS and iOS read current resident memory through Mach task information. No
WebAdmin change is required because the field schema matches the Python one.

## Purpose

Memory monitoring lets an operator distinguish an overloaded host from a
process whose resident footprint is growing, and gives a support bundle a
small, redacted fact set for diagnosing memory pressure. It must work for the
Python runtime and all native Swift products (Linux, macOS, and iOS) without
placing allocation tracking, filesystem I/O, or unbounded history on the
packet-forwarding path.

The feature answers these operational questions:

- How much physical memory is the ObstacleBridge process using now?
- What is the largest observed process footprint for this runtime lifetime?
- Did memory peak recently, while the operator was investigating an event?
- Is the process near an explicitly configured, process-local warning limit?

It does not attempt to attribute memory to a peer, packet, request, callback,
or source file. Such attribution is expensive, platform-specific, and can
retain sensitive operational detail.

## Product Contract

Every runtime status payload publishes the additive `memory_bytes` object
inside `runtime_metrics`:

```json
{
  "memory_bytes": {
    "current": 52428800,
    "overall_peak": 65011712,
    "last_2_seconds_peak": 54525952,
    "warning_limit": 134217728,
    "warning_active": false,
    "measurement_kind": "resident"
  }
}
```

All byte values are non-negative integers or `null`. `warning_limit` is
`null` when no limit is configured; `warning_active` is then `false`.
`measurement_kind` identifies the normalized meaning of `current` and must be
either `resident`, `physical_footprint`, or `unavailable`.

An unavailable platform or a denied system API returns a stable, redacted
shape instead of an error:

```json
{
  "memory_bytes": {
    "current": null,
    "overall_peak": null,
    "last_2_seconds_peak": null,
    "warning_limit": null,
    "warning_active": false,
    "measurement_kind": "unavailable"
  }
}
```

The status projection contains aggregate process values only. It never
includes paths, environment values, allocations, heap objects, peer identity,
or an operating-system error string. Existing consumers must continue to work
when the field is absent while older products are being upgraded.

## Measurement Semantics

`current` is a point-in-time, process-local measurement. It is not container
memory, host memory, memory available to the operating system, or the summed
memory of child processes. `overall_peak` is the largest successful `current`
sample since process start. `last_2_seconds_peak` is the maximum of successful
samples whose completion time is within the trailing two seconds.

The metrics use binary bytes and the UI displays IEC units (KiB, MiB, GiB).
No rate is inferred from two samples: consumers may calculate a trend outside
the runtime if needed, but the runtime should retain only the bounded current
and peak state.

`resident` means resident physical pages attributable to the process where
the platform can provide that value. Apple platforms may use
`physical_footprint` when it is available and appropriate; the current macOS
and iOS collectors use the Mach resident-size value and label it `resident`.
Comparisons are valid within a product and platform; dashboards must label the
measurement kind rather than imply that resident bytes and physical footprint
are identical.

## Sampling and Retention

Memory sampling uses the existing low-frequency runtime monitor cadence: once
per second, after the CPU sample. It runs in the monitor/background status
publisher, never in a forwarding callback. A sample must have bounded,
constant-size work and must not trigger garbage collection, allocation
profiling, heap walking, subprocess execution, or network I/O.

The monitor retains:

- the latest successful value;
- one lifetime maximum;
- a fixed two-second window containing at most the monitor's recent samples;
- the configured warning limit and current boolean state.

Failed reads leave the latest successful aggregate unchanged, record no raw
error in the public status response, and do not interrupt forwarding. A
runtime with no successful sample reports the unavailable shape. Implementations
may emit a rate-limited local diagnostic event that names only the collector
and error class.

## Python Runtime

The Python `Runner` monitor task samples memory alongside process CPU and
event-loop lag, then folds its bounded projection into
`_runtime_metrics_status_fields()`. The sampler and aggregate model are
injectable for deterministic tests.

On Linux, the sampler obtains current RSS from `/proc/self/status` `VmRSS`,
normalizes KiB to bytes, and handles a read/parse failure as unavailable.
`resource.getrusage(...).ru_maxrss` is not used: it is a high-water value
rather than current memory and its units vary by platform.

On macOS Python deployments, the current implementation reports
`unavailable`; it does not shell out to tools such as `ps`. A future supported
adapter may report `measurement_kind: "resident"` only when it truly returns
current resident bytes.

The sampler must be dependency-free. Adding a general process-inspection
library solely for this metric is not justified, because it expands the
runtime/package surface and may behave differently in restricted deployments.

## Swift Products

Shared Swift Core owns the schema, bounded peak bookkeeping, and snapshot
projection alongside `ObstacleBridgeRuntimeMetrics`. Narrow platform samplers
supply timestamped byte measurements to that Core actor, keeping one status
vocabulary for Linux, macOS, and iOS while leaving operating-system APIs at the
appropriate platform boundary.

- **Swift Linux:** reads current process RSS from `/proc/self/status` `VmRSS`,
  normalizes KiB to bytes, and reports `resident`.
- **Swift macOS:** obtains Mach task basic information and reports its current
  `resident_size` as `resident`.
- **Swift iOS / Network Extension:** obtains the same permitted Mach measure
  for the extension process. The foreground app and packet-tunnel extension
  are separate processes: each status endpoint reports only its own process,
  never their sum.

Swift status owners refresh the metric through their existing asynchronous
snapshot cache. Admin HTTP and WebSocket reads return that cached projection;
they do not synchronously call Mach or proc interfaces during a request.

## Configuration and Warning Behavior

Python exposes a read-only `warning_limit` supplied by the local
`--memory-warning-limit-bytes` runtime configuration in bytes. The default is
disabled (`null`). Limits apply to the process reporting the metric, not to a
device, cgroup, container, or combined application/extension budget. Swift
currently publishes the same disabled API state (`warning_limit: null`,
`warning_active: false`); a Swift configuration surface for a warning limit is
intentionally not introduced by this monitoring slice.

`warning_active` is true when a successful current reading is greater than or
equal to the configured limit. A crossing may add a rate-limited, redacted
runtime-health or local-log event containing the measurement kind and rounded
byte value. It must not automatically restart the bridge, terminate the
process, alter packet forwarding, or upload telemetry. Any remediation policy
needs a separate explicit design because process termination is particularly
unsafe for active tunnel traffic.

## WebAdmin Presentation

Runtime Analysis displays a compact Python Memory section beside CPU:

- Current process memory, labelled RSS or physical footprint.
- Peak since process start and peak over the last two seconds.
- Configured warning limit and a visible warning state when active.
- `Unavailable` when the product cannot obtain a measurement.

The screen must not turn byte values into a percentage unless it also has a
clearly defined process-local limit. It must not present a physical-footprint
reading as RSS, nor compare it directly to host RAM. Live status and the full
status response use the same projection so page refreshes cannot erase the
memory rows.

## Privacy, Reliability, and Performance Boundaries

- Only aggregate byte counts and a fixed vocabulary reach WebAdmin, logs, or
  telemetry.
- No memory maps, heap snapshots, object names, packet buffers, paths, or peer
  identifiers are collected.
- Sampling is fixed cadence and constant retention; sustained traffic cannot
  increase its memory use.
- A sampler failure is non-fatal and represented as unavailable, not as an
  admin endpoint failure.
- A memory warning is observational by default and cannot change routing or
  cryptographic behavior.

## Parity and Test Plan

The Python and Swift payloads must have identical keys, nullability, units,
warning semantics, and trailing-window semantics. Platform-specific
measurement kinds are permitted only as described above.

Tests should cover:

1. Deterministic Python sampler success, unavailable, malformed-source, peak,
   trailing-window expiry, and threshold transitions.
2. Equivalent Swift Core actor tests using injected samples and deterministic
   timestamps.
3. Status-schema and WebAdmin rendering tests for `resident`,
   `physical_footprint`, unavailable, and warning states.
4. Linux, macOS, and iOS smoke probes proving that the product status endpoint
   can return a bounded memory projection without blocking packet processing.
5. Cross-runtime parity tests comparing normalized payload shape and peak
   behavior, rather than asserting that two different processes consume the
   same number of bytes.

## Delivery Status

The delivered Python slice covers the bounded aggregate model, Linux sampler,
status projection, WebAdmin rendering, configuration parsing, and deterministic
tests. The delivered Swift slice adds the same Core schema and bounded model,
Linux and Apple samplers, cached status projection, and deterministic Core
parity tests. Packaged macOS and iOS device qualification remains a release
validation activity; Swift warning-limit configuration is a separate future
configuration feature.
