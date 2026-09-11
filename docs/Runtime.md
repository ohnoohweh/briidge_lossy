# Runtime Performance Investigation and Monitoring

This guide defines how to investigate, improve, and continuously monitor the
resource consumption of the ObstacleBridge runtimes. Its immediate focus is a
Python process on a Linux VPS that sometimes approaches `90%` CPU even when
application throughput looks low. The same measurement discipline should be
used for future Python and Swift work.

High CPU is a symptom, not a diagnosis. Low application byte throughput also
does not necessarily mean that the runtime is idle: keepalives, retransmits,
reconnects, rejected packets, TUN traffic, status snapshots, debug logging, or
many small packets can all consume CPU without moving many useful bytes. Do
not change protocol timing, reliability, or security behavior until a profile
identifies the work being performed.

A source audit performed while writing this guide found several concrete
scaling and lifecycle risks. The TCP backpressure task lifecycle issue found
in that audit is fixed; the remaining inspection targets are documented under
[Code-Specific Places to Inspect](#code-specific-places-to-inspect). They are
priority hypotheses for the reported VPS symptom, but a production profile is
still required to determine which one is active on that host.

Related project documents:

- [Architecture](ARCHITECTURE.md) describes runtime ownership and the launcher
  versus bridge-process boundary.
- [WebAdmin Design](WEBADMIN_DESIGN.md) documents the existing operational
  counters exposed through the admin APIs.
- [Compression Design](COMPRESSLAYER_DESIGN.md) describes the default-on
  compression layer and its counters.
- [Testing Guide](README_TESTING.md) contains the functional and integration
  test entry points that must remain green after an optimization.

## Interpret the CPU Number Correctly

On Linux, `top` normally reports `100%` as one fully occupied logical CPU. A
Python row at `90%` therefore usually means about `0.9` CPU cores, not
necessarily 90% of a multi-core VPS. Check the `top` mode, the VPS CPU count,
and any cgroup quota before comparing hosts. A brief `top` spike is also not a
baseline; use CPU time accumulated over a defined interval.

The normal command has two process roles:

1. `python -m obstacle_bridge` is the restart supervisor.
2. The supervisor launches a separate child containing `Runner`, the
   transports, ChannelMux, and WebAdmin.

The supervisor normally waits and consumes little CPU. Profile the busy child,
and monitor the whole service cgroup so that a child restart does not break the
time series. First inspect, then select the PID deliberately:

```bash
pgrep -af 'obstacle_bridge|ObstacleBridge'
pstree -ap
ps -eo pid,ppid,etimes,stat,pcpu,pmem,rss,nlwp,cmd --forest
```

The runtime child normally contains `from obstacle_bridge.bridge import main`
in its command line. There may be multiple legitimate instances, so do not
automatically choose the newest Python PID. Command lines and configuration
can contain secrets; redact them before attaching output to an issue.

Helper-backed TUN mode can also create a separate Python helper process.
Measure the main runtime and helper separately during diagnosis, while keeping
their combined cgroup consumption as the service-level result.

For a systemd-managed deployment, start at the service boundary. Replace the
example unit name with the deployed real unit:

```bash
bridge_service=obstaclebridge.service
systemctl status "$bridge_service"
systemctl show "$bridge_service" \
  -p MainPID -p ControlGroup -p CPUUsageNSec -p MemoryCurrent \
  -p TasksCurrent -p NRestarts
systemctl cat "$bridge_service"
systemd-cgtop
```

`MainPID` can be the supervisor rather than the hot child. The cgroup totals
are the better long-running service measurement because they include both and
survive child replacement.

## Establish a Reproducible Baseline

A useful result always states what was running. Record at least:

- Git commit/build identifier and whether the checkout was modified
- Python version, dependency lock or installed versions, and launch method
- kernel, distribution, VPS type, logical CPU count, and CPU quota
- overlay transport and client/listener role
- peer, service, open-channel, and TUN counts
- SecureLink, compression, WebAdmin, dashboard, and relevant logging settings
- whether a WebAdmin page or live API client was open
- test duration, warm-up duration, traffic rate, packet-size distribution,
  loss/reordering conditions, and number of repetitions
- host CPU pressure, especially VPS steal time

Never compare a one-minute disconnected retry loop on one host with a
connected-idle listener on another. Use an explicit scenario matrix:

| Scenario | Purpose |
| --- | --- |
| Disconnected idle | Measures DNS, connection attempts, backoff, authentication failure, and restart behavior. |
| Connected idle, WebAdmin closed | Establishes the transport/session timer floor. |
| Connected idle, WebAdmin open | Isolates live snapshot and browser subscription cost. |
| Listener with 0, 1, and many peers | Detects work that scales per peer. |
| Configured services with no channels | Detects service-health and TUN polling cost. |
| Repeated TCP open/close followed by idle | Detects per-channel task/resource leaks; CPU and task count must return to baseline. |
| Invalid myUDP datagrams from many source tuples | Verifies that pre-auth allocation, task count, and CPU remain bounded under scans or spoofed traffic. |
| Fixed packets/s with small payloads | Measures per-packet overhead that a bytes/s graph hides. |
| Fixed bytes/s with large payloads | Measures copying, encryption, and compression throughput. |
| Controlled loss and reordering | Measures acknowledgement, missing-frame, and retransmit work. |
| Each of `myudp`, `tcp`, `quic`, and `ws` | Keeps a transport-specific regression from being averaged away. |

For a first baseline, allow the bridge to warm up, measure for at least five
minutes, and repeat the same scenario at least three times. Longer captures
are appropriate for intermittent spikes. Report the median and range; keep raw
samples as CI or release artifacts.

The primary normalized CPU quantities are:

```text
average CPU cores = delta(process or cgroup CPU seconds) / delta(wall seconds)
CPU seconds per GiB = delta(CPU seconds) / delta(application bytes / 2^30)
```

The first works for idle and loaded runs. The second only makes sense when a
meaningful amount of application data moved. Also record packets/s, because
one byte rate can represent very different numbers of frames and callbacks.

## Fast VPS Triage

After confirming the runtime-child PID, collect a sustained process and thread
view. The `sysstat` package supplies `pidstat` and `mpstat` on common Linux
distributions.

For a non-systemd host, [`scripts/runtime_analysis.sh`](../scripts/runtime_analysis.sh)
performs this capture without guessing between multiple running bridge
children. It writes one timestamped report directory and deliberately excludes
process arguments/configuration, which can contain secrets:

```bash
./scripts/runtime_analysis.sh --samples 300
./scripts/runtime_analysis.sh --pid 12345 --samples 60 --output-dir /var/tmp/obstaclebridge-triage
```

Run it as the bridge service user where possible. It captures `pidstat`,
threaded batch `top`, `mpstat`, `vmstat`, CPU pressure, sockets, interface
counters, process I/O, deleted-open-file evidence, and global CPU-leader
snapshots in parallel. When `py-spy` is installed and allowed to attach, it
also writes a 120-second `py-spy-flamegraph.svg`; use this during a high-CPU
incident, or pass `--no-py-spy` for a shorter lightweight capture. It neither
uses systemd nor changes the running bridge. Socket and `lsof` visibility can
be reduced when run as a different user.

Unavailable optional commands are recorded in their respective report files;
the capture continues with the data the host can provide. The selected PID and
every descendant present at capture start are profiled. The report preserves
the start and end inventories in `process-tree-pids-{start,end}.txt`; a child
created after the start inventory is visible at the end but has no
retrospective timed samples. Tree-wide `pidstat` results are in
`pidstat-*-tree.txt`, and each initial PID has its own
`top-threads-pid<PID>.txt` plus status and I/O snapshots. The
`global-cpu-consumers-{start,end}.txt` files contain the host-wide equivalent of
`ps -eo pid,ppid,comm,%cpu,%mem --sort=-%cpu | head -20` for unrelated
contention.

### VPS capture findings — 2026-09-11

A five-minute, target-PID-only capture on a one-logical-CPU VPS showed
sustained but not 90% CPU consumption for the main Python child. These figures
describe that capture, not a universal baseline; preserve later report
directories so changes can be compared against the same duration and workload.

| Evidence from the 300-second capture | Finding | Interpretation |
| --- | --- | --- |
| Main Python process CPU time | About 102.8 CPU seconds, or 34.3% of one CPU; the leader thread was 25.5–37.3%. | The reported 90% peak did not occur during this interval. The bridge is nevertheless a material consumer on this small VPS. |
| Host scheduler and CPU pressure | Average runnable queue 8.3, CPU idle about 0.05%, and CPU PSI `some` about 97%. | The guest was severely CPU-contended. Attribute the incident to both bridge work and host-wide contention until a host-wide top-process view is captured. |
| Main-process memory | RSS stayed about 123–126 MiB; no swap was in use. | This capture does not show a growing resident-memory leak as the immediate cause. |
| Process context switching | Roughly 229 voluntary plus involuntary context switches per second between the two report starts. | Consistent with a timer/polling workload and CPU contention, but insufficient by itself to identify the loop. |
| Launcher output | An unlinked temporary capture file was open and had grown to about 2.1 MiB. | Redirected child stdout/stderr is accumulating while the launcher runs. It is a disk-retention issue, not an explanation for the measured CPU at this size. |
| Capture coverage | `pidstat`, `mpstat`, and `sar` were unavailable; a helper child was not profiled. | The report cannot split user/system CPU, establish per-process I/O or network rates, or give total bridge-plus-helper CPU. |

The source audit identified a high-priority churn-related CPU defect: ChannelMux
created a TCP backpressure polling task at channel creation and did not cancel
it on every teardown path. The runtime now creates that worker only after a
write leaves bytes buffered, exits it once the buffer is empty, and cancels it
idempotently on local EOF, remote `CLOSE`, peer reset, and shutdown. The VPS
report predates this fix, so compare a post-deployment capture with the same
TCP churn workload rather than assuming it explains every observed CPU spike.

For the next comparison capture, install `sysstat` and sample the main process
tree for at least 300 seconds. The script includes helper descendants present
at capture start and collects the host-wide CPU leaders alongside the report:

```bash
sudo apt-get update && sudo apt-get install -y sysstat
./scripts/runtime_analysis.sh --samples 300
```

Install `py-spy` where policy permits: the script writes its 120-second flame
graph automatically during a high-CPU run, or records why it could not attach.
Then compare an idle baseline, a controlled TCP connect/disconnect churn run,
and the post-churn idle state. A planned maintenance restart can establish a
temporary baseline, but it is not a fix; the regression test and explicit task
cancellation are the durable remedy.

```bash
bridge_pid=12345
ps -p "$bridge_pid" -o pid,ppid,etimes,stat,pcpu,pmem,rss,vsz,nlwp,cmd
pidstat -u -r -d -w -p "$bridge_pid" 1 300
pidstat -t -u -w -p "$bridge_pid" 1 60
top -H -p "$bridge_pid"
mpstat -P ALL 1
vmstat 1
cat /proc/pressure/cpu
lsof -p "$bridge_pid" +L1
```

Interpret the measurements together:

| Observation | Likely direction for the next check |
| --- | --- |
| High `%usr`, one hot thread | Python callbacks, parsing, snapshot building, compression, crypto orchestration, or a user-space loop. |
| High `%system` | Excessive reads/writes, wakeups, logging, socket/TUN calls, or another syscall-heavy loop. |
| Many voluntary context switches while idle | Frequent timers or blocking operations waking more often than needed. |
| Many non-voluntary context switches | CPU contention, quota pressure, or an actually CPU-bound worker. |
| High `%steal` in `mpstat` | The VPS host is not scheduling the guest consistently; do not attribute all latency or CPU variation to this code. |
| High cgroup throttling or a low CPU quota | The service is hitting its allocation; raising the quota can hide but does not remove inefficient work. |
| CPU tracks peer/service count, not bytes | Look for one timer, poller, or snapshot traversal per object. |
| CPU grows after TCP connection churn and does not return to baseline | Count ChannelMux TCP backpressure tasks versus currently open TCP channels. |
| CPU rises only with an admin page open | Profile WebAdmin live-topic snapshot production and serialization. |
| Deleted temporary files grow while the launcher runs | The launcher is capturing redirected child output in unlinked files; inspect dashboard and logging volume. |

If the child restarts during the capture, a PID-only series becomes
incomplete. Preserve the service cgroup counters and restart count, then start
a new per-PID capture for the replacement child.

## Correlate CPU With Actual Runtime Work

Record CPU and application evidence over the same timestamps. WebAdmin is
authenticated; obtain API snapshots through the normal authenticated operator
flow rather than placing a password or token in shell history.

- `/api/peers` provides per-peer traffic rates and byte counts, RTT and
  transmit delay, in-flight/queued work, myUDP repeat counts, decode errors,
  SecureLink counters, and compression counters.
- `/api/connections` provides channel/service state and per-connection
  byte/message counters.
- `/api/status` provides build, uptime, configured runtime status, and helper
  diagnostics. It does not currently expose Linux process CPU usage; building
  the status response still performs runtime snapshot work.
- Component logs can reveal reconnect, authentication, retransmit,
  listener-repair, and TUN error storms. Use the narrowest useful log level;
  packet-level `DEBUG` logging can itself become the dominant workload.

The current logging implementation sets the root logger to `DEBUG` and keeps a
formatted in-memory debug ring for WebAdmin. Consequently, `--log WARNING`
alone does not eliminate debug-record construction and formatting. For a
diagnostic A/B run, set explicit component overrides such as
`--log-udp-session WARNING`, `--log-channel-mux WARNING`, and the matching flag
for every active transport/component. Reducing
`--admin-web-log-max-lines` bounds retained lines but does not prevent each
record from being formatted. Treat this as a current implementation caveat and
verify effective logger levels in the profile.

An open WebAdmin client subscribes to live data and causes periodic snapshot
work. Always perform otherwise identical connected-idle runs with all admin
tabs closed and with one normal admin session open. Also check for forgotten
browser tabs or monitoring clients that create multiple live subscriptions.

Low application traffic should be cross-checked against the host network and
TUN interfaces. Port scanners, malformed datagrams, keepalives, and small
packets may be almost invisible in an application bytes/s view:

```bash
ss -upnt
ip -s link
sar -n DEV 1
```

Use a bounded `tcpdump` capture when the packet source is unclear. Capture only
the required interfaces and ports, and handle the result as sensitive data.

## Find the Hot Code

### 1. Sample the live process first

A sampling profiler usually gives the best production evidence for the least
distortion. `py-spy` can attach without modifying ObstacleBridge. Use the same
user where permissions allow it; elevate only when the host's ptrace policy
requires that.

```bash
py-spy top --pid "$bridge_pid" --rate 99
py-spy dump --pid "$bridge_pid"
py-spy record --pid "$bridge_pid" --duration 120 --rate 99 \
  --output obstaclebridge-idle.svg
```

Capture at least one flame graph during the high-CPU interval and one during a
normal interval. A profile taken after the spike has ended does not explain
the spike. If Python stacks do not account for the observed system CPU, repeat
with native stack collection where supported and inspect syscalls.

### 2. Count syscalls and scheduler activity

These commands attach to a running process and they add overhead, so use a
short bounded window and avoid stacking several profilers at once.

```bash
sudo timeout --signal=INT 30s strace -f -c -p "$bridge_pid"
sudo perf stat -p "$bridge_pid" \
  -e task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions \
  -- sleep 60
sudo perf record -F 99 -g -p "$bridge_pid" -- sleep 60
sudo perf report
```

Repeated nonblocking `read`/`recv` calls returning `EAGAIN` point toward a
polling loop. Heavy `write` calls often point toward logging or terminal
status output. Futex/epoll waits are normally evidence that a thread is
sleeping, not consuming CPU. Kernel permissions and symbols determine how much
detail `perf` can show.

### 3. Use deterministic profiling in a controlled environment

`cProfile` is useful for function call counts and cumulative time, but its
instrumentation overhead changes scheduling and absolute CPU usage. Run it in
development or staging with a production-like configuration. The following
invokes the bridge child directly and intentionally bypasses launcher restart
supervision:

```bash
.venv/bin/python -m cProfile -o obstaclebridge.prof \
  -m obstacle_bridge.bridge_runner \
  --config ObstacleBridge.cfg --no-dashboard

.venv/bin/python -c \
  'import pstats; pstats.Stats("obstaclebridge.prof").strip_dirs().sort_stats("cumulative").print_stats(50)'
```

Stop the run cleanly so the profile is written. Sort by cumulative time and
also inspect call count and per-call time. Use asyncio debug mode only to find
slow callbacks in staging; it adds overhead and must not be enabled during a
performance comparison.

### 4. Change one dimension at a time

Once a profile exists, use controlled A/B runs to attribute a subsystem. Useful
comparisons include:

- WebAdmin closed versus one live WebAdmin session
- dashboard default versus `--no-dashboard`
- normal logging versus a temporarily narrower log configuration
- compression default versus `--no-compress-layer`
- configured TUN service versus an otherwise equivalent socket-only service
- inline TUN versus helper-backed TUN, where both are valid for the test host
- one transport or peer versus several

Feature-disable tests are diagnostic experiments, not automatic production
fixes. In particular, do not leave security, reliability, or required tunnel
behavior disabled merely because doing so reduces CPU.

As the code currently stands, `--no-dashboard` prevents the StatsBoard's
periodic render task from starting. A service can express the same controlled
setting in grouped configuration, and can disable periodic status explicitly:

```json
{
  "stats_board": {
    "status": false,
    "no_dashboard": true
  }
}
```

There is currently no `--no-status` CLI flag. Keep this distinction in mind if
StatsBoard behavior is later corrected so `--no-dashboard` means line output
rather than no periodic task.

## Code-Specific Places to Inspect

The following are known periodic or potentially expensive paths. They are a
profile checklist, not a claim that any one currently causes the observed
`90%` CPU.

| Area | Current behavior to correlate with a profile | Improvement direction if confirmed hot |
| --- | --- | --- |
| [TCP backpressure task lifecycle](../src/obstacle_bridge/bridge_channelmux.py) | A worker starts only after a TCP write leaves buffered bytes and exits when the buffer drains. Local EOF, remote `CLOSE`, peer reset, and shutdown all detach and cancel it idempotently; task cleanup is identity-guarded so a late cancellation cannot remove a replacement for a reused channel ID. | Keep the lifecycle regression and add a churn/integration profile that confirms active workers return to baseline after repeated real TCP connects. |
| [myUDP listener peer allocation and timers](../src/obstacle_bridge/bridge_transport_udp.py) | `PeerProtocol._control_tick` and `_retx_tick` each wake at 25 ms intervals. A listener currently allocates a peer and starts these tasks before validating the first datagram; unauthenticated sources can remain for about 15 seconds. Scans or spoofed source tuples can therefore create many tasks with almost no useful throughput. | Validate a minimal frame/cookie before full allocation where the protocol permits it; cap and rate-limit pre-auth peers; defer timers/probes until validation; arm ACK/retransmit work only while a deadline exists; and stress-test random invalid source tuples. |
| [Transport RTT runtime](../src/obstacle_bridge/bridge_transport_common.py) | Connected/disconnected liveness checks use periodic sleeps and probes. | Coalesce deadlines and verify that failed peers back off instead of forming a retry storm. |
| [Linux helper TUN reader](../src/obstacle_bridge/bridge_tun_helper_linux.py) and [macOS helper TUN reader](../src/obstacle_bridge/bridge_tun_helper_macos.py) | A nonblocking TUN read that returns no packet is retried after a 10 ms sleep. This can produce about 100 wakeups/s per active helper reader. The normal inline Linux TUN path is readiness-driven. | Prefer readiness notification or a cancellable blocking read; otherwise use a bounded adaptive idle backoff and return to low latency immediately when traffic resumes. |
| [ChannelMux maintenance](../src/obstacle_bridge/bridge_channelmux.py) | UDP expiry, service self-healing, and delay-rotation checks run periodically, generally once per second. Snapshot and cleanup work can scale with services, peers, and fragments. | Avoid full scans when collections are empty, use next-expiry data structures where justified, and consolidate per-instance maintenance only after measuring it. |
| [Reconnect loops](../src/obstacle_bridge/bridge_runner.py) | The configured reconnect delay accepts zero, and TCP, WebSocket, and QUIC retry loops can then repeatedly fail with a zero-second sleep. | Enforce a positive floor and use bounded exponential backoff with jitter; expose attempts/s and consecutive failures. |
| [StatsBoard](../src/obstacle_bridge/bridge_stats.py) | With dashboard mode enabled, status and aggregate metrics are rendered and flushed once per second, even when launcher output is redirected. | Auto-disable rendering for non-TTY output, add an explicit `--no-status`, cache inexpensive counters, and separate metric sampling from terminal formatting. Compare with `--no-dashboard` first. |
| [Launcher child-output capture](../src/obstacle_bridge/launcher.py) | In redirected mode, stdout and stderr go to unlinked `TemporaryFile` objects for the entire child lifetime so an early failure tail can be replayed. Dashboard and log output therefore consume filesystem space even though no file is visible by name. | Retain only a bounded startup/failure tail, then redirect to `/dev/null` or the service log. Monitor deleted-open files with `lsof +L1`. |
| [Logging configuration](../src/obstacle_bridge/bridge_debug_logging.py) | Root remains at `DEBUG` and a DEBUG handler formats every accepted record into the WebAdmin memory ring. Numerous hot paths use per-packet/per-frame debug calls, including TUN hex formatting. | Make the application threshold honor the configured level, make the debug ring opt-in or independently filtered, guard expensive formatting, and count/rate-limit suppressed repetitions. |
| [WebAdmin live topics](../src/obstacle_bridge/bridge_webadmin.py) | Most subscribed topics refresh once per second per live client and build/deep-copy peer and connection snapshots. Status construction also consults connection state. If a build misses its interval, a client can immediately begin the next cycle. | Build one cached snapshot per topic/interval, reuse it across clients, skip missed ticks with a minimum yield, and avoid traversing data no subscriber requested. |
| [Runner asyncio diagnostics](../src/obstacle_bridge/bridge_runner.py) | A task factory records activity and adds a completion callback for every asyncio task, but exposes only the latest activity rather than useful task population/rate data. | Benchmark the task factory cost, make detailed tracing opt-in if material, and replace last-event-only data with cheap bounded counters and event-loop-lag metrics. |
| [Compression layer](../src/obstacle_bridge/bridge_compression.py) | Compression is enabled by default and may spend CPU on candidates that later produce little or no size benefit. | Use the existing attempt/applied/no-gain and byte counters to tune minimum size and level for measured workloads. |

Also inspect object counts. A modest timer cost multiplied by many listener
peers, transports, TUN devices, services, or WebAdmin clients can dominate an
otherwise idle process.

## Improve the Runtime Safely

Use this order of work:

1. Reproduce the issue and save an evidence bundle.
2. Identify the hot stack, its wakeup/call rate, and the runtime condition that
   activates it.
3. Add a focused benchmark or regression scenario before changing behavior.
4. Make the smallest change that removes unnecessary work.
5. Repeat the identical measurement and correctness suite.
6. Compare absolute CPU cores, CPU per unit of work, latency/RTT,
   retransmissions, drops, queue depth, and memory rather than CPU alone.
7. Roll out as a canary and confirm the production time series.

Common safe optimization patterns include:

- replace fixed-frequency empty polling with readiness or event-driven waits
- make every per-channel task have an explicit owner and symmetric teardown on
  normal close, remote close, failure, reconnect, and global shutdown
- schedule a timer for the next actual deadline instead of checking all
  deadlines at a fixed interval
- apply adaptive backoff only while genuinely idle and wake immediately when
  new work arrives
- batch packets or callbacks while retaining a burst limit so one peer cannot
  starve the event loop
- cache immutable or interval-scoped admin snapshots and serialize once per
  refresh, not once per client
- avoid repeated full-list scans when an empty-state or generation check can
  prove there is no work
- avoid bytes copies, hex conversion, and eager log formatting in hot paths
- tune compression thresholds and levels from compression ratio and CPU
  evidence, not from payload size alone
- move work to threads, processes, or native code only when the profile proves
  that algorithmic and scheduling fixes are insufficient

Do not trade correctness for a lower number. Any timer change must retain RTT,
reconnect, acknowledgement, retransmit, and cleanup guarantees under loss.
Any TUN change must retain prompt shutdown and cancellation. Any snapshot
cache must retain peer isolation and have a defined maximum staleness.

ObstacleBridge maintains Python and Swift implementations. If an optimization
changes shared transport, ChannelMux, SecureLink, compression, TUN, or admin
semantics, perform the parity review and equivalent test update required by
the project workflow. A Python-only scheduling implementation can differ, but
the observable protocol and lifecycle contract must remain aligned.

## Performance Regression Workflow

### Benchmark layers

Use both layers because neither replaces the other:

- Microbenchmarks isolate frame parsing/building, compression decisions,
  crypto wrappers, mux codecs, and snapshot assembly. A stable tool such as
  `pyperf` can reduce warm-up and statistics mistakes.
- Subprocess/integration benchmarks run real event loops, sockets, peers,
  WebAdmin, and TUN modes. They reveal wakeups and scaling costs that a codec
  benchmark cannot.

Each result artifact should be machine-readable and contain fields equivalent
to:

```json
{
  "commit": "...",
  "platform": "...",
  "python": "...",
  "scenario": "connected-idle-myudp-one-peer",
  "warmup_seconds": 60,
  "measurement_seconds": 300,
  "cpu_seconds": 0.0,
  "average_cpu_cores": 0.0,
  "application_bytes": 0,
  "packets": 0,
  "rss_peak_bytes": 0,
  "context_switches": 0,
  "retransmits": 0
}
```

Use the same machine image, power settings, CPU quota, Python build,
dependencies, configuration, and traffic generator for before/after runs.
Dedicated runners are appropriate for hard CPU budgets. Shared CI runners are
useful for functional tests and coarse trend warnings, but host noise makes
small performance gates unreliable.

Start by collecting history without failing builds. Once a scenario is stable,
define both an absolute budget and an allowed change from its established
median. Derive the margin from observed run-to-run noise; do not declare a
universal percentage from a single VPS sample. Store the baseline and budget
with the scenario so intentional changes are reviewed rather than silently
rebaselined.

Every performance-sensitive pull request should report:

- scenario and exact commands/configuration
- at least three before and after measurements
- median, range, absolute CPU cores, and normalized CPU/unit-of-work
- flame graphs or call-count evidence for the changed hotspot
- latency, retransmit/drop, memory, and correctness results
- Python/Swift parity impact
- expected production metric and rollback condition

## Active Production Monitoring

### Observe at four layers

| Layer | Minimum signals | Preferred source |
| --- | --- | --- |
| VPS host | per-CPU use, load, `%steal`, memory pressure, network packets/bytes | node/host exporter or provider telemetry |
| service cgroup | CPU seconds, quota/throttling, RSS/peak, tasks, file descriptors, restarts | systemd/cgroup collector |
| Python runtime | event-loop lag, task/thread counts, garbage collection, timer/poller executions, snapshot duration | future in-process metrics sampled on a fixed cadence |
| ObstacleBridge work | peer/channel counts, packets and bytes, RTT/delay, queues, retransmits, reconnects, compression attempts/no-gain | existing admin counters plus a future metrics exporter |

Enable service accounting explicitly when the deployment does not already do
so:

```ini
[Service]
CPUAccounting=yes
MemoryAccounting=yes
TasksAccounting=yes
```

Treat a CPU quota as a safety boundary, not an optimization. If the runtime is
throttled, record throttled time and event-loop/RTT impact; a cap can turn an
efficiency problem into packet loss or reconnects.

A Prometheus `process-exporter`, cgroup-aware collector, or equivalent agent
can turn monotonic CPU seconds into average cores. For example, with the
exporter's group name configured as `obstaclebridge`:

```promql
sum(rate(namedprocess_namegroup_cpu_seconds_total{groupname="obstaclebridge"}[5m]))
```

The result is cores consumed. Multiply by 100 for percent of one core; divide
by the effective CPU allocation before presenting percent of the service's
available capacity. Prefer cgroup grouping over one PID so supervisor-driven
restarts do not reset the apparent workload.

### Add low-overhead runtime metrics

The Python runtime does not currently expose Linux process CPU as a documented
WebAdmin metric. Future instrumentation should sample on a fixed cadence and
serve cached values through a Prometheus endpoint or a clearly versioned admin
payload. Do not compute an expensive process snapshot separately for every
browser request.

Recommended process/runtime metrics are:

- monotonic process CPU seconds, resident/peak memory, open FDs, and threads
- event-loop scheduling lag distribution and longest callback duration
- live and completed asyncio task counts by a small bounded category
- garbage-collection counts and pause time
- control-timer, retransmit-sweep, idle-probe, reconnect-attempt, and empty-TUN
  poll counters
- TCP backpressure tasks created/active/completed/cancelled, compared with the
  number of currently open TCP channels
- pre-auth myUDP peers, new source tuples, invalid first frames, allocation
  drops, and pre-auth expiry rate
- admin snapshot build count and duration by topic
- log records and formatted bytes by bounded logger/level category
- redirected child-output bytes and deleted-open capture-file size
- packets/s and frames/s alongside bytes/s
- queue depth/age, retransmits, drops, decode failures, and compression no-gain
  rate
- build commit, runtime version, Python version, and transport mode as target
  metadata

Metric labels must remain low-cardinality. Do not label time series with raw
peer addresses, channel IDs, service IDs, exception text, or session IDs.
Keep detailed per-peer information in the authenticated admin APIs and expose
bounded aggregates to the monitoring system.

### Dashboard and alert on relationships

Place these graphs on one time axis:

- service CPU cores and CPU quota/throttling
- application bytes/s and packets/s
- active peers, services, and channels
- event-loop lag and context-switch rate
- myUDP control/retransmit counts and RTT/transmit delay
- current TCP channels versus active TCP backpressure tasks
- pre-auth myUDP peers and new/invalid source rate
- WebAdmin live clients and snapshot build time
- TUN packets and empty-read/poll rate
- log records/formatted bytes and launcher capture-file growth
- compression attempts, applied/no-gain ratio, and input/output bytes
- RSS, file descriptors, and restart count

Alerts should be sustained and baseline-aware. Useful conditions include:

- CPU above the scenario's idle envelope while packets/s and bytes/s remain
  below their idle thresholds
- CPU per GiB or CPU per million packets exceeding the release budget
- event-loop lag or RTT rising while the service is CPU-throttled
- retransmit, decode-failure, reconnect, empty-poll, or snapshot rates changing
  sharply without a corresponding traffic increase
- RSS or file descriptors growing across repeated connect/disconnect cycles
- a restart counter increase or repeated child-PID replacement
- high host steal time, reported separately from an application regression

Calibrate thresholds from at least several clean deployment periods and alert
on multiple consecutive samples. A single `top` refresh should never page an
operator.

### Release monitoring

Deploy performance-sensitive changes to one canary first. Annotate the
dashboard with the build commit and deployment time, compare the same
hour-of-day/workload window, and preserve the previous build until the agreed
observation period ends. Define rollback criteria before deployment using CPU,
event-loop lag, RTT, retransmit/drop, and memory—not CPU alone.

## Evidence Bundle for an Incident or Pull Request

Use this checklist so another developer can reproduce the finding:

```text
UTC start/end:
host/VPS and effective CPU quota:
kernel/distribution:
commit/build and dirty state:
Python and dependency versions:
launch method, supervisor PID, runtime-child PID, service cgroup:
redacted transport/service/TUN/SecureLink/compression configuration:
peer/service/channel/WebAdmin-client counts:
traffic bytes/s, packets/s, packet sizes, loss/reordering:
pidstat/mpstat/cgroup capture:
normal and high-CPU flame graphs:
bounded strace/perf summary, if collected:
matching /api/peers, /api/connections, and /api/status snapshots:
matching redacted logs and packet capture, if required:
reproduction steps and frequency:
before/after benchmark results:
correctness and parity validation:
production alert and rollback condition:
```

For the currently reported VPS symptom, the shortest useful investigation is:

1. identify the runtime child and service cgroup
2. record five minutes of `pidstat` plus host `%steal`
3. repeat connected-idle with WebAdmin closed and open
4. capture a two-minute `py-spy` flame graph while CPU is high
5. check whether active TCP backpressure tasks exceed current TCP channels and
   whether CPU grows with cumulative TCP connection churn
6. correlate it with pre-auth peer count, new source tuples, packet,
   retransmit, compression, log, and deleted-open-file activity
7. use one-at-a-time controlled comparisons to isolate dashboard, WebAdmin,
   compression, TUN helper, transport, and peer-count effects
8. add the reproduced scenario to the performance suite before optimizing the
   confirmed hotspot
