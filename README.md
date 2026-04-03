# ObstacleBridge
ObstacleBridge is a Python-based overlay and channel-multiplexing toolkit for barrier-resilient networking. It can run over multiple overlay transports (`myudp`, `tcp`, `quic`, `ws`), expose local TCP/UDP listener services through a reliable overlay, and host an admin UI for monitoring active channels.

## Whitepaper
The complete whitepaper requested for this project update is available as a rendered preview at [`docs/WHITEPAPER.html`](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/WHITEPAPER.html). It covers:
- Internet barriers such as NAT, DPI, protocol blocking, traffic shaping, and TLS interception.
- Transport-level behavior for IP, ICMP, UDP, TCP, QUIC, DNS, HTTP/HTTPS, and WebSockets.
- The layered overlay architecture used here: RTT/liveness, reliable DATA/CONTROL framing, and ChannelMux OPEN/DATA/CLOSE multiplexing.
- Why UDP overlays can outperform TCP-over-TCP tunnels on hostile paths.
- Development-process lessons from AI-supported programming.
### Whitepaper abstract
> This whitepaper presents a detailed technical explanation of Internet communication mechanisms and a Python-based UDP overlay protocol designed to work across restrictive network environments. The report explains how modern Internet barriers such as NAT, IPv4/IPv6 asymmetry, deep packet inspection, protocol blocking, traffic shaping, and throttling affect connectivity, and how a layered UDP overlay can reconstruct connection detection, round-trip-time measurement, loss recovery, retransmission, and multi-channel multiplexing in user space.

## Similar projects
- [chisel](https://github.com/jpillora/chisel) — a well-known TCP/UDP tunnel over HTTP/WebSocket implemented in Go.

## Why this project was developed
- `chisel` is implemented in Go, and using/building it on Synology NAS environments can be difficult in practice.
- ObstacleBridge adds the `myudp` transport to better handle network obstacles and traffic degradation conditions seen in large-scale Asian network environments.

## Quick-start examples
The recommended workflow is:

1. start each instance with a small config file
2. enable the Admin Web UI from the beginning
3. tune transports, peers, published services, auth, and logging in the Config tab
4. save the resulting config and use it as the durable runtime definition

This keeps first startup simple and makes larger settings such as `own_servers`, `remote_servers`, auth options, and multi-transport listener combinations much easier to manage than long shell commands.

![WebAdmin Config Editor](docs/WebAdmin%20ConfigEditor.png)

### Minimal bootstrap pattern
Create one config file per instance and only keep a few startup arguments on the command line.

**Listener / server bootstrap**
```ini
# bridge_server.ini
overlay_transport = myudp
udp_bind = ::
udp_own_port = 4443
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18080
log = INFO
```

```bash
python -m obstacle_bridge --config bridge_server.ini
```

**Peer / client bootstrap**
```ini
# bridge_client.ini
overlay_transport = myudp
udp_peer = bridge.example.com
udp_peer_port = 4443
udp_own_port = 0
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18081
log = INFO
```

```bash
python -m obstacle_bridge --config bridge_client.ini
```

After the first startup, open the Admin Web UI and adjust the remaining details there:

- overlay transport mix such as `myudp`, `ws`, `tcp`, or `quic`
- peer target and listener bind/port values
- `own_servers` and `remote_servers`
- admin authentication and instance naming
- logging and log retention settings

### 1) NAS behind outbound-only internet, reached through a public server
This setup fits a NAS or home server that can make outgoing connections but cannot accept incoming internet traffic directly.

Use a small VPS listener config first, then finish the published service mapping in WebAdmin:

Issue before ObstacleBridge:

![NAS issue example](docs/NAS_Issue.svg)

Solution with a public ObstacleBridge server:

![NAS solution example](docs/NAS_solution.svg)

**Public VPS initial config**
```ini
overlay_transport = myudp
udp_bind = ::
udp_own_port = 4443
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18080
admin_web_name = VPS
log = INFO
```

**NAS initial config**
```ini
overlay_transport = myudp
udp_peer = bridge.example.com
udp_peer_port = 4443
udp_own_port = 0
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18081
admin_web_name = NAS
log = INFO
```

Then use WebAdmin to add the service exposure you want, for example:

- VPS listener publishes NAS SSH as TCP `18022 -> 127.0.0.1:22`
- VPS listener publishes NAS HTTP/HTTPS as TCP `80` and `443`
- NAS peer publishes its admin UI back to the VPS on a separate TCP port such as `18081`

### 2) WireGuard bridge through inspected internet access
This fits environments where raw VPN UDP is blocked or degraded, but HTTP(S)-shaped traffic still survives.

Start with a WebSocket-based config and then use WebAdmin to define the local UDP service recreation:

Issue before ObstacleBridge:

![Client issue example](docs/Client_issue.svg)

Solution with an ObstacleBridge WebSocket bridge:

![Client solution example](docs/Client_solution.svg)

**Public bridge config**
```ini
overlay_transport = ws
ws_bind = 0.0.0.0
ws_own_port = 443
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18080
admin_web_name = Public WS Bridge
log = INFO
```

**Restricted-side peer config**
```ini
overlay_transport = ws
ws_peer = bridge.example.com
ws_peer_port = 443
ws_own_port = 0
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18081
admin_web_name = Restricted Client
log = INFO
```

Then use WebAdmin to add an `own_servers` entry that recreates the local WireGuard or UDP OpenVPN endpoint, for example `udp,16666,127.0.0.1,udp,127.0.0.1,16666`.

### 3) WireGuard bridge for high-loss obstacle conditions
This fits paths where UDP still passes, but loss and retransmission pressure make conventional transports perform badly.

Start with `myudp` in the config file and use WebAdmin to finish the local service mapping:

Issue before ObstacleBridge:

![Client2 issue example](docs/Client2_issue.svg)

Solution with an ObstacleBridge `myudp` bridge:

![Client2 solution example](docs/Client2_solution.svg)

**Public bridge config**
```ini
overlay_transport = myudp
udp_bind = 0.0.0.0
udp_own_port = 4433
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18080
admin_web_name = Public myudp Bridge
log = INFO
```

**Restricted-side peer config**
```ini
overlay_transport = myudp
udp_peer = bridge.example.com
udp_peer_port = 4433
udp_own_port = 0
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18081
admin_web_name = Lossy Client
log = INFO
```

Then use WebAdmin to add the same local UDP recreation for WireGuard or UDP OpenVPN, usually on `127.0.0.1:16666`.

### 4) Peer client with both inspected-path and high-loss-path transports
If you want one peer config that can use both WebSocket and `myudp`, keep the bootstrap config simple and tune the rest in WebAdmin:

```ini
overlay_transport = ws,myudp
ws_peer = bridge.example.com
ws_peer_port = 443
ws_own_port = 0
udp_peer = bridge.example.com
udp_peer_port = 4433
udp_own_port = 0
admin_web = true
admin_web_bind = 127.0.0.1
admin_web_port = 18081
admin_web_name = Dual Transport Client
log = INFO
```

Then use WebAdmin to define:

- the local UDP service recreation such as WireGuard on `127.0.0.1:16666`
- any additional published TCP or UDP services
- authentication, log policy, and instance naming

Using config files plus WebAdmin makes these multi-transport setups much easier to review and maintain than long shell commands with many inline options.
## Entry points
- `python -m obstacle_bridge --help`

## CLI parameter reference
The tables below are generated from the current parser registrations in `bridge.py`, so the defaults and descriptions match the live code.
### General / status
| Option(s) | Default | Description |
|---|---:|---|
| `--status` | `True` | enable periodic status (default: on) |
| `--no-dashboard` | `False` | disable non-scrolling dashboard (print multiline blocks instead) |

### UDP overlay
| Option(s) | Default | Description |
|---|---:|---|
| `--udp-bind` | `::` | overlay bind address (IPv4 '0.0.0.0' or IPv6 '::') |
| `--udp-own-port` | `4433` | UDP overlay own port |
| `--udp-peer` | `None` | peer IP/FQDN (IPv4 or IPv6 literal; IPv6 may be in [brackets]) |
| `--udp-peer-port` | `443` | peer overlay port |
| `--peer-resolve-family` | `prefer-ipv6` | Peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only. |
| `--max-inflight` | `32767` | max DATA frames allowed in flight (1..32767). Excess frames are queued. |
| `--peer` | alias of `--udp-peer` | backwards-compatible alias |
| `--peer-port` | alias of `--udp-peer-port` | backwards-compatible alias |

### WebSocket overlay
| Option(s) | Default | Description |
|---|---:|---|
| `--ws-path` | `/` | WebSocket HTTP path (default /) |
| `--ws-bind` | `::` | WS overlay bind address |
| `--ws-own-port` | `8080` | WS overlay own port |
| `--ws-peer` | `None` | WS peer IP/FQDN |
| `--ws-peer-port` | `8080` | WS peer overlay port |
| `--ws-subprotocol` | `None` | Optional WebSocket subprotocol (e.g. mux2) |
| `--ws-tls` | `False` | Use TLS (wss://). Provide cert/key via your deployment. |
| `--ws-max-size` | `65535` | Maximum binary message size to accept/send (default 65535). |
| `--ws-payload-mode` | `binary` | WebSocket payload transfer mode: raw binary frames (default), base64 text frames, or JSON text frames with the base64 payload in the data field. |
| `--ws-static-dir` | `./web` | Directory to serve as a static web root on the WS port (default ./web). Set to '' to disable. |
| `--ws-send-timeout` | `3.0` | Seconds to wait for a WebSocket frame send before forcing reconnect (default 3.0). |
| `--ws-tcp-user-timeout-ms` | `10000` | TCP_USER_TIMEOUT in milliseconds for WebSocket sockets (default 10000, 0 disables). |
| `--ws-reconnect-grace` | `3.0` | Seconds to wait before reporting DISCONNECTED after WS transport loss (default 3.0). |
| `--ws-proxy-mode` | `off` | WebSocket peer-client proxy mode: `off`, `manual`, or `system` (Windows only). |
| `--ws-proxy-host` | `` | Manual WebSocket proxy host for `--ws-proxy-mode manual` (Windows only). |
| `--ws-proxy-port` | `8080` | Manual WebSocket proxy port for `--ws-proxy-mode manual` (Windows only). |
| `--ws-proxy-auth` | `none` | WebSocket proxy auth mode: `none` or `negotiate` (Windows only). |

WebSocket proxy tunneling is currently scoped narrowly:

- Windows only
- WebSocket peer client only
- HTTP proxy traversal via `CONNECT`
- optional `Negotiate` proxy authentication using the current Windows logon context

### TCP overlay
| Option(s) | Default | Description |
|---|---:|---|
| `--tcp-bp-wbuf-threshold` | `131072` | TCP overlay: write() buffer size threshold in bytes to signal drain (default 131072). |
| `--tcp-bind` | `::` | TCP overlay bind address |
| `--tcp-own-port` | `8081` | TCP overlay own port |
| `--tcp-peer` | `None` | TCP peer IP/FQDN |
| `--tcp-peer-port` | `8081` | TCP peer overlay port |
| `--tcp-bp-latency-ms` | `300` | TCP overlay: if > 0, trigger drain after this latency (ms) whenever pending bytes exist. |
| `--tcp-bp-poll-interval-ms` | `50` | TCP overlay: polling interval for time-based backpressure checks (ms; default 50). |

### QUIC overlay
| Option(s) | Default | Description |
|---|---:|---|
| `--quic-alpn` | `hq-29` | ALPN protocol ID (default hq-29) |
| `--quic-bind` | `::` | QUIC overlay bind address |
| `--quic-own-port` | `443` | QUIC overlay own port |
| `--quic-peer` | `None` | QUIC peer IP/FQDN |
| `--quic-peer-port` | `443` | QUIC peer overlay port |
| `--quic-cert` | `None` | Server certificate file (PEM) |
| `--quic-key` | `None` | Server private key file (PEM) |
| `--quic-insecure` | `False` | Client: disable certificate verification (TEST ONLY) |
| `--quic-max-size` | `65535` | Maximum app message size accepted/sent (default 65535). |

### Channel mux
| Option(s) | Default | Description |
|---|---:|---|
| `--own-servers` | `None` | Space-separated service specs (client mode only): 'proto,listen_port,listen_bind,proto,host,port' (quoted). Listener instances ignore --own-servers because multiple overlay peers make the target ambiguous. Example: "tcp,80,0.0.0.0,tcp,127.0.0.1,88 udp,16666,::,udp,127.0.0.1,16666" |
| `--remote-servers` | `None` | Space-separated service specs with the same format as `--own-servers`, but applied to the connected overlay peer via mux control signaling (reverse behavior of `--own-servers`). Example: "udp,16666,0.0.0.0,udp,127.0.0.1,16666 tcp,3128,0.0.0.0,tcp,127.0.0.1,3128". |
| `--mux-tcp-bp-threshold` | `1` | Mux TCP: size threshold (bytes) to trigger drain() (default 1). |
| `--mux-tcp-bp-latency-ms` | `300` | Mux TCP: if > 0, drain writers after this ms when bytes pending. |
| `--mux-tcp-bp-poll-interval-ms` | `50` | Mux TCP: polling interval for time-based backpressure (ms). |

#### Reverse service publishing with `--remote-servers`

`--remote-servers` lets one peer ask the connected peer to expose listeners and bridge them to peer-local targets.

```bash
--remote-servers "udp,16666,0.0.0.0,udp,127.0.0.1,16666 tcp,3128,0.0.0.0,tcp,127.0.0.1,3128"
```

Expected behavior:

- On connected peer: bind UDP listener on `0.0.0.0:16666`, and connect forwarded UDP channel to `127.0.0.1:16666`.
- On connected peer: bind TCP listener on `0.0.0.0:3128`, and connect forwarded TCP channel to `127.0.0.1:3128`.
- Initiating peer sends a dedicated mux control command after overlay connection so the remote side can install or refresh the requested service catalog.

### Admin web
| Option(s) | Default | Description |
|---|---:|---|
| `--admin-web` | `True` | Enable admin web interface |
| `--admin-web-bind` | `127.0.0.1` | Bind address for admin web interface |
| `--admin-web-port` | `18080` | Port for admin web interface |
| `--admin-web-path` | `/` | Base path for admin web interface |
| `--admin-web-dir` | `./admin_web` | Directory containing admin web files |
| `--admin-web-name` | `` | Optional instance name shown in the admin web window title and headline |
| `--admin-web-token` | `` | Optional bearer token for admin restart endpoint |
| `--admin-web-auth-disable` | `False` | Disable admin web username/password challenge |
| `--admin-web-username` | `` | Username for admin web access when challenge-based authentication is enabled |
| `--admin-web-password` | `` | Password for admin web access when challenge-based authentication is enabled; redacted from admin config snapshots |
| `--admin-web-log-max-lines` | `1200` | Maximum number of debug log lines kept in memory for the admin web log view |

When `--admin-web-username` and `--admin-web-password` are configured and auth is not disabled, the admin web page requires a challenge-response login. The browser requests a one-time seed, hashes `seed:username:password` client-side, and sends only the hash proof back to the server. The configured password is not returned by the admin config API.

#### Admin web examples

The repository includes two exported admin web snapshots:

- [docs/ObstacleBridge Client.html](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/ObstacleBridge%20Client.html) shows a peer/client-side view.
- [docs/ObstacleBridge Server.html](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/ObstacleBridge%20Server.html) shows a listener/server-side view.

Client admin web screenshot:

![ObstacleBridge client admin web screenshot](docs/ObstaceBridge%20Client.png)

What the admin web shows:

- A top status badge with the current overlay state, for example `CONNECTED`.
- A summary row with the currently open UDP and TCP channel counts.
- Traffic cards for app-side RX/TX and peer-side RX/TX rates.
- A peer-session table with transport type, RTT estimate, open channel counts, byte counters, inflight frames, and `myudp` confirmation statistics.
- UDP and TCP connection tables that show current mappings, local listening ports, remote endpoints, and per-channel byte/message counters.
- A configuration tab that exposes the live runtime options such as overlay transports, listener ports, `--remote-servers`, admin web settings, and log levels.
- A debug log tab with recent in-memory log lines, which is especially useful while investigating channel setup, backpressure, reconnects, and late-data cases.

What is visible in the included snapshots:

- The client snapshot shows a connected `myudp` peer session, one active UDP service, and TCP listener activity on the peer side where overlay traffic is being delivered back to local sockets.
- The server snapshot shows a public listener role with a connected `myudp` session, an additional idle `ws` listener, and multiple active TCP channels being bridged through the overlay.

### Logging
| Option(s) | Default | Description |
|---|---:|---|
| `--log` | `WARNING` | logging level (default WARNING; try INFO or DEBUG) be aware of --console-level and --file-level |
| `--log-file` | `None` | file path to also write logs enabled by --log |
| `--log-file-max-bytes` | `0` | Maximum on-disk log file size in bytes before rotation; `0` disables rotation |
| `--log-file-backup-count` | `5` | Number of rotated log files to keep when `--log-file-max-bytes` is enabled |
| `--console-level` | `INFO` | console (stdout) logging level (default INFO) |
| `--file-level` | `DEBUG` | file logging level (default: same as --log) |
| `--debug-stderr` | `False` | mirror DEBUG lines to stderr (default: off) |

### Runner
| Option(s) | Default | Description |
|---|---:|---|
| `--overlay-transport` | `myudp` | Overlay transport between peers: comma-separated list from myudp,tcp,quic,ws. Multiple transports are supported simultaneously for listening instances. |
| `--client-restart-if-disconnected` | `0.0` | If configured as a peer client (for example --udp-peer set) and overlay stays disconnected for this many seconds, request process restart. 0 disables. |

## Notes
- Listener mode intentionally ignores `--own-servers`, because a multi-peer listener cannot unambiguously bind one local listener to one remote peer.
- Multi-transport mode is currently intended for listening instances without configured transport peers (for example no `--udp-peer`, `--tcp-peer`, `--quic-peer`, or `--ws-peer`).
- WebSocket listener mode supports multiple simultaneous peers with per-peer mux-channel rewriting so that peer-local channel IDs do not collide inside the shared mux logic.

## Development environment and procedure
- Feature development is done on Fedora 42.
- The primary IDE is Visual Studio Code.
- ChatGPT 5.4 Codex integration is used for implementation support.
- Changes are mainly prompt-driven, with comparatively little direct source editing by hand.
- On each change, the focus is on test feedback and on extending the test environment to cover the functional increase.
- Integration testing is executed on a local machine running Python 3.13.12.
- After successful local validation, deployment is tested on a VPS running Ubuntu 24.04.03 LTS with Python 3.12.3 and a Fedora 42 client system.
- After successful validation there, deployment is also intended for the productive NAS environment running DSM 7.12 with Python 3.9.

## Trouble shooting recommendations
Debugging in a project like this can be difficult because the behavior emerges from the interaction of different peers, while the relevant evidence is often hidden in a large amount of runtime data.

- Enable logging on the relevant component, generate log files, and analyze them carefully. In practice it is often effective to use AI assistance to summarize the logs and provide reasoning about the likely sequence of events.
- Avoid guessing. If the evidence is not strong enough, extend the logging so that the next run produces harder facts instead of more assumptions.
- Keep in mind that the application log only shows what the application is attempting to hand over to the network stack. That does not necessarily prove that the same traffic was actually sent on the network or reached the remote side.
- When transport behavior is in doubt, capture network traffic with tools such as `tcpdump`. Do this on both peer client and peer server whenever possible so the full picture can be reconstructed from both ends.
- Try to reproduce problems in a lower-complexity environment such as the local development machine before debugging them in a more distributed or production-like setup.
- Create integration test cases for controlled reproduction whenever a bug or unclear transport interaction is found.
- Add those reproduction cases to the regression suite so future releases continue to cover the behavior and the functionality does not silently erode over time.

## Testing strategy
- Run the regular pytest suite during normal development to cover unit, integration, and overlay harness regression paths.
- Use the parallel overlay harness for frequent end-to-end validation when transport and socket behavior matter most.
- Keep reconnect, listener, and concurrent multi-peer coverage in the regular regression flow instead of treating them as occasional manual checks.
- The full testing catalog, commands, and scenario-by-scenario criteria are documented in `docs/README_TESTING.md`.

## Repository layout
- `src/obstacle_bridge/` — main implementation.
- `tests/unit/` — targeted unit tests.
- `tests/integration/` — end-to-end and subprocess tests.
- `scripts/` — development helpers.
- `docs/ObstacleBridge Client.html` — exported example of the admin web UI on a peer/client instance. Rendered preview: `https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/ObstacleBridge%20Client.html`
- `docs/ObstacleBridge Server.html` — exported example of the admin web UI on a listener/server instance. Rendered preview: `https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/ObstacleBridge%20Server.html`
- `docs/WHITEPAPER.html` — full whitepaper requested for this repository update. Rendered preview: `https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/WHITEPAPER.html`
- `docs/README_TESTING.md` — consolidated testing catalog, execution commands, and regression coverage notes.
- `wireshark/` — Wireshark dissectors grouped by framing/version.
