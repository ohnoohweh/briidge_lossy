# ObstacleBridge
ObstacleBridge is a Python-based overlay and channel-multiplexing toolkit for barrier-resilient networking. It can run over multiple overlay transports (`myudp`, `tcp`, `quic`, `ws`), expose local TCP/UDP listener services through a reliable overlay, and host an admin UI for monitoring active channels.
## Repository layout
- `src/obstacle_bridge/` — main implementation.
- `tests/unit/` — targeted unit tests.
- `tests/integration/` — end-to-end and subprocess tests.
- `scripts/` — development helpers.
- `docs/WHITEPAPER.html` — full whitepaper requested for this repository update.
- `wireshark/` — Wireshark dissectors grouped by framing/version.
## Entry points
- `python -m obstacle_bridge --help`

## Quick-start examples
### 1) WireGuard bridge setup
This example assumes the bridge **server** can already reach a local WireGuard UDP service on `127.0.0.1:16666`. The **peer** connects to that bridge server and recreates the same UDP port locally on `127.0.0.1:16666`, so a WireGuard client on the peer machine can point at `localhost:16666`.

**Bridge server**
```bash
python -m obstacle_bridge \
  --udp-bind 0.0.0.0 \
  --udp-own-port 443 \
  --log INFO
```
This bridge server must be reachable by clients at DNS name `bridge.example.com` (for example via public DNS A/AAAA records and firewall/NAT rules).

**Peer that recreates the WireGuard UDP port locally**
```bash
python -m obstacle_bridge \
  --udp-peer bridge.example.com \
  --udp-peer-port 443 \
  --udp-own-port 0 \
  --own-servers "udp,16666,127.0.0.1,udp,127.0.0.1,16666" \
  --log INFO
```

With that peer command running, a local WireGuard client can use `127.0.0.1:16666` as its endpoint; ObstacleBridge forwards the traffic over the overlay to the bridge server, which then sends it to the WireGuard service on its own `127.0.0.1:16666`.

### 2) Single overlay transport listener
```bash
python -m obstacle_bridge --overlay-transport ws --ws-bind 0.0.0.0 --ws-own-port 54321
```
### 3) Multi-transport listening instance
```bash
python -m obstacle_bridge \
  --overlay-transport "myudp,tcp,quic,ws" \
  --udp-own-port 443 \
  --udp-bind 0.0.0.0 \
  --tcp-bind 0.0.0.0 \
  --quic-bind 0.0.0.0 \
  --ws-bind 0.0.0.0 \
  --quic-cert cert.pem \
  --quic-key key.pem
```
In multi-transport listener mode, ObstacleBridge derives deterministic own-port offsets from `--udp-own-port`: `myudp:+0`, `tcp:+1`, `quic:+2`, `ws:+3`.
### 4) Peer client exposing local services
```bash
python -m obstacle_bridge \
  --overlay-transport ws \
  --ws-peer 203.0.113.10 --ws-peer-port 446 \
  --ws-own-port 0 \
  --own-servers "udp,16667,0.0.0.0,udp,127.0.0.1,16666 tcp,3129,0.0.0.0,tcp,127.0.0.1,3128"
```
Using `--ws-own-port 0` requests dynamic local source-port assignment by the OS. If a specific outgoing local WebSocket port is required by your network policy, set that exact value with `--ws-own-port`.
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
| `--admin-web-token` | `` | Optional bearer token for admin restart endpoint |

### Logging
| Option(s) | Default | Description |
|---|---:|---|
| `--log` | `WARNING` | logging level (default WARNING; try INFO or DEBUG) be aware of --console-level and --file-level |
| `--log-file` | `None` | file path to also write logs enabled by --log |
| `--console-level` | `INFO` | console (stdout) logging level (default INFO) |
| `--file-level` | `DEBUG` | file logging level (default: same as --log) |
| `--debug-stderr` | `False` | mirror DEBUG lines to stderr (default: off) |

### Runner
| Option(s) | Default | Description |
|---|---:|---|
| `--overlay-transport` | `myudp` | Overlay transport between peers: comma-separated list from myudp,tcp,quic,ws. Multiple transports are supported simultaneously for listening instances. |
| `--client-restart-if-disconnected` | `0.0` | If configured as a peer client (for example --udp-peer set) and overlay stays disconnected for this many seconds, request process restart. 0 disables. |

## Whitepaper
The complete whitepaper requested for this project update is included verbatim in [`docs/WHITEPAPER.html`](docs/WHITEPAPER.html). It covers:
- Internet barriers such as NAT, DPI, protocol blocking, traffic shaping, and TLS interception.
- Transport-level behavior for IP, ICMP, UDP, TCP, QUIC, DNS, HTTP/HTTPS, and WebSockets.
- The layered overlay architecture used here: RTT/liveness, reliable DATA/CONTROL framing, and ChannelMux OPEN/DATA/CLOSE multiplexing.
- Why UDP overlays can outperform TCP-over-TCP tunnels on hostile paths.
- Development-process lessons from AI-supported programming.
### Whitepaper abstract
> This whitepaper presents a detailed technical explanation of Internet communication mechanisms and a Python-based UDP overlay protocol designed to work across restrictive network environments. The report explains how modern Internet barriers such as NAT, IPv4/IPv6 asymmetry, deep packet inspection, protocol blocking, traffic shaping, and throttling affect connectivity, and how a layered UDP overlay can reconstruct connection detection, round-trip-time measurement, loss recovery, retransmission, and multi-channel multiplexing in user space.
### Whitepaper table of contents
1. Introduction  
2. Internet Services and Their Performance Requirements  
3. Routing Fundamentals: Hubs, Switches, Routers, VPN Paths, and the Layer Model  
4. Modern Internet Barriers  
5. Internet Protocol (IP)  
6. ICMP Protocol  
7. UDP Protocol  
8. TCP Protocol  
9. TCP Congestion Control  
10. TCP Backpressure and Flow Control  
11. QUIC Protocol  
12. DNS Protocol  
13. HTTP, HTTPS, and WebSockets  
14. Deep Packet Inspection and TLS Interception  
15. VPNs, HTTP Proxies, and Tunneling  
16. Why a UDP Overlay Helps  
17. Overlay Architecture Overview  
18. Overlay Architecture Overview  
19. Layer 1: Connection Detection and RTT Measurement  
20. Layer 2: Reliable DATA / CONTROL Protocol  
21. Layer 3: ChannelMux OPEN / DATA / CLOSE Protocol  
22. End-to-End Example: Browser via HTTP Proxy over Overlay  
23. Why This Can Improve Performance  
24. Detailed TCP-over-TCP Problem Example  
25. Limitations and Engineering Considerations  
26. Development Procedure and Experience with AI-Supported Programming  
27. Conclusion  
References
## Notes
- Listener mode intentionally ignores `--own-servers`, because a multi-peer listener cannot unambiguously bind one local listener to one remote peer.
- Multi-transport mode is currently intended for listening instances without configured transport peers (for example no `--udp-peer`, `--tcp-peer`, `--quic-peer`, or `--ws-peer`).
- WebSocket listener mode supports multiple simultaneous peers with per-peer mux-channel rewriting so that peer-local channel IDs do not collide inside the shared mux logic.
