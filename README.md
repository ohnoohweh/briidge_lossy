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
- `ObstacleBridge.py`
- `python -m obstacle_bridge.tools.overlay_tty`
- `python -m obstacle_bridge.tools.extract_udp_debug`
- `python scripts/run_udp_bidir_tests.py --help`
## Quick-start examples
### 1) Single overlay transport listener
```bash
python -m obstacle_bridge --overlay-transport ws --bind443 0.0.0.0 --port443 54321
```
### 2) Multi-transport listening instance
```bash
python -m obstacle_bridge \
  --overlay-transport "myudp,tcp,quic,ws" \
  --port443 443 \
  --overlay-port-tcp 444 \
  --overlay-port-quic 445 \
  --overlay-port-ws 446 \
  --quic-cert cert.pem \
  --quic-key key.pem
```
If explicit per-transport ports are omitted in multi-transport listener mode, ObstacleBridge derives deterministic offsets from `--port443`: `myudp:+0`, `tcp:+1`, `quic:+2`, `ws:+3`.
### 3) Peer client exposing local services
```bash
python -m obstacle_bridge \
  --overlay-transport ws \
  --peer 203.0.113.10 --peer-port 446 \
  --own-servers "udp,16667,0.0.0.0,udp,127.0.0.1,16666 tcp,3129,0.0.0.0,tcp,127.0.0.1,3128"
```
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
| `--bind443` | `::` | overlay bind address (IPv4 '0.0.0.0' or IPv6 '::') |
| `--port443` | `443` | overlay listen port |
| `--peer` | `None` | peer IP/FQDN (IPv4 or IPv6 literal; IPv6 may be in [brackets]) |
| `--peer-port` | `443` | peer overlay port |
| `--peer-resolve-family` | `prefer-ipv6` | Peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only. |
| `--max-inflight` | `32767` | max DATA frames allowed in flight (1..32767). Excess frames are queued. |

### WebSocket overlay
| Option(s) | Default | Description |
|---|---:|---|
| `--ws-path` | `/` | WebSocket HTTP path (default /) |
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
| `--tcp-bp-latency-ms` | `300` | TCP overlay: if > 0, trigger drain after this latency (ms) whenever pending bytes exist. |
| `--tcp-bp-poll-interval-ms` | `50` | TCP overlay: polling interval for time-based backpressure checks (ms; default 50). |

### QUIC overlay
| Option(s) | Default | Description |
|---|---:|---|
| `--quic-alpn` | `hq-29` | ALPN protocol ID (default hq-29) |
| `--quic-cert` | `None` | Server certificate file (PEM) |
| `--quic-key` | `None` | Server private key file (PEM) |
| `--quic-insecure` | `False` | Client: disable certificate verification (TEST ONLY) |
| `--quic-max-size` | `65535` | Maximum app message size accepted/sent (default 65535). |

### Channel mux
| Option(s) | Default | Description |
|---|---:|---|
| `--own-servers` | `None` | Space-separated service specs (client mode only): 'proto,listen_port,listen_bind,proto,host,port' (quoted). Listener instances ignore --own-servers because multiple overlay peers make the target ambiguous. Example: "tcp,80,0.0.0.0,tcp,127.0.0.1,88 udp,16666,::,udp,127.0.0.1,16666" |
| `--mux-tcp-bp-threshold` | `1` | Mux TCP: size threshold (bytes) to trigger drain() (default 1). |
| `--mux-tcp-bp-latency-ms` | `300` | Mux TCP: if > 0, drain writers after this ms when bytes pending. |
| `--mux-tcp-bp-poll-interval-ms` | `50` | Mux TCP: polling interval for time-based backpressure (ms). |

### Admin web
| Option(s) | Default | Description |
|---|---:|---|
| `--admin-web` | `False` | Enable admin web interface |
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
| `--overlay-port-myudp` | `None` | Optional listen port override for overlay transport myudp. Defaults to --port443 or a deterministic offset when multiple transports are active. |
| `--overlay-port-tcp` | `None` | Optional listen port override for overlay transport tcp. Defaults to --port443 or a deterministic offset when multiple transports are active. |
| `--overlay-port-quic` | `None` | Optional listen port override for overlay transport quic. Defaults to --port443 or a deterministic offset when multiple transports are active. |
| `--overlay-port-ws` | `None` | Optional listen port override for overlay transport ws. Defaults to --port443 or a deterministic offset when multiple transports are active. |
| `--client-restart-if-disconnected` | `0.0` | If configured as a peer client (--peer set) and overlay stays disconnected for this many seconds, request process restart. 0 disables. |

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
- Multi-transport mode is currently intended for listening instances without `--peer`.
- WebSocket listener mode supports multiple simultaneous peers with per-peer mux-channel rewriting so that peer-local channel IDs do not collide inside the shared mux logic.
