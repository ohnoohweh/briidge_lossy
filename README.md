# ObstacleBridge
ObstacleBridge is a Python-based overlay and channel-multiplexing toolkit for barrier-resilient networking. It can run over multiple overlay transports (`myudp`, `tcp`, `quic`, `ws`), expose local TCP/UDP listener services through a reliable overlay, and host an admin UI for monitoring active channels.

## Reader guide

- User: start with `Why this project was developed` and `Quick-start examples`
- Contributor: start with `Contributor guidance`

## For Users

### Whitepaper
The complete whitepaper is available as a rendered preview at [`docs/WHITEPAPER.html`](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/WHITEPAPER.html). It covers:
- Internet barriers such as NAT, DPI, protocol blocking, traffic shaping, and TLS interception.
- Transport-level behavior for IP, ICMP, UDP, TCP, QUIC, DNS, HTTP/HTTPS, and WebSockets.
- The layered overlay architecture used here: RTT/liveness, reliable DATA/CONTROL framing, and ChannelMux OPEN/DATA/CLOSE multiplexing.
- Why UDP overlays can outperform TCP-over-TCP tunnels on hostile paths.
- Development-process lessons from AI-supported programming.

#### Whitepaper abstract
> This whitepaper presents a detailed technical explanation of Internet communication mechanisms and a Python-based UDP overlay protocol designed to work across restrictive network environments. The report explains how modern Internet barriers such as NAT, IPv4/IPv6 asymmetry, deep packet inspection, protocol blocking, traffic shaping, and throttling affect connectivity, and how a layered UDP overlay can reconstruct connection detection, round-trip-time measurement, loss recovery, retransmission, and multi-channel multiplexing in user space.

### Similar projects
- [chisel](https://github.com/jpillora/chisel) — a well-known TCP/UDP tunnel over HTTP/WebSocket implemented in Go.

### Why this project was developed
- `chisel` is implemented in Go, and using/building it on Synology NAS environments can be difficult in practice.
- ObstacleBridge adds the `myudp` transport to better handle network obstacles and traffic degradation conditions seen in large-scale Asian network environments.

### Quick-start examples
The recommended workflow is:

1. start each instance with a small JSON config file
2. enable the Admin Web UI from the beginning
3. tune transports, peers, published services, auth, and logging in the Config tab
4. save the resulting config and use it as the durable runtime definition

This keeps first startup simple and makes larger settings such as `own_servers`, `remote_servers`, auth options, and multi-transport listener combinations much easier to manage than long shell commands.

Important config-format note:

- `--config` / `-c` currently expects a JSON file, not an INI file
- the examples below are therefore shown as JSON so they can be copied directly into a file and loaded without surprises on Linux or Windows
- flat JSON works well for hand-written bootstrap files
- saved config files keep `admin_web_password` and `secure_link_psk` encrypted on disk and restore them when loaded back into the runtime

![WebAdmin Config Editor](docs/refered_docs/WebAdmin%20ConfigEditor.png)

### Minimal bootstrap pattern
Create one JSON config file per instance and only keep a few startup arguments on the command line.

**Listener / server bootstrap**
```json
{
  "overlay_transport": "myudp",
  "udp_bind": "::",
  "udp_own_port": 4443,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18080,
  "log": "INFO"
}
```

```bash
python scripts/run.py --command "python -m obstacle_bridge --config bridge_server.json"
```

**Peer / client bootstrap**
```json
{
  "overlay_transport": "myudp",
  "udp_peer": "bridge.example.com",
  "udp_peer_port": 4443,
  "udp_own_port": 0,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18081,
  "log": "INFO"
}
```

```bash
python scripts/run.py --command "python -m obstacle_bridge --config bridge_client.json"
```

Windows tip:

- save the examples as `bridge_server.json` and `bridge_client.json`
- then run `python scripts/run.py --command "python -m obstacle_bridge --config bridge_server.json"`
- and `python scripts/run.py --command "python -m obstacle_bridge --config bridge_client.json"`
- if you prefer to generate a valid JSON template from the tool itself, use `python -m obstacle_bridge --dump-config json`

After the first startup, open the Admin Web UI and adjust the remaining details there:

- overlay transport mix such as `myudp`, `ws`, `tcp`, or `quic`
- peer target and listener bind/port values
- `own_servers` and `remote_servers`
- admin authentication and instance naming
- logging and log retention settings

### 1) NAS behind outbound-only internet, reached through a public server
This setup fits a NAS or home server that can make outgoing connections but cannot accept incoming internet traffic directly.

Assumptions:

- a public VPS or similar reachable listener host is available
- the NAS can open outbound connections to that listener
- Python and the required runtime dependencies are available on both sides
- the services you want to expose actually exist on the NAS and are reachable locally

Use a small VPS listener config first, then finish the published service mapping in WebAdmin:

Issue before ObstacleBridge:

![NAS issue example](docs/refered_docs/NAS_Issue.svg)

Solution with a public ObstacleBridge server:

![NAS solution example](docs/refered_docs/NAS_solution.svg)

**Public VPS initial config**
```json
{
  "overlay_transport": "myudp",
  "udp_bind": "::",
  "udp_own_port": 4443,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18080,
  "admin_web_name": "VPS",
  "log": "INFO"
}
```

**NAS initial config**
```json
{
  "overlay_transport": "myudp",
  "udp_peer": "bridge.example.com",
  "udp_peer_port": 4443,
  "udp_own_port": 0,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18081,
  "admin_web_name": "NAS",
  "log": "INFO"
}
```

Then use WebAdmin to add the service exposure you want, for example:

- VPS listener publishes NAS SSH as TCP `18022 -> 127.0.0.1:22`
- VPS listener publishes NAS HTTP/HTTPS as TCP `80` and `443`
- NAS peer publishes its admin UI back to the VPS on a separate TCP port such as `18081`

### 2) WireGuard bridge through inspected internet access
This fits environments where raw VPN UDP is blocked or degraded, but HTTP(S)-shaped traffic still survives.

Assumptions:

- the surrounding network still permits the chosen fallback transport, for example WebSocket
- both sides can run ObstacleBridge with the required dependencies
- the local WireGuard or UDP OpenVPN service already exists and listens on the configured endpoint

Start with a WebSocket-based config and then use WebAdmin to define the local UDP service recreation:

Issue before ObstacleBridge:

![Client issue example](docs/refered_docs/Client_issue.svg)

Solution with an ObstacleBridge WebSocket bridge:

![Client solution example](docs/refered_docs/Client_solution.svg)

**Public bridge config**
```json
{
  "overlay_transport": "ws",
  "ws_bind": "0.0.0.0",
  "ws_own_port": 443,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18080,
  "admin_web_name": "Public WS Bridge",
  "log": "INFO"
}
```

**Restricted-side peer config**
```json
{
  "overlay_transport": "ws",
  "ws_peer": "bridge.example.com",
  "ws_peer_port": 443,
  "ws_own_port": 0,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18081,
  "admin_web_name": "Restricted Client",
  "log": "INFO"
}
```

Then use WebAdmin to add an `own_servers` entry that recreates the local WireGuard or UDP OpenVPN endpoint, for example `udp,16666,127.0.0.1,udp,127.0.0.1,16666`.

### 3) WireGuard bridge for high-loss obstacle conditions
This fits paths where UDP still passes, but loss and retransmission pressure make conventional transports perform badly.

Assumptions:

- the network still passes enough UDP for `myudp` to operate
- both peers can run the selected config and local UDP service recreation
- the local VPN endpoint or other UDP application already exists on the configured address and port

Start with `myudp` in the config file and use WebAdmin to finish the local service mapping:

Issue before ObstacleBridge:

![Client2 issue example](docs/refered_docs/Client2_issue.svg)

Solution with an ObstacleBridge `myudp` bridge:

![Client2 solution example](docs/refered_docs/Client2_solution.svg)

**Public bridge config**
```json
{
  "overlay_transport": "myudp",
  "udp_bind": "0.0.0.0",
  "udp_own_port": 4433,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18080,
  "admin_web_name": "Public myudp Bridge",
  "log": "INFO"
}
```

**Restricted-side peer config**
```json
{
  "overlay_transport": "myudp",
  "udp_peer": "bridge.example.com",
  "udp_peer_port": 4433,
  "udp_own_port": 0,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18081,
  "admin_web_name": "Lossy Client",
  "log": "INFO"
}
```

Then use WebAdmin to add the same local UDP recreation for WireGuard or UDP OpenVPN, usually on `127.0.0.1:16666`.

### 4) Peer client with both inspected-path and high-loss-path transports
If you want one peer config that can use both WebSocket and `myudp`, keep the bootstrap config simple and tune the rest in WebAdmin:

Assumptions:

- both transport paths are meaningful in the target environment
- the listener side is configured to accept the selected transports
- the client environment can use the required runtime dependencies for both overlay modes

```json
{
  "overlay_transport": "ws,myudp",
  "ws_peer": "bridge.example.com",
  "ws_peer_port": 443,
  "ws_own_port": 0,
  "udp_peer": "bridge.example.com",
  "udp_peer_port": 4433,
  "udp_own_port": 0,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18081,
  "admin_web_name": "Dual Transport Client",
  "log": "INFO"
}
```

Then use WebAdmin to define:

- the local UDP service recreation such as WireGuard on `127.0.0.1:16666`
- any additional published TCP or UDP services
- authentication, log policy, and instance naming

Using config files plus WebAdmin makes these multi-transport setups much easier to review and maintain than long shell commands with many inline options.

### 5) TUN interface example (Linux and Windows)

A TUN device is a virtual Layer 3 network interface. It is useful when you want to tunnel complete IP traffic between two hosts or sites instead of exposing only individual TCP or UDP ports. In practice, that means you can use ObstacleBridge to carry routed subnet traffic in the same general way that tools such as WireGuard or OpenVPN carry virtual network traffic.

ChannelMux can expose a local TUN interface as a muxed packet service. The service-spec format uses the existing six-field syntax:

```text
tun,<local_mtu>,<local_ifname>,tun,<remote_ifname>,<remote_mtu>
```

Interpretation:

- `local_ifname` is the interface name to create on this side
- `local_mtu` is the MTU to apply on this side
- `remote_ifname` is the interface name the peer should create
- `remote_mtu` is the MTU to apply on the peer side

Example pair:

- client `own_servers`: `tun,1400,obtun0,tun,obtun1,1400`
- server `remote_servers`: `tun,1400,obtun1,tun,obtun0,1400`

Linux (native) notes

- Linux uses `/dev/net/tun` and the standard Python library.
- The process needs permission to create and configure TUN devices; ObstacleBridge brings the interface up and applies MTU, but it does not assign IP addresses for you.

Example Linux IP assignment (run as root):

```bash
sudo ip addr add 10.20.0.1/30 dev obtun0
sudo ip link set obtun0 up
```

Windows (WinTun) notes — tested path

- ObstacleBridge uses a WinTun adapter on Windows. This requires the Wintun driver (tested with Wintun 0.14.1 from https://www.wintun.net/).
- Administrative privileges are required to install the Wintun driver and to create or configure virtual interfaces.
- The default and tested Windows runtime path in this repository is direct ctypes binding to `wintun.dll`.

How to use a downloaded Wintun folder with this project

- Download and extract the Wintun release from https://www.wintun.net/ and install the driver per the Wintun instructions.
- Point ObstacleBridge to the folder that contains the desired `wintun.dll` by setting the `WINTUN_DIR` environment variable to the folder containing the DLL, or to a parent folder that contains `bin\\amd64` or `bin\\x86` subfolders.

Expected Wintun release layout

- Official Wintun releases include a small layout such as:
  - `bin\<arch>\wintun.dll` (for example `bin\amd64\wintun.dll` or `bin\x86\wintun.dll`)
  - `include\wintun.h`
  - `LICENSE.txt`, `README.md`, and similar release files

- ObstacleBridge autodetects the DLL and prefers the file under `bin\<arch>\wintun.dll` that matches the running Python process architecture (64-bit Python -> `amd64` or `x64`, 32-bit Python -> `x86`). If `WINTUN_DIR` points at the top-level extracted folder, the code looks inside its `bin` subfolders for the matching architecture. To force a particular DLL, set `WINTUN_DIR` to the exact folder that contains `wintun.dll`, for example `...\bin\amd64`.

PowerShell examples (set permanently for the current user):

```powershell
# If your DLL is in a top-level folder containing the DLL directly:
setx WINTUN_DIR "C:\\Program Files\\Wintun"

# Or point to the specific architecture subfolder (preferred to force x64 vs x86):
setx WINTUN_DIR "C:\\path\\to\\wintun\\bin\\amd64"
```

Notes on selecting the correct DLL

- Match the DLL architecture to the running Python process: use an `amd64` (x64) DLL with 64-bit Python, or `x86` (32-bit) DLL with 32-bit Python. To check Python bitness run:

```powershell
python -c "import struct; print(struct.calcsize('P')*8)"  # prints 64 or 32
```

- ObstacleBridge will attempt to autodetect and load `wintun.dll` from:
  - the folder specified by `WINTUN_DIR` (if set)
  - common Program Files locations (`C:\\Program Files\\Wintun` or `C:\\Program Files (x86)\\Wintun`)
  - `System32` or `SysWOW64`
  - the current working directory

- If autodetection loads the wrong architecture or the wrong DLL, set `WINTUN_DIR` to the specific folder that holds the desired `wintun.dll`, for example `...\\bin\\amd64`, and restart the process.

Running example (PowerShell, run as Administrator when creating adapters):

```powershell
$env:WINTUN_DIR = 'C:\\path\\to\\wintun\\bin\\amd64'  # or setx as shown above
python -u scripts\\wintun_example.py --duration 5
```

What `scripts/wintun_example.py` does

- loads `wintun.dll` through the same direct ctypes path used by the default Windows runtime
- creates a temporary Wintun adapter
- starts a packet session on that adapter
- sends one small test packet into the adapter
- polls briefly for received packets
- closes the session and adapter again

What to expect on success

- `Loaded wintun.dll from ...`
- `Creating adapter: ...`
- `Adapter handle: ...`
- `Session started`
- `Sent test packet`
- `Session ended`
- `Adapter closed`

- depending on the Windows network stack behavior on that machine, one or more `Received packet size=...` lines may also appear during the polling window

What failures usually mean

- `Unable to load wintun.dll`: `WINTUN_DIR` points to the wrong folder, the DLL is missing, or the DLL architecture does not match the Python process
- `WintunCreateAdapter failed`: the process is not elevated, the driver is not installed correctly, or Windows rejected adapter creation
- `WintunStartSession failed`: adapter creation succeeded, but the packet session could not be started; this usually points to a driver or runtime state problem on the host

Runtime behavior and caveats

- The default runtime path on Windows binds directly to `wintun.dll` using ctypes.
- The ctypes path requires only `wintun.dll` and the driver; no project-specific files need to be added to the downloaded Wintun folder for runtime use.
- Creating adapters and manipulating virtual interfaces requires Administrator privileges; run the process elevated when exercising adapter creation.

## Entry points
- recommended runtime launcher: `python scripts/run.py`
- direct CLI help: `python -m obstacle_bridge --help`

If your configuration includes any `tun,...` service entries, start ObstacleBridge with elevated operating-system privileges. On Linux that normally means root or equivalent permission to manage `/dev/net/tun`; on Windows that means an Administrator session plus a usable WinTun installation.

### Launcher script

Use the cross-platform Python launcher at `scripts/run.py`. This is the recommended way to start normal runtime instances because it supports the project's restart workflow.

- Default (uses the running Python interpreter and `ObstacleBridge.cfg`):

```bash
python scripts/run.py
```

- Windows (show output; useful for debugging):

```powershell
python .\scripts\run.py --no-redirect
```

- Supply a custom command instead of the default:

```bash
python scripts/run.py --command "python -m obstacle_bridge --config ObstacleBridge.cfg"
```

Options: `--interval` (seconds between restarts when the process exits with code 75), `--no-redirect` (do not redirect stdout/stderr), and `--command` to override the default launcher command.

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
| `--ws-payload-mode` | `binary` | WebSocket payload transfer mode: raw binary frames (default), grouped `semi-text-shape` text frames, base64 text frames, or JSON text frames with the base64 payload in the data field. |
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

Current direct WebSocket peer-client bootstrap also performs a separate `GET /` preflight on a separate TCP connection before the later WebSocket upgrade attempt. That preflight must return `200 OK`, the client downloads the full response body before continuing, and the later WebSocket upgrade is refused when the preflight status is not `200`. The proxy-tunneled path skips this preflight.

Current websocket payload forms:

- `binary`: raw overlay wire bytes in websocket binary frames
- `semi-text-shape`: grouped 6-bit text symbols using `A-Z`, `a-z`, `0-9`, `-`, and `+`, with whitespace between runs of up to 8 symbols
- `base64`: one base64 text frame per overlay payload
- `json-base64`: compact JSON text with the base64 payload in the `data` field
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

When `--admin-web-username` and `--admin-web-password` are configured and auth is not disabled, the admin web page requires a challenge-response login. The browser requests a one-time seed, hashes `seed:username:password` client-side, and sends only the hash proof back to the server. The login flow works over HTTP as well as HTTPS; when the browser is not in a secure context, the admin page uses a JavaScript SHA-256 fallback instead of Web Crypto. The configured password is not returned by the admin config API.

Saving configuration changes uses a second challenge-response confirmation bound to the exact update block, so the current admin password must be re-entered before the server applies guarded config writes.

The admin-web design note in [docs/WEBADMIN_DESIGN.md](docs/WEBADMIN_DESIGN.md) explains the applied auth, session, live-update, and secret-redaction concepts in more detail.

#### Admin web examples

The repository includes two exported admin web snapshots:

- [docs/refered_docs/ObstacleBridge Client.html](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/refered_docs/ObstacleBridge%20Client.html) shows a peer/client-side view.
- [docs/refered_docs/ObstacleBridge Server.html](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/refered_docs/ObstacleBridge%20Server.html) shows a listener/server-side view.

Client admin web screenshot:

![ObstacleBridge client admin web screenshot](docs/refered_docs/ObstaceBridge%20Client.png)

What the admin web shows:

- A summary row with the currently open UDP and TCP channel counts.
- Traffic cards for app-side RX/TX and peer-side RX/TX rates.
- A peer-session table that now groups each peer into connection, protocol, security, and lifecycle rows so secure-link state stays with the peer it belongs to.
- UDP and TCP connection tables that show current mappings, local listening ports, remote endpoints, and per-channel byte/message counters.
- A peer-scoped rekey action inside each peer security block for operator-triggered secure-link rotation on authenticated client-side sessions.
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
| `--overlay-reconnect-retry-delay-ms` | `30000` | Delay in milliseconds between failed reconnect attempts for `tcp`/`quic`/`ws` client overlays. |
| `--client-restart-if-disconnected` | `0.0` | If configured as a peer client (for example --udp-peer set) and overlay stays disconnected for this many seconds, request process restart. 0 disables. |

### Secure-link

#### Common parameters
| Option(s) | Default | Description |
|---|---:|---|
| `--secure-link` | `False` | Enable secure-link. Delivered modes are PSK and certificate-based secure-link over `myudp`, `tcp`, `ws`, and `quic`. |
| `--secure-link-mode` | `off` | Secure-link mode. Supported values are `off`, `psk`, and `cert`. |
| `--secure-link-retry-backoff-initial-ms` | `1000` | Initial client-side retry backoff after a secure-link authentication failure, in milliseconds. |
| `--secure-link-retry-backoff-max-ms` | `5000` | Maximum client-side retry backoff after repeated secure-link authentication failures, in milliseconds. |
| `--secure-link-require` | `False` | Fail closed if secure-link cannot be negotiated or authenticated. |

#### PSK mode parameters
| Option(s) | Default | Description |
|---|---:|---|
| `--secure-link-psk` | `` | Pre-shared secret for `secure_link_mode=psk`. Both peers must use the same non-empty value. |
| `--secure-link-rekey-after-frames` | `0` | Automatically initiate PSK rekey after this many protected data frames are sent. `0` disables frame-triggered rekeying. |
| `--secure-link-rekey-after-seconds` | `0.0` | Automatically initiate PSK rekey after this many authenticated seconds, once the current session has already carried protected client data. `0` disables time-triggered rekeying. |

#### Cert mode parameters
| Option(s) | Default | Description |
|---|---:|---|
| `--secure-link-root-pub` | `` | Root public key PEM for `secure_link_mode=cert`. |
| `--secure-link-cert-body` | `` | Local certificate body JSON for `secure_link_mode=cert`. |
| `--secure-link-cert-sig` | `` | Detached certificate signature file for `secure_link_mode=cert`. |
| `--secure-link-private-key` | `` | Local identity private key PEM for `secure_link_mode=cert`. |
| `--secure-link-revoked-serials` | `` | Optional JSON-array or line-based revoked-serial file for `secure_link_mode=cert`. |
| `--secure-link-cert-reload-on-restart` | `True` | Reload certificate material on process restart. In `secure_link_mode=cert`, operators can also trigger live reload through the admin API or WebAdmin. |

#### Current secure-link quick start

The current runtime includes both delivered secure-link modes:

- `secure_link_mode=psk`
- `secure_link_mode=cert`

Recommended operator flow:

1. enable WebAdmin on both peers
2. configure secure-link in the JSON config file or through the Configuration tab
3. start both peers and open the peer cards in WebAdmin first
4. use the API only for details that are not yet surfaced in WebAdmin

What works today:

- `overlay_transport=myudp`
- `overlay_transport=tcp`
- `overlay_transport=ws`
- `overlay_transport=quic`
- secure-link visibility in WebAdmin, with API fallback through `/api/status` and `/api/peers`
- optional automatic rekey through `secure_link_rekey_after_frames`
- optional time-based rekey through `secure_link_rekey_after_seconds`
- operator-forced rekey from the peer security block in WebAdmin, with `/api/secure-link/rekey` available for automation
- `myudp` PSK rekey that still completes under ongoing protected traffic and preserves healthy same-channel UDP flow across the `REKEY_COMMIT` to `REKEY_DONE` cutover window
- cert-mode trust-anchor, role, validity-window, deployment-scope, and revoked-serial enforcement before protected traffic starts
- cert-mode peer identity and trust diagnostics in WebAdmin, with additional detail available through `/api/peers`
- cert-mode live reload from the Secure-Link tab in WebAdmin through the `Reload Revocation`, `Reload Local Identity`, and `Reload All` buttons, with `/api/secure-link/reload` available for automation
- aggregate reload/apply summaries and some peer-scoped enforcement diagnostics through `/api/status` and `/api/peers`

What is still planned:

- operator tooling for certificate issuance/rotation
- in-product certificate/key generation and signing workflows

Minimal listener example:

```json
{
  "overlay_transport": "tcp",
  "tcp_bind": "::",
  "tcp_own_port": 8081,
  "secure_link": true,
  "secure_link_mode": "psk",
  "secure_link_psk": "change-this-demo-secret",
  "secure_link_rekey_after_frames": 0,
  "secure_link_rekey_after_seconds": 0.0,
  "secure_link_require": true,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18080,
  "log": "INFO"
}
```

Cert-mode operators can also apply updated trust material without process restart from the Secure-Link tab in WebAdmin:

- use `Reload Revocation` after updating the revoked-serials file
- use `Reload Local Identity` after replacing the local certificate/signature/private-key material
- use `Reload All` when both trust inputs changed and you want one operator action to apply the full set

The same reload scopes remain available through `/api/secure-link/reload` for automation.

Detailed API signals after a cert-mode reload succeeds:

- `/api/status` reports the aggregate reload result, scope, timestamp, active material generation, and cumulative dropped-peer count
- `/api/peers` reports peer-scoped reload/enforcement details such as active material generation, trust-enforcement timestamp, and disconnect reason/detail
- peers invalidated by a new revocation set are dropped immediately
- peers authenticated under superseded local identity material are dropped and must re-authenticate under the new generation

Minimal peer example:

```json
{
  "overlay_transport": "tcp",
  "tcp_peer": "127.0.0.1",
  "tcp_peer_port": 8081,
  "tcp_own_port": 0,
  "secure_link": true,
  "secure_link_mode": "psk",
  "secure_link_psk": "change-this-demo-secret",
  "secure_link_rekey_after_frames": 0,
  "secure_link_rekey_after_seconds": 0.0,
  "secure_link_require": true,
  "admin_web": true,
  "admin_web_bind": "127.0.0.1",
  "admin_web_port": 18081,
  "log": "INFO"
}
```

Start them with:

```bash
python scripts/run.py --command "python -m obstacle_bridge --config secure_link_server.json"
python scripts/run.py --command "python -m obstacle_bridge --config secure_link_client.json"
```

What to look for in WebAdmin first:

- WebAdmin shows secure-link details inside each peer block instead of a single legacy headline state, with peer cards laid out full-width across the browser
- the Configuration tab masks `secure_link_psk` and keeps it write-only in the web UI so the PSK secret is not exposed for editing after startup
- peer cards show connection uptime, and myudp-specific protocol statistics remain visible only when the peer is actually using the myudp transport
- when `secure_link.mode=cert`, WebAdmin also shows peer identity and trust details such as subject id/name, roles, deployment id, serial, issuer, trust-anchor id, and trust-validation status
- when rekeying is enabled, the peer block can briefly show `rekey_in_progress=true` while the session rotates to a fresh `secure_link.session_id`
- on healthy authenticated runs, the peer block exposes `last_event`, `last_event_unix_ts`, `last_authenticated_unix_ts`, `authenticated_sessions_total`, `rekeys_completed_total`, and `last_rekey_trigger`
- operators can force rekey on an authenticated client-side secure-link session from the peer security block in WebAdmin

API fallback for details not fully surfaced in WebAdmin yet:

- `/api/peers` shows the peer row with `secure_link.authenticated=true`
- `/api/status` remains limited to common runtime summary fields such as uptime, aggregate open-channel counts, and aggregate traffic rates
- if the PSK does not match, the client and server stay disconnected and the failure is reported as:
  - `secure_link.state=failed`
  - `failure_code=1`
  - `failure_reason=bad_psk`
  - repeated client-side retries show increasing `consecutive_failures`, a bounded `retry_backoff_sec`, a populated `next_retry_unix_ts`, a populated `failure_session_id`, increasing `handshake_attempts_total`, and `last_event=retry_scheduled`

Current WebAdmin gap to close in a future update:

- aggregate cert-reload results and some peer-scoped enforcement diagnostics are still easier to inspect through `/api/status` and `/api/peers` than through WebAdmin

API alternative for operator-forced rekey when scripting or automation is preferred:

```bash
curl -sS -X POST http://127.0.0.1:18081/api/secure-link/rekey \
  -H 'Content-Type: application/json' \
  -d '{"peer_id":"0:0"}'
```

Operator notes:

- use `--secure-link-require` when you want a hard failure instead of falling back to plaintext behavior
- use a long random PSK for anything beyond local testing
- leave `secure_link_rekey_after_frames=0` unless you intentionally want to exercise or validate rekey behavior
- use `secure_link_rekey_after_seconds` when you want automatic rotation on long-lived authenticated client-side sessions without waiting for a frame-count threshold
- operator-forced rekey currently applies to authenticated client-side secure-link sessions for the targeted peer row; if no protected client data has been sent yet, the WebAdmin action and admin API both reject the request rather than guessing its way past the handshake boundary
- if you are intentionally testing wrong-PSK or rollout mistakes, `secure_link_retry_backoff_initial_ms` and `secure_link_retry_backoff_max_ms` let you tune how aggressively the client retries after secure-link auth failures
- the current PSK runtime uses strictly monotonic per-direction protected-data counters starting at `1`; counter `0` is reserved and counter exhaustion fails closed rather than wrapping
- malformed or unexpected secure-link frames fail closed and remain observable through the admin/API surface; they do not continue forwarding overlay traffic on the affected peer
- the delivered PSK mode remains useful for development/testing/lab bring-up, while the delivered cert mode is the deployment-rooted trust model described in [docs/SECURE_LINK_DESIGN.md](docs/SECURE_LINK_DESIGN.md)

#### Secure-link certificate setup

The current runtime supports `secure_link_mode=cert`, and the following workflow is the expected way to prepare the certificate/key material that mode consumes.

The trust model is:

- one admin root keypair per deployment
- one leaf keypair per peer client or peer server
- one admin-signed leaf certificate per peer

#### 1. Generate the admin root keypair

```bash
openssl genpkey -algorithm ED25519 -out admin_root_key.pem
openssl pkey -in admin_root_key.pem -pubout -out admin_root_pub.pem
```

Keep:

- `admin_root_key.pem` offline and tightly controlled
- `admin_root_pub.pem` distributed to the peer client and peer server nodes that should trust this deployment

#### 2. Generate a leaf keypair for one peer

Example for a listener/server identity:

```bash
openssl genpkey -algorithm ED25519 -out peer_server_key.pem
openssl pkey -in peer_server_key.pem -pubout -out peer_server_pub.pem
```

Repeat the same pattern for a client identity, for example:

```bash
openssl genpkey -algorithm ED25519 -out peer_client_key.pem
openssl pkey -in peer_client_key.pem -pubout -out peer_client_pub.pem
```

#### 3. Create the unsigned certificate body

The certificate input profile is documented in [docs/SYSTEM_BOUNDARY.md](docs/SYSTEM_BOUNDARY.md). A minimal server leaf example looks like:

```json
{
  "version": 1,
  "serial": "srv-0001",
  "issuer_id": "deployment-admin",
  "subject_id": "bridge-server-01",
  "subject_name": "Public Bridge Server",
  "deployment_id": "lab-a",
  "public_key_algorithm": "Ed25519",
  "public_key": "BASE64_ENCODED_PUBLIC_KEY",
  "roles": ["server"],
  "issued_at": "2026-04-04T12:00:00Z",
  "not_before": "2026-04-04T12:00:00Z",
  "not_after": "2027-04-04T12:00:00Z",
  "constraints": []
}
```

Replace `BASE64_ENCODED_PUBLIC_KEY` with the actual leaf public key material.

Important:

- the file must be one valid JSON object
- include the opening `{` and closing `}`
- do not paste multiple JSON objects into the same file

If you want to sanity-check the file before canonicalizing it:

```bash
python -m json.tool peer_server_cert_body.json > /dev/null
```

#### 4. Canonicalize the certificate body before signing

One simple dependency-light way is to use Python itself to emit a stable compact JSON form:

```bash
python -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1], 'r', encoding='utf-8')), sort_keys=True, separators=(',', ':')))" \
  peer_server_cert_body.json > peer_server_cert_body.c14n.json
```

If that command fails with `JSONDecodeError: Extra data`, the input file is not a single valid JSON object. A common cause is a missing opening `{` or accidentally pasting extra lines into the file.

The runtime signs the canonicalized certificate body, excluding the `signature` field itself.

#### 5. Sign the canonicalized body with the admin root key

```bash
openssl pkeyutl -sign -rawin \
  -inkey admin_root_key.pem \
  -in peer_server_cert_body.c14n.json \
  -out peer_server_cert.sig
```

Optional verification step:

```bash
openssl pkeyutl -verify -rawin -pubin \
  -inkey admin_root_pub.pem \
  -in peer_server_cert_body.c14n.json \
  -sigfile peer_server_cert.sig
```

#### 6. Provide the runtime inputs

For cert mode, each node needs:

- its own certificate body JSON
- its own detached certificate signature
- its own private key PEM
- the deployment root public key PEM
- optionally a revoked-serials file

This stays consistent with the current runtime boundary:

- ObstacleBridge uses key material and certificates
- ObstacleBridge does not generate private keys or sign certificates
- primitive signature verification and encryption/decryption are delegated to the selected crypto library in the delivered secure-link runtime

## Notes
- Listener mode intentionally ignores `--own-servers`, because a multi-peer listener cannot unambiguously bind one local listener to one remote peer.
- Multi-transport mode is currently intended for listening instances without configured transport peers (for example no `--udp-peer`, `--tcp-peer`, `--quic-peer`, or `--ws-peer`).
- WebSocket listener mode supports multiple simultaneous peers with per-peer mux-channel rewriting so that peer-local channel IDs do not collide inside the shared mux logic.

## For Contributors

### Contributor guidance
- Development process: [docs/DEVELOPMENT_PROCESS.md](docs/DEVELOPMENT_PROCESS.md)
- User use-cases in the README: [README.md](README.md)
- System boundary and assumptions: [docs/SYSTEM_BOUNDARY.md](docs/SYSTEM_BOUNDARY.md)
- Requirements: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- Testing guide and traceability entrypoints: [docs/README_TESTING.md](docs/README_TESTING.md)

Testing statistics (see [docs/README_TESTING.md](docs/README_TESTING.md)): `135` integration tests, `138` unit tests. Current branch validation also includes the CI-aligned Linux shared run `pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"`, the Linux elevated TUN subset `pytest -q tests/integration/test_linux_elevated.py -m "linux_elevated"`, and the Windows elevated TUN subset `pytest -q tests/integration/test_windows_elevated.py -m "windows_elevated"`.

The shared integration harness now generates localhost TLS test certificates in a temporary directory outside the repository and uses availability-aware loopback port allocation when materializing test cases. This keeps private key material out of version control and makes the Linux shared `xdist` run resilient to host services that already occupy uncommon local ports.

### Current requirements coverage
Current snapshot from `python scripts/report_requirements_coverage.py`:

- Integration-covered: `70/74 = 94.6%`
- Unit-covered: `51/74 = 68.9%`
- Any-test-covered: `74/74 = 100.0%`
- Tracked in manifest: `74/74 = 100.0%`
- Requirements without integration coverage: `REQ-ADM-007`, `REQ-ADM-008`, `REQ-ADM-009`, `REQ-LIFE-006`

The supporting product-requirement traceability manifest used for this snapshot is maintained in `.github/requirements_traceability.yaml`.

The related architecture decomposition is linked to tests through `.github/architecture_traceability.yaml`.

This top-level section is a compact coverage snapshot. Update the counts and supporting links here when requirements, implementation, or the test set changes. Keep detailed behavior, rationale, and traceability discussion in `docs/REQUIREMENTS.md`, `docs/ARCHITECTURE.md`, `docs/SYSTEM_BOUNDARY.md`, and `docs/README_TESTING.md`.

### CI split note

- Linux runs the OS-independent shared integration suite with `pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"`
- Linux runs the elevated TUN subset separately with `pytest -q tests/integration/test_linux_elevated.py -m "linux_elevated"`
- Windows runs the Windows-specific non-elevated integration subset with `pytest -q -n 4 tests/integration/test_overlay_e2e.py -m "windows_only"`
- Windows runs the elevated TUN subset separately with `pytest -q tests/integration/test_windows_elevated.py -m "windows_elevated"`
- Recent validation for this branch used the Windows-local unit suite, the Windows `windows_only` subset, the Windows elevated TUN subset, and the Linux shared integration subset; the dedicated Linux elevated subset is part of the split CI expectation as well.
- The Linux shared integration subset is currently validated with the runtime-generated localhost TLS fixture set and the availability-aware loopback port allocator in the integration harness.

### Development environment and procedure
- Feature development is done on Fedora 42.
- The primary IDE is Visual Studio Code.
- ChatGPT 5.4 Codex integration is used for implementation support.
- Changes are mainly prompt-driven, with comparatively little direct source editing by hand.
- On each change, the focus is on test feedback and on extending the test environment to cover the functional increase.
- Integration testing is executed on a local machine running Python 3.13.12.
- After successful local validation, deployment is tested on a VPS running Ubuntu 24.04.03 LTS with Python 3.12.3 and a Fedora 42 client system.
- After successful validation there, deployment is also intended for the productive NAS environment running DSM 7.12 with Python 3.9.

### Trouble shooting recommendations
Debugging in a project like this can be difficult because the behavior emerges from the interaction of different peers, while the relevant evidence is often hidden in a large amount of runtime data.

- Enable logging on the relevant component, generate log files, and analyze them carefully. In practice it is often effective to use AI assistance to summarize the logs and provide reasoning about the likely sequence of events.
- Avoid guessing. If the evidence is not strong enough, extend the logging so that the next run produces harder facts instead of more assumptions.
- Keep in mind that the application log only shows what the application is attempting to hand over to the network stack. That does not necessarily prove that the same traffic was actually sent on the network or reached the remote side.
- When transport behavior is in doubt, capture network traffic with tools such as `tcpdump`. Do this on both peer client and peer server whenever possible so the full picture can be reconstructed from both ends.
- Try to reproduce problems in a lower-complexity environment such as the local development machine before debugging them in a more distributed or production-like setup.
- Create integration test cases for controlled reproduction whenever a bug or unclear transport interaction is found.
- Add those reproduction cases to the regression suite so future releases continue to cover the behavior and the functionality does not silently erode over time.

### Testing strategy
- Run the regular pytest suite during normal development to cover unit, integration, and overlay harness regression paths.
- Use the parallel overlay harness for frequent end-to-end validation when transport and socket behavior matter most.
- Keep reconnect, listener, and concurrent multi-peer coverage in the regular regression flow instead of treating them as occasional manual checks.
- The full testing catalog, commands, and scenario-by-scenario criteria are documented in [docs/README_TESTING.md](docs/README_TESTING.md).

### Repository layout
- `src/obstacle_bridge/` — main implementation.
- `tests/unit/` — targeted unit tests.
- `tests/integration/` — end-to-end and subprocess tests.
- `scripts/` — development helpers.
- `docs/` — main project documents such as requirements, architecture, development process, system boundary, testing guide, and whitepaper.
- `docs/SECURE_LINK_DESIGN.md` — Phase 0 design baseline for transport-independent tunnel authentication and encryption.
- `docs/refered_docs/` — referenced examples, exported admin snapshots, diagrams, images, and the smoke-test cheat sheet.
- `.github/requirements_traceability.yaml` — product-requirement to test traceability manifest used by the requirements guard and coverage report.
- `docs/refered_docs/ObstacleBridge Client.html` — exported example of the admin web UI on a peer/client instance. Rendered preview: `https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/refered_docs/ObstacleBridge%20Client.html`
- `docs/refered_docs/ObstacleBridge Server.html` — exported example of the admin web UI on a listener/server instance. Rendered preview: `https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/refered_docs/ObstacleBridge%20Server.html`
- `docs/WHITEPAPER.html` — full whitepaper requested for this repository update. Rendered preview: `https://htmlpreview.github.io/?https://raw.githubusercontent.com/ohnoohweh/briidge_lossy/main/docs/WHITEPAPER.html`
- `docs/README_TESTING.md` — consolidated testing catalog, execution commands, and regression coverage notes.
- `wireshark/` — Wireshark dissectors grouped by framing/version.
