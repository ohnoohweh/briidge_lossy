# Smoke test cheat sheet

This file replaces the old `testbed.txt` format with Markdown and uses the current CLI option names from `python -m obstacle_bridge --help`.

## 1) Overlay TTY loopback helpers

### IPv4 TCP
- **Purpose:** Start a local TCP echo-style overlay test server on port `3128`.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto tcp --role server --port 3128
```
- **Purpose:** Connect a local TCP test client to the same local TCP test port `3128`.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto tcp --role client --host 127.0.0.1 --connect-port 3128
```

### IPv4 UDP
- **Purpose:** Start a local UDP echo-style overlay test server on port `16666`.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role server --port 16666
```
- **Purpose:** Connect a local UDP test client to the same local UDP test port `16666`.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role client --host 127.0.0.1 --connect-port 16666
```

### IPv6 UDP
- **Purpose:** Start an IPv6 UDP test server listening on all interfaces.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role server --listen-bind :: --port 16666
```
- **Purpose:** Connect an IPv6 UDP test client to the same local UDP test port `16666`.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role client --host ::1 --bind :: --connect-port 16666
```

### IPv6 TCP
- **Purpose:** Start an IPv6 TCP test server listening on all interfaces.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto tcp --role server --listen-bind :: --port 3128
```
- **Purpose:** Connect an IPv6 TCP test client to the same local TCP test port `3128`.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto tcp --role client --host ::1 --bind :: --connect-port 3128
```

## 2) Default UDP-overlay bridge examples (myudp)

### UDP over overlay (IPv4)
- **Purpose:** Run the destination UDP service that receives forwarded traffic.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role server --port 16666
```
- **Purpose:** Run bridge listener/server on UDP overlay port `443`.
```bash
python -m obstacle_bridge --udp-bind 0.0.0.0 --udp-own-port 443 --log INFO --log-file br_server_ipv4.txt
```
- **Purpose:** Run peer/client that connects to bridge server and exposes local UDP listener `16667` forwarding to remote `127.0.0.1:16666`.
```bash
python -m obstacle_bridge --udp-bind 0.0.0.0 --udp-peer 127.0.0.1 --udp-peer-port 443 --udp-own-port 0 --own-servers "udp,16667,0.0.0.0,udp,127.0.0.1,16666" --log INFO --log-file br_client_ipv4.txt
```
- **Purpose:** Send test UDP payloads into the local exposed listener.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role client --host 127.0.0.1 --connect-port 16667
```

### UDP over overlay (IPv6 transport, IPv6 client access)
- **Purpose:** Run destination UDP service over IPv6.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role server --listen-bind :: --port 16666
```
- **Purpose:** Run bridge listener/server over IPv6 UDP transport.
```bash
python -m obstacle_bridge --udp-bind :: --udp-own-port 443 --log INFO --log-file br_server_ipv6.txt
```
- **Purpose:** Run peer/client over IPv6 UDP transport and publish an IPv6 local UDP listener.
```bash
python -m obstacle_bridge --udp-bind :: --udp-peer ::1 --udp-peer-port 443 --udp-own-port 0 --own-servers "udp,16667,::,udp,::1,16666" --log INFO --log-file br_client_ipv6.txt
```
- **Purpose:** Send test UDP payloads through the IPv6 exposed listener.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role client --host ::1 --bind :: --connect-port 16667
```

### TCP over overlay (IPv4 client access)
- **Purpose:** Run destination TCP service that receives forwarded traffic.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto tcp --role server --port 3128
```
- **Purpose:** Run bridge listener/server on UDP overlay port `443`.
```bash
python -m obstacle_bridge --udp-bind 0.0.0.0 --udp-own-port 443 --log INFO --log-file br_server_tcp_ipv4.txt
```
- **Purpose:** Run peer/client and publish local TCP listener `3129` forwarding to remote `127.0.0.1:3128`.
```bash
python -m obstacle_bridge --udp-bind 0.0.0.0 --udp-peer 127.0.0.1 --udp-peer-port 443 --udp-own-port 0 --own-servers "tcp,3129,0.0.0.0,tcp,127.0.0.1,3128" --log INFO --log-file br_client_tcp_ipv4.txt
```
- **Purpose:** Send test TCP payloads into local exposed TCP listener.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto tcp --role client --host 127.0.0.1 --connect-port 3129
```

## 3) TCP overlay transport example

- **Purpose:** Run target UDP service that the overlay peer will reach.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role server --port 16666
```
- **Purpose:** Run TCP-overlay listener/server on port `12345`.
```bash
python -m obstacle_bridge --overlay-transport tcp --tcp-bind 0.0.0.0 --tcp-own-port 12345 --log DEBUG --log-file br_server_tcp_overlay.txt
```
- **Purpose:** Run TCP-overlay peer/client and expose local UDP `16667` -> remote UDP `127.0.0.1:16666`.
```bash
python -m obstacle_bridge --overlay-transport tcp --tcp-peer 127.0.0.1 --tcp-peer-port 12345 --tcp-own-port 0 --own-servers "udp,16667,0.0.0.0,udp,127.0.0.1,16666" --log DEBUG --log-file br_client_tcp_overlay.txt
```
- **Purpose:** Generate UDP traffic through the TCP overlay path.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role client --host 127.0.0.1 --connect-port 16667
```

## 4) WebSocket overlay transport example

- **Purpose:** Run target UDP service that the WS overlay peer will reach.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role server --port 16666
```
- **Purpose:** (Windows) ensure localhost bypasses outbound proxy for WS local tests.
```bat
set NO_PROXY=127.0.0.1,%NO_PROXY%
```
- **Purpose:** Run WS-overlay listener/server on port `54321`.
```bash
python -m obstacle_bridge --overlay-transport ws --ws-bind 0.0.0.0 --ws-own-port 54321 --log DEBUG --log-file br_server_ws_overlay.txt
```
- **Purpose:** (Windows) ensure localhost bypasses outbound proxy for WS local tests.
```bat
set NO_PROXY=127.0.0.1,%NO_PROXY%
```
- **Purpose:** Run WS-overlay peer/client and expose local UDP `16667` -> remote UDP `127.0.0.1:16666`.
```bash
python -m obstacle_bridge --overlay-transport ws --ws-peer 127.0.0.1 --ws-peer-port 54321 --ws-own-port 0 --own-servers "udp,16667,0.0.0.0,udp,127.0.0.1,16666" --log DEBUG --log-file br_client_ws_overlay.txt
```
- **Purpose:** Generate UDP traffic through the WS overlay path.
```bash
python -m obstacle_bridge.tools.overlay_tty --proto udp --role client --host 127.0.0.1 --connect-port 16667
```

## 5) Admin web quick check

- **Purpose:** Start a listener with admin web enabled for runtime checks.
```bash
python -m obstacle_bridge --udp-bind 0.0.0.0 --udp-own-port 443 --admin-web --admin-web-port 18080 --log INFO --log-file br_server_admin.txt
```
- **Purpose:** Inspect runtime metadata (including selected overlay transport).
```bash
curl -s http://127.0.0.1:18080/api/meta
```
