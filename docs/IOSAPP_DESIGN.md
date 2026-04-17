# iOS App Design

## Purpose

This document describes how ObstacleBridge can grow into an iOS application comparable in user experience to WireGuard or OpenVPN clients while still reusing as much of the current Python runtime as iOS realistically allows.

The target product is an iPhone/iPad app that can:

- import an ObstacleBridge invite or configuration snippet
- show connection, peer, secure-link, and tunnel status
- start and stop a tunnel from an iOS-native control surface
- carry TUN-style routed IP traffic through ObstacleBridge transports such as `myudp`, `ws`, `tcp`, or `quic`
- preserve the existing ObstacleBridge peer model, secure-link model, service catalog model, and admin observability concepts

This document intentionally separates the first practical mobile step from the full VPN-style endpoint. A normal iOS application and a system VPN tunnel provider have different Apple platform requirements, lifecycles, entitlements, and packaging constraints.

## External platform facts checked

The design is based on the current project plus these platform references:

- BeeWare documentation: https://beeware.org/docs/
- Briefcase iOS platform reference: https://briefcase.beeware.org/en/v0.3.16/reference/platforms/iOS.html
- Apple Network Extension framework: https://developer.apple.com/documentation/NetworkExtension
- Apple packet tunnel provider documentation: https://developer.apple.com/documentation/networkextension/packet-tunnel-provider
- Python 3.13 iOS support notes: https://docs.python.org/3/whatsnew/3.13.html
- PEP 730, adding iOS as a supported CPython platform: https://peps.python.org/pep-0730/

Important interpretation:

- BeeWare/Briefcase is a promising way to package a Python-powered iOS app and produce an Xcode project.
- A WireGuard/OpenVPN-like iOS client is not just a normal app. It requires Apple's Network Extension framework, specifically a packet tunnel provider app extension for custom packet-oriented VPN protocols.
- Therefore, BeeWare is best treated as the management-app path first, while the packet tunnel itself should be designed as an iOS Network Extension with a clear bridge to reusable ObstacleBridge logic.

## Relationship To Existing Project Architecture

The current runtime is already close to the conceptual shape needed by an iOS VPN-style client:

- `ARC-CMP-001` transport/session layer provides `myudp`, `tcp`, `ws`, and `quic` overlay connectivity.
- `ARC-CMP-006` secure-link layer provides peer authentication, encryption, replay defense, rekeying, and diagnostics.
- `ARC-CMP-007` compression layer can reduce selected mux frames.
- `ARC-CMP-003` ChannelMux already supports TCP, UDP, and TUN packet services.
- `ARC-CMP-005` WebAdmin provides a useful mental model for mobile status, onboarding, diagnostics, and guarded configuration writes.

The iOS app should not create a separate protocol family. It should reuse the same overlay wire formats, service definitions, secure-link behavior, and invite/config concepts whenever possible.

Relevant existing documents:

- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md)
- [SECURE_LINK_DESIGN.md](./SECURE_LINK_DESIGN.md)
- [SECURITY_DESIGN.md](./SECURITY_DESIGN.md)
- [SERVICE_DEFINITION_DESIGN.md](./SERVICE_DEFINITION_DESIGN.md)
- [USER_INTERACTION_DESIGN.md](./USER_INTERACTION_DESIGN.md)
- [WEBADMIN_DESIGN.md](./WEBADMIN_DESIGN.md)
- [SYSTEM_BOUNDARY.md](./SYSTEM_BOUNDARY.md)

## Product Goal

The long-term iOS product should feel like a normal VPN client:

- install from TestFlight/App Store or an enterprise/internal distribution channel
- open the app
- import an invite token or scan a QR code
- review the tunnel endpoint, transport, routing, DNS, and security mode
- install an iOS VPN profile managed by the app
- tap Connect
- see connection status in both the app and iOS Settings
- recover automatically across network changes when policy allows

The app should also keep the ObstacleBridge-specific value visible:

- transport choice and fallback guidance
- secure-link identity state
- peer-specific diagnostics
- service catalog preview
- live counters for TCP, UDP, and TUN channels
- warnings when the configuration is not yet hardened

## Non-Goals

The iOS app should not try to:

- replace WireGuard or OpenVPN protocol implementations
- impersonate their configuration formats except where an import helper is explicitly added later
- expose arbitrary local iOS sockets in the same way a desktop/server ObstacleBridge node can
- run unrestricted background Python code outside iOS lifecycle rules
- rely on private Apple APIs
- assume Apple will approve all Network Extension entitlements without an explicit distribution plan

## Recommended Phasing

### Phase 0: Prepare The Python Runtime For Embedding

Before building an iOS app, split the runtime so core protocol logic can be reused without dragging in desktop/server assumptions.

Deliverables:

- create a small `obstacle_bridge.core` or equivalent package boundary
- isolate wire codec, secure-link, compression, transport abstractions, config parsing, and status snapshots
- keep CLI, WebAdmin HTTP server, filesystem hooks, and desktop TUN adapters outside the embeddable core
- add a minimal programmatic API for lifecycle control instead of only command-line startup

Recommended API shape:

```python
class ObstacleBridgeClient:
    async def start(self, config: RuntimeConfig, packet_io: PacketIO | None = None) -> None: ...
    async def stop(self) -> None: ...
    async def update_config(self, config: RuntimeConfig) -> None: ...
    def snapshot(self) -> RuntimeSnapshot: ...
```

The `packet_io` abstraction is important because iOS packet I/O comes from `NEPacketTunnelFlow`, not from `/dev/net/tun` or WinTun.

### Phase 1: BeeWare Companion App

Build a BeeWare app that acts as an ObstacleBridge mobile control surface and configuration manager.

This phase can validate:

- Briefcase iOS packaging
- Python dependency compatibility on iOS
- configuration import/export
- invite-token parsing
- secure-link material handling
- local status rendering
- communication with a desktop/server ObstacleBridge node's admin API

This phase should not promise system-wide VPN behavior.

Possible Phase 1 capabilities:

- import invite token from clipboard, file, QR code, or share sheet
- validate and preview ObstacleBridge config
- store profile metadata in iOS Keychain/app storage
- connect to a remote WebAdmin endpoint and show status
- generate a ready-to-send client configuration for a later native tunnel provider
- provide troubleshooting guidance and logs from the app side

Reasoning:

- BeeWare is valuable here because the app UI and business logic can be Python-first.
- This lowers risk before attempting Network Extension integration.
- It proves which existing dependencies can actually be packaged for iOS.

### Phase 2: Native Packet Tunnel Provider Proof Of Concept

Add an iOS app extension using `NEPacketTunnelProvider`.

The packet tunnel provider must:

- receive start options and provider configuration from the containing app
- create `NEPacketTunnelNetworkSettings`
- read IP packets from `packetFlow`
- hand those packets to ObstacleBridge's TUN packet path
- receive tunnel packets from ObstacleBridge and write them back to `packetFlow`
- report status, errors, and counters to the containing app

At this point, the project must decide between two implementation strategies.

Strategy A: embed Python in the packet tunnel extension.

- Reuse the current Python protocol implementation most directly.
- Requires proving CPython, `cryptography`, `websockets`, and `aioquic` can be packaged and run reliably inside the extension.
- Requires careful startup-time, memory, and background execution testing.
- Keeps one protocol implementation for desktop and iOS, but increases packaging complexity.

Strategy B: port the packet-tunnel critical path to Swift.

- Implement the Network Extension, packet I/O, and possibly transport/event loop in Swift.
- Keep Python for the companion app, config tooling, tests, and reference implementation.
- Reuse wire-format test vectors from Python to keep protocol compatibility.
- Reduces iOS extension runtime risk, but creates a second protocol implementation to maintain.

Recommended decision:

- Prototype Strategy A first for maximum Python reuse.
- Keep Strategy B as the fallback if extension packaging, dependency, or App Store constraints make embedded Python impractical.
- Do not block the management app on the tunnel-provider choice.

### Phase 3: Full ObstacleBridge VPN Client

Turn the proof of concept into a complete iOS tunnel client.

Deliverables:

- VPN profile creation and management with `NETunnelProviderManager`
- connection start/stop from the app
- app-to-extension messaging for status and control
- reconnect behavior for network changes
- DNS settings and route include/exclude controls
- secure-link PSK and certificate mode support
- QR/invite onboarding flow
- exportable diagnostics bundle with secret redaction
- TestFlight-ready packaging

### Phase 4: Production Hardening

Production hardening should focus on security, battery, stability, and Apple review readiness.

Deliverables:

- entitlement/distribution plan
- background lifecycle tests
- memory and CPU profiling on real devices
- dependency license review
- keychain storage and migration rules
- crash reporting strategy
- privacy policy notes
- threat-model review for mobile-specific risks
- compatibility matrix for iOS versions, devices, and transports

## Target iOS Architecture

The final app should have two installable iOS components:

1. Containing app
2. Packet tunnel provider extension

The containing app owns:

- user interface
- onboarding
- profile management
- configuration editing
- local secure storage
- high-level status
- logs and diagnostics
- import/export/share workflows

The packet tunnel provider extension owns:

- active tunnel lifecycle
- packet I/O through `NEPacketTunnelFlow`
- overlay connection to the peer server
- secure-link handshake and data protection
- mux TUN packet forwarding
- route and DNS settings applied to the virtual interface
- low-level counters and failure reporting

Conceptual data path:

```text
iOS apps and system traffic
  -> iOS virtual interface
  -> NEPacketTunnelFlow
  -> ObstacleBridge packet adapter
  -> ChannelMux TUN service
  -> SecureLink and compression
  -> selected overlay transport
  -> remote ObstacleBridge peer
  -> remote TUN/service target
```

Conceptual control path:

```text
Containing app
  -> stored profile/config
  -> NETunnelProviderManager
  -> packet tunnel provider extension
  -> runtime snapshots/events
  -> containing app status UI
```

## BeeWare Role

BeeWare should be used where it fits well:

- iOS management app UI
- shared Python onboarding logic
- config parsing and validation
- invite-token handling
- status formatting
- possibly embedded runtime experiments

BeeWare should not be assumed to solve:

- Apple Network Extension entitlement approval
- packet tunnel provider lifecycle
- direct access to the iOS virtual interface from a normal app
- all binary dependency packaging for compiled crypto/QUIC libraries

Recommended BeeWare project structure:

```text
ios/
  pyproject.toml
  src/obstacle_bridge_ios/
    app.py
    onboarding.py
    profiles.py
    status.py
    secure_store.py
  resources/
    icons/
    splash/
```

The BeeWare app can call shared project modules after the core package is made import-friendly for mobile.

## Network Extension Role

For VPN-like behavior, the project needs an iOS packet tunnel provider.

The extension should be treated as the iOS equivalent of the current desktop/server TUN boundary:

- Linux uses `/dev/net/tun`.
- Windows uses WinTun.
- iOS uses `NEPacketTunnelProvider` and `NEPacketTunnelFlow`.

Proposed abstraction:

```python
class PacketIO(Protocol):
    async def read_packets(self) -> list[bytes]: ...
    async def write_packets(self, packets: list[bytes]) -> None: ...
```

Platform implementations:

- `LinuxTunPacketIO`
- `WindowsWintunPacketIO`
- `IOSPacketTunnelFlowIO`

If the extension is implemented in Swift, the same abstraction should still exist conceptually. Swift can feed packets into a compatibility layer that emits/accepts the same mux TUN frames as Python.

## Reusing Current Python Code

### Direct Reuse Candidates

These areas should be reusable with limited changes:

- structured runtime config parsing
- invite-token/config-snippet validation
- secure-link PSK and certificate data model
- secure-link wire formats and test vectors
- ChannelMux frame formats
- compression policy and frame wrapping
- transport-independent session interfaces
- status snapshot data shape
- secret redaction policy

### Conditional Reuse Candidates

These may be reusable after platform-specific adaptation:

- `WebSocketSession`, if the Python `websockets` dependency works well on iOS or is replaced by a native socket bridge
- `TcpStreamSession`, if asyncio stream behavior is acceptable inside the extension
- `UdpSession`, if asyncio UDP support is acceptable inside the extension
- `QuicSession`, if `aioquic` and dependencies are practical on iOS
- secure-link cryptography, if `cryptography` packaging is successful

### Not Directly Reusable On iOS

These areas should not be reused as-is:

- Linux `/dev/net/tun` implementation
- Windows WinTun implementation
- lifecycle hook scripts
- shell-oriented route/firewall manipulation
- WebAdmin as an embedded HTTP server for the mobile UI
- assumptions that a long-running foreground Python process can own the tunnel

## Dependency Risk

Current runtime dependencies are:

- `aioquic`
- `cryptography`
- `websockets`

iOS risk:

- `websockets` is pure Python in many usage paths, but it still depends on asyncio behavior and socket support inside the target runtime.
- `cryptography` includes compiled/native components and must be validated for iOS builds.
- `aioquic` uses Python protocol logic plus crypto/TLS dependencies and must be tested on-device.

Mitigation:

- create a mobile dependency spike before promising embedded runtime support
- build a minimal Briefcase app that imports each dependency
- run basic crypto, WebSocket, UDP, TCP, and QUIC smoke tests on simulator and real device
- keep a native Swift fallback plan for packet-tunnel-critical networking

## Configuration Model

The app should reuse the existing runtime config shape where possible, with an iOS profile wrapper around it.

Example iOS profile:

```json
{
  "profile_id": "ios-site-a",
  "display_name": "Site A Bridge",
  "enabled": true,
  "obstacle_bridge": {
    "overlay_transport": "myudp",
    "udp_peer": "bridge.example.com",
    "udp_peer_port": 4443,
    "udp_own_port": 0,
    "secure_link_mode": "psk",
    "own_servers": [
      {
        "name": "ios-tun-local",
        "listen": {
          "protocol": "tun",
          "ifname": "ios-utun",
          "mtu": 1280
        },
        "target": {
          "protocol": "tun",
          "ifname": "obtun1",
          "mtu": 1280
        }
      }
    ],
    "remote_servers": [
      {
        "name": "server-tun-remote",
        "listen": {
          "protocol": "tun",
          "ifname": "obtun1",
          "mtu": 1280
        },
        "target": {
          "protocol": "tun",
          "ifname": "ios-utun",
          "mtu": 1280
        }
      }
    ]
  },
  "ios_vpn": {
    "included_routes": ["0.0.0.0/0", "::/0"],
    "excluded_routes": [],
    "dns_servers": ["1.1.1.1", "8.8.8.8"],
    "on_demand": false
  }
}
```

Notes:

- `ifname` is mostly a logical compatibility value on iOS. The real interface is owned by Network Extension.
- iOS full-tunnel profiles should default to conservative MTU values such as `1280` until measured.
- Secrets should not be stored in plain JSON. The JSON example is a logical shape, not an at-rest storage format.

## Secure Storage

The iOS app should store sensitive values in the iOS Keychain rather than plain app files.

Sensitive values include:

- `secure_link_psk`
- certificate private keys
- admin credentials for remote WebAdmin access
- invite-token secrets
- profile-specific auth material

Non-sensitive profile metadata may live in app group storage shared with the extension.

Recommended storage split:

- App Group container: non-secret profile JSON, logs, redacted snapshots
- Keychain access group: secrets needed by both containing app and extension
- In-memory only: decrypted active session keys and plaintext PSKs

## User Experience

The app should follow the existing user-interaction direction: guided networking instead of raw syntax.

Primary screens:

- Home: active profile, Connect button, current state
- Profiles: imported tunnel profiles and server endpoints
- Import: QR code, clipboard, file, paste-ready JSON
- Security: secure-link mode, identity, PSK/certificate status
- Routes: full tunnel, split tunnel, DNS, MTU
- Diagnostics: peers, RTT, transport, bytes, reconnects, logs
- Advanced: raw config preview and expert transport settings

Recommended first-run flow:

1. show "Import invite or set up manually"
2. parse and preview the invite
3. show transport and peer endpoint
4. show security mode and trust status
5. ask whether to create an iOS VPN profile
6. save secrets to Keychain
7. start the tunnel or leave it ready

The app should explain platform-specific limitations in plain language, for example:

- "This profile creates an iOS VPN tunnel. iOS will ask permission before installing it."
- "The tunnel runs in an Apple Network Extension, so some diagnostics are collected separately from the app."
- "Full-tunnel mode routes most device traffic through ObstacleBridge. Keep the bridge server reachable outside the tunnel."

## Routing And DNS

The iOS packet tunnel provider should support two initial modes:

- split tunnel: route only configured private subnets through ObstacleBridge
- full tunnel: route default IPv4/IPv6 traffic through ObstacleBridge

Full tunnel requires care:

- preserve the underlay route to the ObstacleBridge peer endpoint outside the tunnel
- apply DNS settings only when the tunnel is established
- avoid recursive routing where ObstacleBridge's own transport packets enter its own tunnel
- use MTU/MSS recommendations suitable for layered overlay encapsulation

The existing Linux hook docs already call out the need to preserve the overlay peer route. The iOS implementation must solve the same problem through `NEPacketTunnelNetworkSettings`, not shell hooks.

## Transport Support Plan

Initial recommended transport order:

1. `ws`
2. `tcp`
3. `myudp`
4. `quic`

Reasoning:

- `ws` and `tcp` are the easiest starting point for restrictive networks and extension debugging.
- `myudp` is strategically important but needs careful packet loss, NAT, and battery testing on mobile networks.
- `quic` depends on the highest-risk dependency path because of `aioquic` and TLS/crypto integration.

The UI should still present the product goal as transport-flexible, but implementation should land one transport at a time.

## Observability

The iOS app should reuse the WebAdmin status concepts but render them natively.

Minimum status fields:

- profile name
- tunnel state
- selected transport
- peer host and port
- secure-link state
- bytes in/out
- packets in/out
- reconnect count
- last error
- current route mode
- DNS mode

Advanced status fields:

- peer RTT
- last incoming age
- mux TCP/UDP/TUN channel counts
- secure-link rekey state
- certificate subject/issuer/deployment id
- compression counters
- transport-specific failures

The extension should send periodic redacted snapshots to the containing app. Logs must avoid plaintext secrets.

## Security Model

The iOS app should preserve the existing ObstacleBridge security goals:

- do not accept unauthenticated protected traffic when secure-link is enabled
- keep peer identity visible
- redact secrets by default
- bind risky configuration changes to explicit user intent
- fail closed when key material or policy is invalid

Mobile-specific additions:

- store secrets in Keychain
- use app group access only for non-secret or encrypted state
- never place PSKs or private keys in crash logs
- use iOS local authentication as an optional extra gate for revealing or exporting secrets
- require explicit user confirmation before enabling full-tunnel routing
- show warnings for insecure lab settings such as disabled verification

## App And Extension Communication

The containing app and packet tunnel provider need a small message protocol.

Messages from app to extension:

- start profile
- stop tunnel
- request snapshot
- request log tail
- rotate/reload secure-link material
- update non-disruptive settings where supported

Messages from extension to app:

- current state
- fatal error
- warning
- counters
- peer diagnostics
- secure-link diagnostics
- redacted logs

Implementation options:

- `NETunnelProviderSession` provider messages for active tunnel communication
- App Group files for snapshots/logs
- Keychain access group for shared secrets

The extension must be able to start from stored provider configuration even when the containing app is not foregrounded.

## Testing Strategy

The iOS work should add tests in layers.

Shared Python tests:

- config parsing for iOS profiles
- invite import/export
- secure-link test vectors
- mux TUN frame test vectors
- route configuration validation
- secret redaction

Desktop compatibility tests:

- ensure new abstractions do not regress Linux TUN
- ensure WinTun path still works
- ensure service catalog behavior remains compatible

iOS simulator tests:

- BeeWare app import smoke test
- dependency import smoke test
- config UI smoke test
- extension launch where simulator support permits

Real-device tests:

- install VPN profile
- start/stop tunnel
- Wi-Fi to cellular transition
- airplane-mode recovery
- locked-screen behavior
- full-tunnel route preservation
- DNS behavior
- battery and memory profiling

Interoperability tests:

- iOS client to Linux server over `ws`
- iOS client to Linux server over `tcp`
- iOS client to Linux server over `myudp`
- iOS client to Linux server with secure-link PSK
- iOS client to Linux server with certificate mode
- iOS full-tunnel internet exit through ObstacleBridge server

## Build And Repository Layout

Proposed repository additions:

```text
ios/
  README.md
  pyproject.toml
  src/obstacle_bridge_ios/
    app.py
    profiles.py
    onboarding.py
    secure_store.py
    diagnostics.py
  native/
    ObstacleBridgeTunnel/
      PacketTunnelProvider.swift
      PacketFlowBridge.swift
      TunnelStatus.swift
  tests/
    test_ios_profile_config.py
    test_invite_import.py
```

If Briefcase is used, generated Xcode output should either be ignored or kept in a controlled path with clear regeneration instructions. The source of truth should remain the Python app code, native extension code, and configuration templates.

## Open Design Questions

- Can the required Apple Network Extension entitlement be obtained for the intended distribution model?
- Should the first full VPN tunnel prototype embed Python in the extension or port the critical path to Swift?
- Which transport should be the first supported production transport on iOS?
- Can `cryptography` and `aioquic` be packaged reliably for iOS devices?
- Should certificate private key generation happen on iOS, or should keys be provisioned externally?
- How much of WebAdmin should be reimplemented as native UI versus exposed through a local embedded page for development only?
- What is the minimum supported iOS version?
- Should Android be considered in parallel once the core packet I/O abstraction exists?

## Milestone Checklist

### M0: Core Refactor Ready

- Embeddable runtime API exists.
- Packet I/O abstraction exists.
- Config parsing is decoupled from CLI startup.
- Secure-link and mux wire tests are available as reusable vectors.

Current implementation slice:

- `src/obstacle_bridge/core.py` exposes `ObstacleBridgeClient` with `start`, `stop`, `update_config`, and `snapshot`.
- `src/obstacle_bridge/packet_io.py` exposes the `PacketIO` protocol and `MemoryPacketIO` test/spike implementation.
- `src/obstacle_bridge/bridge.py` exposes `parse_runtime_args`, `build_runtime_args_from_config`, and `default_runtime_registrars` so embedders can create runtime arguments without invoking the CLI process entrypoint.
- The current M0 slice reserves packet-I/O handoff on the runner for the upcoming platform TUN adapter refactor; desktop Linux/WinTun behavior remains unchanged.

### M1: BeeWare App Prototype

- Briefcase iOS project builds.
- App imports shared ObstacleBridge modules.
- App imports and previews invite/config snippets.
- App stores a profile without plaintext secrets in normal app files.

Current implementation slice:

- `ios/pyproject.toml` and `ios/src/obstacle_bridge_ios/app.py` provide a minimal BeeWare companion-app scaffold for iOS packaging spikes.
- `src/obstacle_bridge/onboarding.py` exposes shared invite/config import preview helpers so non-WebAdmin hosts can reuse onboarding token logic.
- `ios/src/obstacle_bridge_ios/onboarding.py` imports the shared onboarding helper and exposes invite/config preview behavior for the iOS prototype path.
- `ios/src/obstacle_bridge_ios/profiles.py` and `ios/src/obstacle_bridge_ios/secure_store.py` implement profile persistence that keeps `secure_link_psk` and `admin_web_password` out of normal profile JSON files by storing them in a secret-store abstraction.
- `ios/src/obstacle_bridge_ios/app.py` now includes a small facade path that previews invite/config imports and stores resulting profile material through the secret-aware profile store.
- `ios/tests/test_invite_import.py`, `ios/tests/test_ios_profile_config.py`, and `ios/tests/test_ios_app_facade.py` cover invite/config preview, app-level import/store flow, and no-plaintext-secret profile persistence behavior.
- `briefcase create iOS`, `briefcase build iOS`, and `briefcase run iOS -u --no-input -d "iPhone 17 Pro"` have been validated on macOS with Xcode installed, and the simulator launch renders the M1 prototype screen.

M1 status:

- Complete.

### M2: Dependency Spike

- `websockets` smoke test runs on device.
- `cryptography` smoke test runs on device or fallback is selected.
- `aioquic` smoke test result is documented.
- asyncio TCP/UDP behavior is validated on simulator and device.

### M3: Packet Tunnel POC

- iOS VPN profile installs.
- Packet tunnel extension starts and stops.
- Extension reads and writes packets through `NEPacketTunnelFlow`.
- One ObstacleBridge transport connects to a Linux/server peer.
- TUN packets cross the overlay.

### M4: Secure Tunnel Beta

- Secure-link PSK works.
- Route and DNS settings work.
- Basic status and logs are visible in the containing app.
- Wi-Fi/cellular transition is tested.
- TestFlight/internal distribution package is produced.

### M5: Production Candidate

- Certificate mode works or is explicitly deferred.
- App review/entitlement plan is complete.
- Secrets and diagnostics have passed review.
- Battery/memory profile is acceptable.
- User documentation is written.

## Recommended Next Step

The next engineering step should be M0 plus a small M1 spike:

1. Refactor the runtime just enough to expose an embeddable client API and packet I/O abstraction.
2. Create a minimal BeeWare iOS app that imports the shared config/onboarding code.
3. Create a separate native iOS Network Extension proof-of-concept that only starts, applies dummy network settings, and echoes packet counters.

This path keeps momentum high while protecting the project from the main hidden risk: a nice BeeWare app alone cannot provide WireGuard/OpenVPN-style system tunneling on iOS without the native Network Extension layer.
