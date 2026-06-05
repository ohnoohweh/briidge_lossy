# iOS App Design

## Purpose

This document describes how ObstacleBridge can grow into an iOS application that reuses as much of the current Python runtime as iOS realistically allows.

The target product is an iPhone/iPad app that can:

- import an ObstacleBridge invite or configuration snippet
- show connection, peer, secure-link, and tunnel status
- start and stop a tunnel from an iOS-native control surface
- carry TUN-style routed IP traffic through ObstacleBridge transports such as `myudp`, `ws`, `tcp`, or `quic`
- preserve the existing ObstacleBridge peer model, secure-link model, service catalog model, and admin observability concepts

This document intentionally separates the first practical mobile step from the full VPN-style endpoint. A normal iOS application and a system VPN tunnel provider have different Apple platform requirements, lifecycles, entitlements, and packaging constraints.

Scope note:

- The current implementation already supports a useful iOS foreground app path for onboarding, diagnostics, and app-scoped TCP/UDP behavior.
- However, generic background execution for `admin_web`, `ChannelMux`, or a long-lived TCP/UDP server should not be assumed merely because the app can request Background Tasks capabilities.
- Apple background processing tasks are better treated as bounded maintenance hooks, not as the durable runtime host for a live networking control plane.

## External platform facts checked

The design is based on the current project plus these platform references:

- BeeWare documentation: https://beeware.org/docs/
- Briefcase iOS platform reference: https://briefcase.beeware.org/en/v0.3.16/reference/platforms/iOS.html
- Apple Network Extension framework: https://developer.apple.com/documentation/NetworkExtension
- Apple packet tunnel provider documentation: https://developer.apple.com/documentation/networkextension/packet-tunnel-provider
- Apple app life-cycle guidance: https://developer.apple.com/documentation/uikit/app_and_environment/managing_your_app_s_life_cycle
- Apple Background Tasks framework: https://developer.apple.com/documentation/backgroundtasks
- Apple `BGProcessingTaskRequest`: https://developer.apple.com/documentation/backgroundtasks/bgprocessingtaskrequest
- Python 3.13 iOS support notes: https://docs.python.org/3/whatsnew/3.13.html
- PEP 730, adding iOS as a supported CPython platform: https://peps.python.org/pep-0730/

Important interpretation:

- BeeWare/Briefcase is a promising way to package a Python-powered iOS app and produce an Xcode project.
- A WireGuard/OpenVPN-like iOS client is not just a normal app. It requires Apple's Network Extension framework, specifically a packet tunnel provider app extension for custom packet-oriented VPN protocols.
- Therefore, BeeWare is best treated as the management-app path first, while the packet tunnel itself should be designed as an iOS Network Extension with a clear bridge to reusable ObstacleBridge logic.
- Background Tasks does not change that conclusion for long-lived runtime ownership. `BGProcessingTask` is appropriate for deferred or maintenance-style work, not for keeping a generic WebAdmin server or ChannelMux loop continuously alive after the app loses focus.

Local implementation samples reviewed:

- `/Users/ohnoohweh/ios_vpn_samples/proxypin`
- `/Users/ohnoohweh/ios_vpn_samples/SimpleTunnel`
- `/Users/ohnoohweh/ios_vpn_samples/NEPacketTunnelVPNDemo`

Sample-derived implementation recipes:

- The containing app should use `NETunnelProviderManager.loadAllFromPreferences`, reuse the existing ObstacleBridge manager when present, configure one `NETunnelProviderProtocol`, call `saveToPreferences`, then `loadFromPreferences`, and only then call `startVPNTunnel`.
- The extension principal class should follow the standard packet-tunnel form `$(PRODUCT_MODULE_NAME).PacketTunnelProvider` in the extension `Info.plist`.
- `PacketTunnelProvider.startTunnel` should be the single owner of runtime startup. It reads `providerConfiguration`, applies `NEPacketTunnelNetworkSettings`, starts the ObstacleBridge runtime, starts packet/service loops, and calls the completion handler only after those startup steps are complete.
- `PacketTunnelProvider.stopTunnel` should be the single owner of runtime shutdown. It must stop WebAdmin, ChannelMux, SecureLink, packet readers, and transport sessions before completing.
- The app must communicate with the extension through `NETunnelProviderSession.sendProviderMessage` and shared App Group storage, not by directly owning the Python runtime that carries traffic.
- Extension diagnostics must be written from the extension process, because foreground-app logs cannot prove that the packet tunnel provider started or stayed alive.

Persisted packet-tunnel profile rule discovered on device:

- The saved app-side `NETunnelProviderManager` must stay as close as possible to the Apple sample shape if the VPN profile name should remain visible in iOS Settings.
- A minimal persisted profile containing `localizedDescription`, `providerBundleIdentifier`, and `serverAddress` keeps the visible profile name stable.
- Persisting the larger ObstacleBridge-specific `providerConfiguration` payload from the containing app caused iOS to reload the profile with blank `localizedDescription` and stripped provider metadata, even though the initial `saveToPreferences` call succeeded.
- Therefore the containing app should persist only the minimal packet-tunnel profile metadata. ObstacleBridge runtime configuration should be sourced elsewhere, such as App Group files or app-to-extension messaging, instead of being embedded into the saved tunnel profile.

Proven file-access boundary discovered on device:

- The containing `ObstacleBridge` app can read and write its own visible `Documents` folder, including `Documents/config/ObstacleBridge.cfg`.
- The `IPServer` Network Extension can read and write the shared App Group container.
- However, the `IPServer` Network Extension cannot directly open the containing app's `Documents/config/ObstacleBridge.cfg` path, even when the containing app publishes that absolute path for diagnostic purposes. The extension-side probe returned `PermissionError: [Errno 1] Operation not permitted`.
- Therefore the shared App Group container is not just a convenience layer. It is the required file-exchange boundary for configuration, diagnostics, and other non-secret runtime artifacts that must move between the containing app and the Network Extension.
- The operational rule is: whichever copy of `ObstacleBridge.cfg` is newer must be synchronized into both locations, but the extension runtime itself must load from the App Group copy, not from the containing app `Documents` folder.

## Apple Account Requirement

Developing and signing the packet-tunnel path requires more than a free Apple account.

Requirements:

- An Apple account enrolled in the Apple Developer Program.
- Access to an Apple Developer team that can sign iOS apps and Network Extension targets.
- Xcode configured locally with that account and team.
- The app ID and extension ID configured for Network Extension packet-tunnel use in the Apple Developer portal or the equivalent team-managed signing setup.

Practical consequence:

- Simulator-only work does not prove the full product path.
- Real-device builds for the packet-tunnel target require local signing material and team access.
- This repository should not contain personal Apple IDs, team IDs, device UDIDs, or provisioning-profile identifiers. Those stay local to the developer machine and Apple account.

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

## Implemented Progress And Design Outcomes

The original design questions around "can BeeWare package the app?", "can Python run inside the extension?", "can the app own the runtime?", and "how should config move between app and extension?" are now largely answered by working code and device validation.

Current product-status summary:

- ObstacleBridge on iPhone has now crossed from "prototype packet tunnel host" into "initial full-blown VPN client".
- The app can install and manage the VPN profile, onboard from invite/config material, run the extension-hosted WebAdmin, and route real traffic through the tunnel.
- The earlier sudden-crash class that interrupted active tunnel sessions has been substantially reduced by the current Swift/native hardening work around the extension boundary and shared runtime integration.
- The remaining observed weakness is different: the Network Extension can still disappear after the phone sleeps, after prolonged idle time, or after long periods without traffic, which points more toward iOS lifecycle/background policy, idle-session handling, or missing keepalive strategy than toward the original crash defect.

### Outcome 1: BeeWare Is Useful For The Containing App, Not For Replacing Network Extension

The BeeWare/Briefcase app path is now proven useful for:

- packaging the containing iOS app
- hosting shared Python UI/business logic where appropriate
- seeding `Documents/ObstacleBridge` content such as `config/`, `logs/`, `admin_web/`, and `web/`
- importing configuration, invite material, and diagnostics

Design impact:

- BeeWare remains a good fit for the containing app and test harnesses.
- BeeWare is not the substitute for Apple’s packet tunnel lifecycle.
- The packet tunnel extension remains the durable runtime host for live networking behavior.

### Outcome 2: Embedded Python In The Packet Tunnel Extension Works

The project no longer needs to treat embedded Python in the extension as only a speculative option. The current `IPServer` extension boots the shared Python runtime, runs WebAdmin, ChannelMux, SecureLink, and lower transport layers, and stays alive independently from the foreground app.

Design impact:

- The project keeps a single protocol/runtime implementation across desktop and iOS for the current product path.
- Swift remains the owner of the native extension lifecycle, tunnel settings, and app/provider messaging boundary.
- Python remains the owner of the reusable ObstacleBridge protocol/runtime logic.

### Outcome 3: The Containing App Must Not Own The Traffic Runtime

This was previously a design assumption; it is now validated by device behavior and the working extension architecture.

The containing app is now correctly treated as:

- profile installer/manager
- onboarding and configuration UI host
- diagnostics/log viewer
- WebAdmin viewer

The containing app is not treated as:

- the durable owner of WebAdmin
- the durable owner of ChannelMux
- the durable owner of SecureLink
- the durable owner of transport sessions

Design impact:

- Foreground-app lifetime and tunnel lifetime are separate concerns.
- App restart, app suspension, Safari access, and VPN status must all be reasoned about through the extension boundary, not the app process.

### Outcome 4: Persisted VPN Profile Metadata Must Separate Overlay Identity From Tunnel Identity

Earlier device testing showed that blindly embedding large ObstacleBridge-specific payloads into the saved `NETunnelProviderProtocol.providerConfiguration` was fragile. That observation was useful, but the long-term target is more precise than "keep the profile minimal forever".

The desired product model is closer to WireGuard-style behavior:

- when the tunnel is idle, the profile should primarily express the transport-facing endpoint identity
- when the tunnel is active, the runtime should also expose the effective tunnel network identity such as IPv4 and IPv6 addresses plus route ownership

For ObstacleBridge, the transport-facing endpoint depends on the selected overlay transport:

- `myudp` uses `udp_peer` and `udp_peer_port`
- `ws` uses `ws_peer` and `ws_peer_port`
- `tcp` uses `tcp_peer` and `tcp_peer_port`
- `quic` uses `quic_peer` and `quic_peer_port`

That overlay peer identity is not the same thing as the tunnel-side interface identity:

- tunnel IPv4 local address/prefix
- tunnel IPv6 local address/prefix when configured
- included and excluded routes
- DNS and MTU settings

The stable design target is:

- keep the visible VPN profile name stable in iOS Settings
- treat the saved profile's top-level server/peer identity as the selected overlay endpoint, not as the TUN-side IP
- persist or regenerate derived tunnel network settings from the live ObstacleBridge config so the provider can apply them on tunnel start
- allow the active runtime state to expose richer tunnel identity than the idle-profile view

Design impact:

- VPN-profile persistence and runtime configuration are still separate concerns, but not in a way that requires a permanently empty `providerConfiguration`
- `NETunnelProviderManager` should represent the selected overlay endpoint clearly
- tunnel IPv4/IPv6 identity belongs to derived network settings sourced from the service catalog and applied by the provider at tunnel start
- App Group files and provider messages remain the durable source for ObstacleBridge-specific runtime state

### Outcome 5: App Documents And Extension Storage Are Different Security Domains

This is no longer an open question. The extension-side probe proved that the Network Extension cannot directly open the containing app’s `Documents/config/ObstacleBridge.cfg`, even when that path is known.

The working design is:

- app-visible editable copy in `Documents/config/ObstacleBridge.cfg`
- extension-consumed copy in the shared App Group container
- synchronization rule: the newer copy wins and is copied into both locations
- extension runtime always loads from the App Group copy

Design impact:

- App Group storage is the required exchange boundary.
- Config sync and log harvesting are first-class product behavior, not a temporary workaround.

### Outcome 6: iOS Requires Canonical WebAdmin Asset Staging Into Packaged Builds

### Outcome 7: Swift Packet Adapters Differ From The Python Host-TUN Path

The current product now has a concrete cross-platform lesson from shared-TUN
testing:

- the Python clients on Linux and macOS behave like host-style TUN adapters
- the Swift clients on iOS and macOS behave like packet-adapter clients

That distinction matters for shared-TUN ownership enforcement.

Python host-TUN behavior:

- the OS routes traffic onto the local tunnel interface
- packets that reach the Python ObstacleBridge runtime already line up closely
  with the tunnel-owned identity expected by shared-TUN ownership
- the Python mux path therefore did not need an additional explicit local
  source-address rewrite layer for the tested shared-TUN flows

Swift packet-adapter behavior:

- the iOS packet tunnel provider and the macOS Swift app both deliver packets
  into the shared Swift runtime through native packet adapters
- those packets can still carry the device's original source identity when they
  first arrive at the shared Swift TUN runtime
- the shared-TUN server, correctly, rejects those packets if they do not use
  the peer's assigned tunnel-owned address

Observed effect:

- server-side recent drops showed `source_not_owned_by_peer`
- examples included original device-side source addresses rather than the
  assigned shared-TUN addresses

Implemented design response:

- the shared Swift TUN runtime now normalizes outbound local packet source
  identity to the configured tunnel-owned IPv4 or IPv6 address before mux
  framing
- transport checksums are recomputed where required
- this behavior is shared across the Swift macOS app and the iOS packet tunnel
  path so both Apple-platform clients honor the same server ownership contract

Design consequence:

- the shared-TUN server contract remains strict
- Python remains the reference host-TUN behavior
- Swift packet-adapter clients adapt themselves before shared-TUN forwarding so
  their effective tunnel identity matches the Linux/Python model

The repository now treats top-level `admin_web/` as the canonical source-tree location for WebAdmin assets. iOS packaging must explicitly stage those assets into the built app bundle so the containing app can seed `Documents/ObstacleBridge/admin_web` on first launch.

Design impact:

- there must not be platform-specific WebAdmin forks for iOS, Windows, Linux, or macOS
- packaged builds still need a runtime-accessible bundled copy of the canonical assets
- the iOS build path must be validated against actual staged bundle contents, not only source-tree assumptions

### Outcome 7: The iOS App Now Delivers Real Tunnel User Value

The project has now crossed the first meaningful product threshold: the iOS app can tunnel real user traffic.

This is no longer limited to:

- profile installation
- config import
- WebAdmin access
- control-plane connection proof
- local tunnel endpoint pings

It now includes live routed traffic with device validation:

- Safari traffic on iPhone was routed through the tunnel
- public-IP verification reported the Fedora server address `38.180.143.5`
- Fedora-side `pcap` capture showed real internet-bound flows sourced from the iPhone tunnel address
- dual-stack progression reached the point where iPhone-side browsing also surfaced the expected Austrian IPv6 egress

Design impact:

- ObstacleBridge on iOS is no longer just a packaging or extension-hosting experiment
- the product has reached the first user-visible value-add milestone: tunneled traffic works
- future work should treat packet forwarding and routed browsing as the baseline to preserve, not as speculative scope

### Outcome 8: Dual-Stack Tunnel Identity Is Now Config-Derived

The iOS tunnel is no longer tied to a baked-in local address. The app/provider path now derives effective tunnel settings from live ObstacleBridge config, following the same operational intent used by the Linux/Fedora side.

The current dual-stack model is:

- IPv4 local/peer identity is derived from `TUN_ADDR`, `PEER_ADDR`, and `TUN_SUBNET`
- IPv6 local/peer identity is derived from `TUN_ADDR6`, `PEER_ADDR6`, and `TUN_SUBNET6`
- included routes are full-tunnel by default:
  - IPv4 `0.0.0.0/0`
  - IPv6 `::/0`
- excluded routes preserve loopback ownership:
  - IPv4 `127.0.0.0/8`
  - IPv6 `::1/128`

The intended source of truth is the service definition itself, especially:

- `channel_mux.own_servers[].lifecycle_hooks.listener.on_created.env`

with compatible fallback to matching remote-side peer data when needed for transition compatibility.

Design impact:

- the iOS tunnel profile/runtime is now aligned with the service-catalog model instead of hidden app constants
- tunnel identity can evolve with config updates instead of requiring code edits
- dual-stack support should be treated as part of the main design, not as a future appendix

### Outcome 9: The Original Sudden-Crash Problem Is No Longer The Primary Risk

The earlier "tunnel is working and then suddenly dies under live traffic" problem was an important design-learning phase, and it drove real changes at the Swift/native boundary. That specific class of failure is no longer the dominant story.

Observed outcome:

- the current Swift-backed extension path no longer presents the same abrupt crash signature as the main day-to-day blocker
- the extension/runtime integration has matured enough that traffic forwarding, WebAdmin access, invite onboarding, and VPN profile control are all now part of normal product behavior

Design impact:

- iOS should now be described as an implemented VPN client product slice, not only as a tunnel-hosting experiment
- Swift's role in lifecycle ownership, packet-boundary control, and runtime hardening is now proven and should be treated as part of the stable architecture
- future iOS design work should assume that the packet path itself is basically real and concentrate on resilience and lifecycle correctness

### Outcome 10: Current Risk Has Shifted From Reachability To Extension Lifecycle Hardening

The most recent failure mode no longer questions whether the tunnel can carry traffic. That part is proven. The remaining risk has moved to robustness across iPhone sleep, idle periods, and extension lifecycle transitions.

Observed behavior:

- the Network Extension carries substantial IPv4 and IPv6 traffic successfully while active
- the extension can still vanish later, especially when the iPhone turns off, sleeps, or appears idle for a while
- this disappearance does not look like the original foreground-path crash symptom anymore
- the resulting user-visible symptom is that the VPN disconnects or silently stops carrying traffic until the runtime is reawakened or restarted

Current interpretation:

- this now points more strongly to extension lifecycle policy, idle handling, missing keepalive behavior, or sleep-aware runtime design than to routing or configuration defects
- if the product should remain connected while the phone sleeps or when traffic is sparse, the runtime likely needs an explicit strategy for idle preservation or reconnect after wake
- a "sleep mode" in the design sense may be required: reduce noisy work, preserve session identity where possible, and keep enough control traffic alive that iOS does not treat the tunnel as disposable

Design impact:

- the primary engineering goal has changed from "make iOS tunneling work at all" to "make the working tunnel resilient across sleep, idle, and background lifecycle transitions"
- observability and rate-aware diagnostics in the packet bridge are now important hardening tools
- reducing hot-path logging pressure is part of the runtime-stability design, not just a cosmetic cleanup
- future hardening should explicitly study:
  - wake/reconnect behavior
  - overlay/session keepalive policy
  - idle-time extension survival
  - whether low-traffic periods need synthetic maintenance traffic
- for the localhost-UDP connector experiment, observability must exist on both sides of the seam: native `NEPacketTunnelFlow` PCAPs at the provider boundary and Python-side raw-IP PCAPs plus JSONL session manifests at the connector-to-ChannelMux boundary

### Outcome 11: iOS Crypto Parity Is Achieved Through A Native Backend Boundary

The project previously treated missing Python `cryptography` support on iOS as a release-blocking gap. That gap is now addressed by the current native iOS crypto path used by the extension runtime for the required subset of primitives.

Design impact:

- the design should not describe iOS crypto as fundamentally unavailable anymore
- the correct long-term pattern is a narrow internal crypto boundary with platform-appropriate implementations
- the project should continue to avoid broad platform-specific protocol forks and instead keep compatibility at the runtime-contract level

### Outcome 12: WebAdmin Restart Behavior Is Solved As A Runtime Concern

The WebAdmin restart path on iOS has now been exercised and hardened:

- restart requests reach the extension runtime
- the Python stack restarts inside the extension
- the VPN stays active during restart
- WebAdmin shutdown no longer causes multi-minute stalls

Design impact:

- restart is an extension-runtime lifecycle event, not an app restart
- WebAdmin shutdown and recovery behavior must be reasoned about as extension-owned service behavior
- frontend behavior should remain platform-agnostic and reflect backend/runtime truth

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
- a WebView/browser surface that opens `http://127.0.0.1:18080` when the extension-hosted WebAdmin is running

The packet tunnel provider extension owns:

- active tunnel lifecycle
- packet I/O through `NEPacketTunnelFlow`
- local WebAdmin service on `127.0.0.1:18080`
- TCP and UDP service listeners that must survive foreground app suspension
- ChannelMux service lifecycle
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

Conceptual local admin path:

```text
ObstacleBridge app WebView or Safari
  -> http://127.0.0.1:18080
  -> extension-owned WebAdmin listener
  -> extension-owned config/status APIs
  -> ChannelMux, SecureLink, and transport runtime state
```

Conceptual control path:

```text
Containing app
  -> App Group profile/config and Keychain/App Group secret boundary
  -> NETunnelProviderManager
  -> packet tunnel provider extension
  -> NETunnelProviderSession provider messages
  -> runtime snapshots/events/logs
  -> containing app status UI
```

### Current Packet-Tunnel Routing Concept

The iOS target is now aligned with a normal VPN client: full routed IPv4 forwarding through the packet tunnel, using `0.0.0.0/0` as the included route and excluding loopback traffic with `127.0.0.0/8`.

Design implications:

- The extension is no longer only a host for WebAdmin, diagnostics, or local service listeners.
- `NEPacketTunnelFlow` must be treated as the live packet boundary for general device traffic.
- The iOS runtime must preserve the same conceptual TUN role already used on Linux (`/dev/net/tun`) and Windows (WinTun), with iOS providing the third platform implementation.
- The tunnel-side interface identity must come from the live service definition, not from a baked app constant.
- The selected overlay peer endpoint and the tunnel-side interface address are different pieces of information and must be modeled separately.
- IPv6 tunnel identity should follow the same rule once enabled.

Packet-path review outcome:

- The native provider already applied `NEPacketTunnelNetworkSettings`, owned the extension lifecycle, and hosted the embedded runtime.
- The missing link was the hop between `NEPacketTunnelFlow` and ChannelMux TUN channels.
- Linux and Windows already had platform adapters that opened a local TUN device, read packets from it, and injected return packets back into it.
- iOS needed the equivalent third adapter plus a native packet-flow bridge:
  - `NEPacketTunnelFlow.readPackets`
  - native packet-flow bridge
  - `bridge_tun_ios.py`
  - ChannelMux TUN service
  - remote peer over SecureLink and selected transport
  - returning TUN payloads back through the same bridge to `NEPacketTunnelFlow.writePackets`

Current route policy:

- Default included route: `0.0.0.0/0`
- Default excluded route: `127.0.0.0/8`
- Keep DNS settings explicit and conservative for the selected tunnel behavior.
- Derive the local iOS tunnel IPv4 identity from the local TUN service definition, ideally `own_servers[].lifecycle_hooks.listener.on_created.env.TUN_ADDR`.
- If that local metadata is temporarily absent, compatibility fallback may infer the local iOS address from the matching remote TUN listener metadata such as `PEER_ADDR`.
- Derive the transport-facing peer endpoint from `udp_peer`, `ws_peer`, `tcp_peer`, or `quic_peer` according to `overlay_transport`.

Target profile/runtime behavior:

- Idle profile:
  - show the selected overlay endpoint for the active transport
  - keep the visible VPN profile name stable in iOS Settings
- Active tunnel:
  - show effective tunnel IPv4 local/peer identity
  - show effective tunnel IPv6 local/peer identity when configured
  - show included and excluded route ownership
  - show DNS and MTU as part of the applied tunnel settings

Operational consequence:

- A broken packet bridge is now a full-traffic outage risk, not just a missing local admin feature.
- Therefore packet-path tracing at the provider boundary, bridge boundary, and ChannelMux TUN boundary is a required part of the design, not optional diagnostics.
- For the UDP connector experiment specifically, the environment should preserve enough raw traffic at the connector seam that a `ChannelMux` or lower-layer crash can be replayed later without the iOS PacketTunnel provider being present.

Critical boundary:

- The containing app must be disposable while traffic is active. If iOS suspends or terminates the app after the user opens Safari, locks the phone, or switches applications, the extension-hosted runtime must continue independently.
- The containing app may render WebAdmin, but it must not host WebAdmin.
- The containing app may start, stop, and inspect the tunnel, but it must not own ChannelMux, SecureLink, or lower transport loops.
- The extension must be able to boot the complete traffic path from persisted provider configuration and shared storage without requiring a foreground Python process in the app.

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

### PacketTunnelProvider Encapsulation Model

The packet tunnel provider is the iOS execution engine. For the current ObstacleBridge target, this means `ios/native/IPServer/PacketTunnelProvider.swift` is not only a packet adapter; it is the root lifecycle owner for WebAdmin, ChannelMux, SecureLink, and the selected lower transport layers.

Startup sequence:

1. iOS launches the extension and calls `PacketTunnelProvider.startTunnel`.
2. The provider validates the `NETunnelProviderProtocol.providerConfiguration` schema and loads shared configuration from the App Group.
3. The provider applies `NEPacketTunnelNetworkSettings` with the selected tunnel address, included routes, excluded routes, DNS, and MTU.
4. The provider boots the embedded ObstacleBridge runtime inside the extension process.
5. The provider starts WebAdmin on `127.0.0.1:18080` inside the extension, not inside the containing app.
6. The provider starts ChannelMux, SecureLink, compression, and selected transport sessions.
7. The provider starts packet-flow and service loops, then calls the `startTunnel` completion handler.

Runtime ownership:

- WebAdmin runs as an extension-owned local admin service. The app only displays it through a WebView or the user opens it in Safari.
- ChannelMux runs in the extension and owns TUN, TCP, and UDP service channels.
- SecureLink runs in the extension so handshake state, rekeying, replay defense, and encryption are not tied to foreground-app lifetime.
- TCP/UDP listeners that must survive app focus loss run in the extension. Foreground-only experiments may exist for development, but they are not the iOS product architecture.
- `NEPacketTunnelFlow.readPackets` feeds packet data into the ObstacleBridge packet adapter. Packets returned by the remote mux path are written back with `NEPacketTunnelFlow.writePackets`.

Shutdown sequence:

1. iOS calls `PacketTunnelProvider.stopTunnel`.
2. The provider records the stop reason and writes extension-side diagnostics.
3. The provider stops accepting new WebAdmin, TCP, and UDP work.
4. The provider drains or cancels ChannelMux sessions, SecureLink state, packet readers, and transport sessions.
5. The provider persists final counters/status and calls the stop completion handler.

App-to-extension contract:

- Use `NETunnelProviderManager` for profile creation, profile reuse, enablement, and start/stop.
- Use `NETunnelProviderSession.sendProviderMessage` for status, health, diagnostics, and controlled commands.
- Use App Group storage for non-secret shared configuration and extension logs.
- Use an approved secret boundary for PSK/password/key material. Plaintext secrets must not be written into normal app files.
- Do not rely on `.git` metadata in the deployed package. Build/version metadata must be generated into package files during build.

### UDP Repro Baseline

The repository should preserve one intentionally small iOS packet-tunnel ladder whose job is to prove packet-flow stability before higher-layer runtime features are brought back into the path.

Design rules for this baseline:

- The provider applies the normal `NEPacketTunnelNetworkSettings`, including dual-stack addresses, DNS, routes, and MTU.
- Two connector modes define the repro ladder:
  - `swift_simple_udp_peer` is the control mode that bypasses Python, ChannelMux, WebAdmin, and SecureLink entirely.
  - `simple_udp_peer` restores Python while still keeping ChannelMux, SecureLink, and overlay sessions out of the packet path.
- The packet path for both modes is:
  - `NEPacketTunnelFlow.readPackets`
  - UDP sender to the Fedora peer
  - UDP receiver from the Fedora peer
  - `NEPacketTunnelFlow.writePackets`
- The Fedora peer is a host-side raw-IP UDP/TUN ferry configured by `run_test_setup.sh` and `run_test.sh`.
- Packet handling on the iOS side should favor fairness over burst throughput. Hot-path queue draining should process one packet or one meaningful unit of work, then cooperatively yield back to the event loop before continuing. In async code this means `await asyncio.sleep(0)`; in callback-driven code it means rescheduling the continuation with `loop.call_soon(...)` instead of draining a whole queue in one turn.
- Yield behavior should be observable. For callback-driven continuations, record the time between `loop.call_soon(...)` and the continuation actually running. This "yield gap" is the callback-side equivalent of measuring how quickly `await asyncio.sleep(0)` returns, and it helps show whether heavy load is stretching event-loop turn granularity.
- This fairness rule applies at every high-volume ingress boundary that can fan out work toward `NEPacketTunnelFlow`, including:
  - native packetflow bridge reads
  - local packetflow-to-ChannelMux UDP seam delivery
  - overlay UDP (`myudp`) datagram ingestion
  - ChannelMux app-payload dispatch from the overlay session into protocol/service handlers

Operational expectations for this baseline:

- It is the reference environment for answering whether iOS `NEPacketTunnelFlow` remains stable under routed IPv4 and IPv6 traffic while the packet path is kept minimal.
- `swift_simple_udp_peer` is the lowest-level control. `simple_udp_peer` is the promoted baseline once the same traffic pattern remains stable with Python reintroduced.
- Stability of these modes is more important than feature coverage. If either mode is unstable, higher-layer experiments are not trustworthy.
- Added latency under burst is acceptable if it prevents long uninterrupted execution slices inside the Network Extension. The design preference is "slow down before you monopolize the loop."
- The provider must emit compact native state and heartbeat records during the run and must record an explicit `userInitiated` stop when the tunnel is stopped manually.
- The Fedora bridge may add routing, NAT, and policy-routing mechanics, but it must not alter packet payloads beyond what normal Linux forwarding requires.

Current known-good baseline:

- iOS runtime mode: `simple_udp_peer`
- Control mode retained for comparison: `swift_simple_udp_peer`
- Tunnel MTU: `1600`
- Fedora peer transport: UDP port `5555`
- Fedora TUN interface: `obexp0`
- Stable repro scope: dual-stack browsing with clean manual stop and no self-inflicted extension shutdown

## Background Task Boundary

The iOS app may request Background Tasks capabilities, but those capabilities should be used narrowly.

Allowed design intent:

- schedule bounded maintenance such as config refresh, log packaging, redacted diagnostics upload, or retryable housekeeping work
- finish short user-initiated work when iOS grants time
- persist state so the foreground app can resume quickly

Disallowed product assumption:

- do not treat `BGProcessingTask` as the host for `admin_web`
- do not treat `BGProcessingTask` as the host for `ChannelMux`
- do not treat `BGProcessingTask` as a generic always-on TCP or UDP server runtime

Reasoning:

- Background processing tasks are opportunistic and system-scheduled.
- iOS may delay them until the device is idle and external power/network conditions are favorable.
- iOS may interrupt them when system conditions change.
- That execution model is the opposite of what a live control plane or active mux/service runtime needs.

Decision:

- Keep `admin_web`, `ChannelMux`, SecureLink, and active transport sessions in the packet tunnel extension for the iOS VPN product path.
- Use background tasks only for bounded resume/sync/export work around the app and extension, never as the primary host for the live networking runtime.

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
- WebAdmin hosted by the containing app as the mobile UI runtime
- assumptions that a long-running foreground Python process can own the tunnel

## Dependency And Crypto Outcome

Current important runtime dependencies are still:

- `aioquic`
- `cryptography`
- `websockets`

The project’s iOS experience now splits these into two categories:

- reusable Python/runtime dependencies that work acceptably in the current embedded-extension path
- capabilities that must be satisfied through a native iOS implementation boundary

### Current Design Outcome

The earlier uncertainty around `cryptography` on iOS is resolved in design terms:

- the project does not need to package the full desktop/server `cryptography` story unchanged into every iOS runtime path
- the project does need the specific security primitives ObstacleBridge relies on
- those primitives are now satisfied through the current native iOS crypto boundary rather than by pretending the problem does not exist

The relevant crypto surface remains intentionally narrow:

- config-secret encryption/decryption: `HKDF(SHA-256)` plus `ChaCha20Poly1305`
- WebAdmin secret-reveal envelope: `PBKDF2-HMAC-SHA256` plus `AESGCM`
- secure-link certificate mode: `Ed25519`, `X25519`, and PEM/DER key-loading support

### Design Impact

- The correct architecture is not "copy less of `cryptography` into iOS"; it is "preserve a narrow internal crypto contract and implement it appropriately per platform."
- iOS secret storage and iOS runtime crypto should continue to be treated as related but separate concerns.
- Keychain remains the right storage boundary for secrets at rest.
- The native crypto backend remains the right execution boundary for the security-critical primitives required by the iOS runtime.

### Remaining Dependency Risk

- `websockets` and asyncio-driven transports still need continued real-device validation under iOS lifecycle constraints.
- `aioquic` remains a higher-risk path than `ws`/`tcp` because it combines transport, TLS, and mobile platform behavior.
- The project should continue to treat transport enablement order as a product decision informed by real-device stability rather than by source-level portability alone.

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
  e2e_app/
    src/obstacle_bridge_ios_e2e/
      runner.py
  native/
    IPServer/
      PacketTunnelProvider.swift
      ObstacleBridgePythonBridge.m
      ObstacleBridgePythonBridge.h
  tests/
    test_ios_profile_config.py
    test_invite_import.py
```

If Briefcase is used, generated Xcode output should either be ignored or kept in a controlled path with clear regeneration instructions. The source of truth should remain the Python app code, native extension code, and configuration templates.

## How To Run ObstacleBridge In iOS Simulator

This quick path is for running the BeeWare iOS companion app in the iOS Simulator.

Prerequisites:

- macOS with Xcode installed (including simulator runtimes).
- Python greater than `3.10` is required for the iOS app path. The current validated setup has been tested with Python `3.14`.
- Python virtual environment for this repository.

If Python is not already installed on macOS, install Homebrew first:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After Homebrew is installed, follow the `brew shellenv` step printed by the installer for your machine, then install Python:

```bash
brew install python
python3 --version
```

From repository root:

```bash
cd ios
python3 -m pip install briefcase
```

First-time project bootstrap (or after major iOS template changes):

```bash
./scripts/create_ios_xcode_project.sh
briefcase build iOS
```

`./scripts/create_ios_xcode_project.sh` wraps `briefcase create iOS` and then applies the repo-owned packet-tunnel Xcode target patch automatically, so no manual Xcode project editing step is required after project generation.

Run the ObstacleBridge iOS app in simulator:

```bash
briefcase run iOS -a obstacle_bridge_ios -u --no-input -d "iPhone 17 Pro"
```

If the simulator device name differs on your machine, list available devices and replace the `-d` value:

```bash
xcrun simctl list devices available
```

Optional: run the standalone E2E probe app target (used by simulator integration tests):

```bash
briefcase run iOS -a obstacle_bridge_ios_e2e -u --no-input -d "iPhone 17 Pro"
```

## How To Build For A Real iPhone Without Exposing Personal Apple IDs

Use local shell variables or Xcode-managed signing rather than committing personal identifiers into the repository.

Recommended local-only variables:

```bash
export OB_APPLE_TEAM_ID="<YOUR_LOCAL_TEAM_ID>"
export OB_IOS_DEVICE_ID="<YOUR_LOCAL_DEVICE_UDID>"
export OB_IOS_DEVICE_NAME="<YOUR_LOCAL_IPHONE_NAME>"
```

These values should be set only in your local shell profile, a local helper script outside version control, or an interactive terminal session.

Prepare the generated project:

```bash
cd ios
./scripts/create_ios_xcode_project.sh
briefcase build iOS
```

Discover the attached device locally:

```bash
xcrun devicectl list devices
```

Build for the attached iPhone using local-only environment variables:

```bash
xcodebuild \
  -project build/obstacle_bridge_ios/ios/xcode/ObstacleBridge.xcodeproj \
  -scheme ObstacleBridge \
  -configuration Debug \
  -destination "id=${OB_IOS_DEVICE_ID}" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="${OB_APPLE_TEAM_ID}" \
  CODE_SIGN_STYLE=Automatic \
  -derivedDataPath /tmp/obstaclebridge-ios-device \
  build
```

Install the built app on the attached iPhone:

```bash
xcrun devicectl device install app \
  --device "${OB_IOS_DEVICE_ID}" \
  /tmp/obstaclebridge-ios-device/Build/Products/Debug-iphoneos/ObstacleBridge.app
```

Launch the app:

```bash
xcrun devicectl device process launch \
  --device "${OB_IOS_DEVICE_ID}" \
  com.obstaclebridge.obstacle-bridge-ios
```

Notes:

- If you prefer Xcode UI signing, open `build/obstacle_bridge_ios/ios/xcode/ObstacleBridge.xcodeproj`, select your local Apple team in `Signing & Capabilities` for both `ObstacleBridge` and `IPServer`, then return to the CLI commands above.
- Keep placeholder names such as `<YOUR_LOCAL_TEAM_ID>` and `<YOUR_LOCAL_DEVICE_UDID>` in documentation and scripts committed to the repo.
- Do not hardcode personal identifiers in `pyproject.toml`, native plist files, entitlements, or tracked shell scripts.
- If a reusable local helper is needed, create an untracked file such as `ios/.local-device-env` and source it manually:

```bash
source ios/.local-device-env
```

Example untracked file contents:

```bash
export OB_APPLE_TEAM_ID="<YOUR_LOCAL_TEAM_ID>"
export OB_IOS_DEVICE_ID="<YOUR_LOCAL_DEVICE_UDID>"
export OB_IOS_DEVICE_NAME="<YOUR_LOCAL_IPHONE_NAME>"
```

## Current iOS Runtime Status

The current design should be understood from implemented outcomes rather than from the original milestone guesses.

### Implemented Baseline

The following are now part of the working iOS design baseline:

- a containing `ObstacleBridge` app and an `IPServer` packet-tunnel extension target
- `NETunnelProviderManager` profile install/reuse/start flows from the app
- a stable app-to-extension control path using provider messages and App Group files
- embedded Python runtime startup inside the extension
- extension-owned WebAdmin, ChannelMux, SecureLink, and transport runtime ownership
- config synchronization between app-visible `Documents` storage and the shared App Group boundary
- extension log harvesting back into the app-visible `Documents/logs`
- iOS-native crypto support for the required ObstacleBridge security primitives
- working SecureLink over `myudp` on device
- working WebAdmin restart behavior inside the extension

### Design Consequence

This means the remaining work is no longer "prove whether the extension architecture is viable." That viability is already demonstrated.

The remaining work is primarily:

- completing packet/TUN carriage through `NEPacketTunnelFlow`
- broadening route behavior safely
- hardening transport behavior under more real-world iOS lifecycle and network transitions
- continuing to replace desktop/server assumptions with explicit iOS runtime contracts where necessary

## Remaining Questions That Still Matter

The old question set is no longer the right one. The questions that still matter now start from a working VPN client baseline:

- How should the extension behave when the iPhone sleeps, the screen turns off, or traffic is idle for a long period?
- Which keepalive, reconnect, or "sleep mode" policy is needed so the extension survives low-traffic periods without wasting power?
- Which transport should be treated as first-class on the maintained iOS production path: `myudp`, `ws`, `tcp`, and later `quic`?
- How much of the current WebAdmin operational surface should move into native iOS UI once the packet/runtime side is stable enough?
- Should certificate private key generation happen on iOS, or should keys be provisioned/imported externally for the first product release?
- What is the minimum supported iOS version for the maintained packet-tunnel product path?

## Current Forward Plan: Hardening A Working VPN Client

The next document-worthy plan should no longer read like "how do we make TUN work at all?" That part is already demonstrated. The forward plan should focus on hardening, parity, and productization.

### 1. Preserve The Single Source Of Truth For Tunnel Identity

What is now known:

- `TUN_routing` must remain the source of truth for tunnel addresses, routes, DNS, and MTU
- remote TUN lifecycle hook env such as `PEER_ADDR`, `PEER_ADDR6`, `TUN_ADDR`, `TUN_ADDR6`, `TUN_SUBNET`, and `TUN_SUBNET6` should be automatically derived from that block
- TUN service definitions should declare that a tunnel exists, but should not silently redefine the tunnel IP plan

Next hardening work:

- keep Python and Swift aligned on this derivation path
- continue to verify that invite generation/import preserves the same tunnel identity on both sides
- defend against stale fallback defaults that can silently reintroduce wrong tunnel addresses

### 2. Treat Sleep/Idle Survival As The Primary iOS Runtime Problem

What is now known:

- the original "sudden crash while forwarding" problem is no longer the main blocker
- the extension can still disappear later, especially when the iPhone sleeps or when traffic is idle for a while
- this points more strongly to lifecycle/keepalive handling than to the original packet-path viability question

Next hardening work:

- define what "connected while idle" should mean for the iOS product
- decide whether sparse control traffic or explicit keepalive maintenance is required
- document and test wake/reconnect behavior separately from initial connect behavior
- treat "sleep mode" as a first-class runtime state rather than as an accidental gap

### 3. Keep Python/Swift Functional Parity Visible

What is now known:

- a substantial amount of direct parity and mixed-runtime evidence exists already
- shared Swift runtime extraction reduced variance, but did not remove the need for parity evidence
- some failures that looked like runtime bugs were actually parity or startup-race issues revealed by mixed Swift/Python lanes

Next hardening work:

- keep parity-oriented tests visible in top-level reporting
- prefer shared implementation for behavior that has no true platform boundary
- add parity/interop coverage whenever Swift grows behavior that Python already has, or vice versa

### 4. Harden Extension Lifecycle, Not Only Packet Path

What is now known:

- packet carriage through `NEPacketTunnelFlow`, ChannelMux, SecureLink, and the overlay is proven
- extension-hosted WebAdmin, restart, config sync, and routed traffic are all part of the working baseline
- the remaining product risk is lifecycle resilience rather than architecture viability

Next hardening work:

- make reconnect behavior robust after peer restart, phone sleep, and interface changes
- keep tunnel/runtime startup deterministic when the app is not in the foreground
- ensure admin state reflects real transport/security truth instead of stale optimistic state

### 5. Continue To Use Layered Diagnostics

What is now known:

- provider-boundary PCAPs, connector-side PCAPs, JSONL logs, and host-side replays are all valuable
- device-only debugging became much less painful once packet/runtime boundaries were made explicit

Next hardening work:

- preserve diagnostics at the provider boundary, bridge boundary, and ChannelMux TUN boundary
- keep host-replay paths for iOS/Fedora failures so device-only incidents can be reproduced without the device
- prefer low-overhead diagnostics that do not themselves become a source of instability

### 6. Productize The User Surface Around The Working Core

What is now known:

- onboarding from invite/config works
- extension-owned WebAdmin is the effective operator surface today
- the app already behaves like a real VPN client in the important first-order sense: install profile, connect, route traffic, inspect status

Next hardening work:

- decide which WebAdmin flows should stay shared browser-style UI and which should later become native iOS UI
- keep the containing app disposable while the extension continues running
- continue to align the macOS app and the iOS app where there is no true platform boundary

## Current Milestone Language

The old milestone ladder is outdated. The product is no longer at "prove packet read/write" or "prove TUN traverses ChannelMux".

The current milestone language should be:

- Milestone A: working iOS VPN client with extension-owned runtime and real routed traffic
- Milestone B: stable config/import/service-catalog/tunnel-identity behavior across Python, macOS, and iOS
- Milestone C: resilient behavior across peer restarts, idle periods, and phone sleep/wake transitions
- Milestone D: stronger automation and parity evidence for the full Python/Swift mixed product surface
- Milestone E: gradual migration of selected operational flows from WebAdmin-only to richer native iOS product UI where useful

Recommended immediate next milestone:

- focus on Milestone C first
- make the working tunnel survive idle, sleep, and reconnect transitions more predictably
- keep documenting new knowledge as implemented outcomes, not as speculative architecture guesses
