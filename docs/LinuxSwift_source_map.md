# Linux Swift Source Map

## Scope and method

This is the LSW-001 portability inventory for the Swift files selected by the
macOS build script on 2026-09-05. It is a design inventory, not evidence that
any listed file compiles for Linux. Files are grouped by the action required to
deliver a Linux target. The Swift toolchain available to this workspace is
Swift 6.3.2 for `x86_64-unknown-linux-gnu`.

The initial Linux v1 target is a foreground `ObstacleBridgeLinux` client with
`myudp`, TCP, and WebSocket only after their Linux implementations qualify;
SecureLink; compression; ChannelMux TCP, UDP, and client TUN services; config,
onboarding, and the supported Admin API. Linux QUIC, macOS helper/XPC, iOS
packet-flow, GUI/app-bundle controls, and packaged service/daemon support are
explicitly out of scope. Configurations selecting an unqualified transport or
platform-only connector must fail validation before opening a socket or TUN
device.

## Target classification

### Portable candidates

These files use Foundation only, already have a Glibc branch, or contain pure
runtime/codecs. They require Linux compilation and behavior tests before being
admitted, but do not require an Apple framework replacement by their current
imports.

```text
ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunnerMain.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAPI.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeAdminConfigSupport.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeAdminSnapshotSupport.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeAdminWebSupport.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxCodec.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTcpRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTunRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxUdpRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeNativeServiceSpec.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeOnboarding.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayLayerTransportAdapter.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayStackPlanner.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeRuntimeConfig.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskTransportAdapter.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeTunPing.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlayCodec.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlayPeerRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlaySessionCodec.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketOverlayRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketPayloadCodec.swift
```

`ObstacleBridgeHostRunnerMain.swift` is portable only as a thin entrypoint; its
current dependency, `ObstacleBridgeHostRunner`, is not. The Linux product needs
a distinct Linux runtime owner. `ObstacleBridgeQuicOverlayRuntime.swift` is a
pure logical runtime and may remain portable, but its use is deferred until a
Linux transport owner is qualified. `ObstacleBridgeChannelMuxCodec.swift`
imports CoreFoundation; verify the Linux Foundation toolchain exposes the
required API, otherwise replace that narrow use with Foundation-only code.

### Split contract from implementation

These files are behaviorally shared but currently import Apple-only frameworks,
Darwin unconditionally, zlib without a Linux system-library target, or mix
portable semantics with macOS-specific behavior. Extract the stable contract
and implement the Linux side in a platform target.

```text
ios/native/ObstacleBridgeShared/ObstacleBridgeAdminAuth.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeAdminConfigChallenge.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeChannelMuxTCPTransportOwner.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeCompressLayerRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeConfigSecretCodec.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeNativeCrypto.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeNativeProxyConnections.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayChannelCore.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeOverlayConnectionSupport.swift
ios/native/ObstacleBridgeShared/ObstacleBridgePeerAddressProtocolRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgePeerAddressResolver.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeProxyServer.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskCodec.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeSecureLinkPskRuntime.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeTcpOverlayTransportOwner.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeTunProbeDiagnosticsSupport.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeUdpOverlayTransportOwner.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeWebAdminServer.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeWebSocketOverlayTransportOwner.swift
```

LSW-003 resolves the crypto portion of this split with the pinned
`apple/swift-crypto` 4.5.1 `Crypto` product, recorded in `Package.resolved`.
The portable `ObstacleBridgeCrypto` contract supplies SHA-256, HMAC-SHA-256,
HKDF-SHA-256, PBKDF2-HMAC-SHA-256, AES-256-GCM, ChaCha20-Poly1305, Ed25519,
and X25519. Its SecureLink PSK transcript functions have Python-derived fixed
vectors. Existing Apple targets are unchanged; their subsequent adoption of
the portable contract remains a parity-preserving refactor rather than a Linux
runtime dependency.

Remaining split decisions:

- `Network` transport/listener/proxy owners need POSIX/Linux implementations
  behind their existing runtime contracts. This includes TCP, UDP, WebSocket,
  Admin HTTP, and proxy connection ownership.
- `Security` used by the WebSocket owner needs a Linux TLS policy/backend.
- unguarded Darwin imports in peer resolution, UDP ownership, diagnostics, and
  secret handling need Glibc/POSIX replacements or separation.
- compression needs an SPM system-library target for zlib, with its C module
  map and deployment dependency stated by the build.

### Linux implementation required

No selected macOS source provides a Linux `/dev/net/tun` implementation. Add a
Linux packet adapter conforming to the existing ChannelMux TUN runtime's
raw-packet contract. It creates an `IFF_TUN | IFF_NO_PI` descriptor, integrates
nonblocking file-descriptor reads with the Linux event loop, reports counters,
and delegates address/route/DNS lifecycle to `scripts/client-tun-hook.sh`.

The Linux target also needs its own executable runtime owner. It orchestrates
configuration, portable runtime, Linux transport owners, lifecycle hooks,
signals, shutdown, and Admin server. It is not a conditional branch inside the
macOS host runner.

### Excluded from Linux v1

These sources are macOS/iOS application, privilege, or packet-flow surfaces and
must not be selected by the Linux package.

```text
ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift
ios/native/ObstacleBridgeApp/ObstacleBridgeMacAppMain.swift
ios/native/ObstacleBridgeApp/ObstacleBridgeTunnelControl.swift
ios/native/ObstacleBridgePrivilegedHelper/ObstacleBridgeTunPrivilegedHelperMain.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeMacOSTunAdapter.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeMacOSTunHelperService.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayTransportOwner.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeTunHelperContract.swift
ios/native/ObstacleBridgeShared/ObstacleBridgeTunHelperXPCTransport.swift
```

The helper contract is excluded because its current concrete service and XPC
transport are macOS-specific. A future Linux privileged helper, if needed,
requires its own authentication and security design. The QUIC transport owner
is excluded because it uses Network.framework; Linux must reject QUIC until a
new backend has passed qualification.

## Shared contracts and parity evidence

| Behavior | Linux implementation owner | Required parity evidence |
| --- | --- | --- |
| Config and service schema | portable runtime + Linux validation | Python/Swift config acceptance and rejection tests |
| SecureLink/crypto bytes | portable protocol + Linux crypto backend | known-answer, codec, and mixed-runtime handshake vectors |
| ChannelMux TCP/UDP/TUN frames | portable ChannelMux + Linux adapters | component runner and mixed-runtime frame/packet tests |
| Transport readiness/reconnect | Linux owners | Python/Swift lifecycle and reconnect integration tests |
| Admin status and routing fields | portable Admin contract + Linux server | Admin component payload comparison |
| TUN packet, hook, and cleanup lifecycle | Linux TUN/hook adapter | elevated `/dev/net/tun`, route, DNS, and teardown tests |

Existing Python/Swift drift and shared-source parity guards remain mandatory for
changes to shared semantics. Platform sources may diverge only below the
adapter contract, with the differing platform behavior named in tests.

## Completion record

LSW-001 is complete: every source selected by the macOS build script is
classified above; the Linux v1 feature matrix and exclusion behavior are
defined; Apple-only dependencies have a replacement, split, or exclusion; and
the parity evidence is mapped by behavior. LSW-002 may begin using this map.
