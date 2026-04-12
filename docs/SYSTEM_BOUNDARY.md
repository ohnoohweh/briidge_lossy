# System Boundary

This document separates three things that are easy to mix together:

1. user use-cases
2. external assumptions and dependencies
3. project-owned behavior

Only the third category belongs in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md) as a normative project requirement.

## How to read the boundary

- User use-case:
  - what the operator wants to achieve in the real world
- External assumption:
  - a condition that must already be true in the surrounding environment
- Project responsibility:
  - behavior ObstacleBridge itself is expected to provide
- Out of scope:
  - something the project may rely on, but does not itself guarantee

## General external assumptions

These assumptions apply broadly across the project and should not be mistaken for project requirements:

- the operating systems on the participating hosts allow local socket creation and loopback networking
- Python and the required runtime dependencies are installed and runnable on the participating hosts
- the selected overlay transport is allowed by the surrounding network path often enough for connection attempts to be meaningful
- name resolution, local routing, and firewall policy are configured well enough for the chosen deployment mode
- the browser used for the admin UI supports the required HTTP and WebSocket behavior
- third-party libraries such as `websockets` and `aioquic` provide the protocol mechanisms the project builds on

## Why secure-link and TUN are inside the project boundary

It is reasonable to ask why ObstacleBridge includes secure-link and TUN-oriented capability at all, because complete VPN-style solutions such as WireGuard or OpenVPN can already provide encrypted tunnel transport and virtual network interfaces.

The boundary answer is:

- User use-case:
  - carry protected application traffic or routed IP traffic across network paths where the operator also needs ObstacleBridge's overlay selection, reconnect behavior, multiplexing, admin visibility, or obstacle-tolerant transports
- Project responsibility:
  - integrate protection and virtual-interface carriage directly with the overlay lifecycle, peer model, mux behavior, and admin surface that ObstacleBridge already owns
- Out of scope:
  - replacing the full product scope, deployment model, ecosystem, or mature PKI/key-management workflows of dedicated VPN systems such as WireGuard or OpenVPN

More concretely:

- A separate WireGuard or OpenVPN layer can solve many tunnel problems, but it lives outside ObstacleBridge's own overlay and observability model.
- When the operator wants the protected or TUN-carried traffic to follow ObstacleBridge-specific transports such as `myudp`, WebSocket, QUIC, or mixed listener/peer configurations, the security and TUN handling have to attach to the ObstacleBridge connection itself rather than to an unrelated external tunnel.
- Integrating these capabilities inside the project also allows peer-scoped policy, mux-aware fragmentation/reassembly, reconnect behavior, remote service publication, and admin/API visibility to remain consistent with the rest of the runtime instead of being split across two independent systems.
- This does not mean ObstacleBridge is trying to supersede dedicated VPN products. It means the project needs a bounded in-project secure-link and TUN capability for the specific cases where the operator wants VPN-like behavior carried inside the same obstacle-tolerant overlay system.

## Secure-link responsibility boundary

For the planned authentication and encryption capability, the surrounding system boundary is:

- External assumption:
  - suitable crypto-capable libraries are available on the target platform and behave correctly for signature verification, key agreement, and authenticated encryption/decryption
- Project responsibility:
  - load configured key material and certificates
  - apply certificate-policy checks such as issuer, role, validity interval, deployment scope, and serial-based revocation
  - decide when a peer is authorized to enter the protected secure-link data phase
  - bind the secure-link policy to the overlay connection lifecycle and the `ChannelMux` boundary
- Out of scope:
  - generating private keys on behalf of the operator
  - signing certificates on behalf of the admin trust anchor
  - replacing the cryptographic primitive implementations supplied by the selected crypto library

More concretely:

- ObstacleBridge is expected to use key material, certificates, and revocation inputs
- ObstacleBridge is not expected to be the certificate-authority tool that creates or signs that material
- the selected crypto library is expected to perform primitive-level signature verification, key agreement, and data-stream encryption/decryption once the project passes it the right inputs
- ObstacleBridge remains responsible for the policy decision around whether those cryptographic results are acceptable for one overlay peer

### Secure-link certificate input profile

The following fields belong to the certificate/key-material interface that ObstacleBridge expects to consume once secure-link is implemented. They are documented here because they constrain supplied inputs rather than describing already-delivered black-box behavior of the current runtime.

- `version`: certificate format version
- `serial`: deployment-unique certificate serial number
- `issuer_id`: identifier of the admin root issuer
- `subject_id`: stable identifier for the peer identity
- `subject_name`: human-meaningful label for operator visibility
- `deployment_id`: identifier binding the certificate to one deployment trust domain
- `public_key_algorithm`: algorithm identifier for the certified identity key
- `public_key`: certified peer public key material
- `roles`: one of `client`, `server`, or `client,server`
- `issued_at`: issuance timestamp
- `not_before`: start of validity interval
- `not_after`: end of validity interval
- `constraints`: optional future restrictions or permissions
- `signature_algorithm`: algorithm identifier for the admin-root signature
- `signature`: admin-root signature over the canonicalized certificate body

Expected semantics of that input profile:

- `serial` is the first revocation identity expected by the project
- `subject_id` is expected to stay stable across reconnects and normal certificate renewal for one peer identity
- `deployment_id` is expected to prevent accidental trust crossover between separate installations
- `roles` are expected to be machine-enforced by the project rather than treated as informational only
- the signed certificate body is expected to exclude the `signature` field itself and follow one canonical serialization rule

## Compression responsibility boundary

For the mux-aware compression capability, the surrounding system boundary is:

- External assumption:
  - a proven compression implementation is available on the platform (the current implementation uses Python stdlib `zlib`)
- Project responsibility:
  - decide when compression should be attempted for eligible mux frame types
  - enforce no-gain bypass so frames stay uncompressed when compression does not reduce size
  - decode compressed mux frames safely with bounded output checks
  - expose compression state and counters to operators through API and WebAdmin
- Out of scope:
  - inventing a novel compression algorithm specifically for ObstacleBridge tunnels
  - replacing or reimplementing primitive compression internals that are already provided by mature libraries

More concretely:

- ObstacleBridge is expected to integrate compression policy into the overlay lifecycle and frame boundary.
- ObstacleBridge is not expected to become a new compression-research project.
- The project intentionally prefers state-of-the-art, maintained compression libraries over custom codec invention.

## Use-case boundary mapping

### NAS behind outbound-only internet

| Layer | Description |
|---|---|
| User use-case | Reach services on a NAS or home server that cannot accept inbound internet connections directly |
| External assumptions | A public VPS or other reachable listener host exists; the NAS can make outbound connections; the chosen service ports are allowed by local firewalls |
| Project responsibility | Establish the overlay between NAS and VPS, keep it observable in the admin UI, and forward the configured TCP or UDP services through the overlay |
| Out of scope | Public DNS correctness, VPS uptime, ISP routing quality, and the remote client software that consumes the exposed service |

### WireGuard bridge through inspected internet access

| Layer | Description |
|---|---|
| User use-case | Carry a local UDP VPN endpoint across an environment where direct VPN traffic is blocked or degraded |
| External assumptions | The inspected network still allows the selected fallback transport such as WebSocket; both sides can run ObstacleBridge; the local WireGuard or OpenVPN endpoint exists |
| Project responsibility | Recreate the configured UDP listener through the overlay and carry traffic between the two peers over the selected overlay transport |
| Out of scope | Whether the surrounding network will always permit WebSocket or HTTPS-shaped traffic, and the correctness of the VPN configuration itself |

### High-loss obstacle path

| Layer | Description |
|---|---|
| User use-case | Keep UDP-style service traffic usable on a path with heavy loss or retransmission pressure |
| External assumptions | The path still passes enough UDP for the `myudp` transport to operate; both peers have compatible local runtime environments |
| Project responsibility | Provide retransmission, liveness, multiplexing, and recovery behavior through the `myudp` overlay so the configured service remains usable |
| Out of scope | The baseline packet loss characteristics of the network and absolute throughput guarantees under hostile conditions |

### WebSocket proxy traversal

| Layer | Description |
|---|---|
| User use-case | Connect a WebSocket peer client through a corporate or environment-mandated HTTP proxy |
| External assumptions | The proxy is reachable; the OS or environment proxy settings are configured correctly; the `websockets` library can perform the WebSocket protocol once a direct or proxied socket path exists |
| Project responsibility | Determine the effective proxy policy, honor platform-default proxy discovery or explicit overrides, establish HTTP `CONNECT` before the WebSocket handshake, and surface failures without corrupting the overlay state machine |
| Out of scope | Proxy server availability, correctness of external proxy configuration, and behavior of transports other than the WebSocket client path unless explicitly documented |

## Relationship to the other project documents

- [README.md](/home/ohnoohweh/quic_br/README.md):
  - user-facing use-cases and assumptions
- [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md):
  - project-owned black-box requirements only
- [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md):
  - component and responsibility decomposition inside the project
- [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md):
  - test evidence mapped to those project-owned requirements
