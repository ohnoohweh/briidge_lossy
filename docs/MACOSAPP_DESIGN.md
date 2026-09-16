# macOS App Design

## Purpose

This document records the current macOS application design for ObstacleBridge,
with special attention to the remaining gaps between:

- the Python runtime, which can now establish a working macOS full-tunnel TUN
  session when started with sufficient privilege
- the Swift-based macOS app, which now uses a privileged host-runner bridge
  for real `utun` ownership, but still needs a bit more hardening and parity
  verification to behave as predictably as the Python path

The goal is to keep the macOS app aligned with the existing ObstacleBridge
architecture and with the working Linux and Python/macOS behavior, while being
honest about the macOS-specific privilege boundary.

## Current product status

The project now has three meaningfully different macOS runtime shapes:

1. Linux/Python-style ObstacleBridge, running on Linux:
   - already supports working full-tunnel TUN behavior
   - remains the main reference implementation for end-to-end TUN behavior
2. Python runtime on macOS:
   - now supports real `utun` creation
   - can configure addresses and default routes
   - can preserve an underlay host route to the overlay peer
   - can move real traffic through the tunnel when started with privilege
3. Swift-based macOS app:
   - can load config, start overlay transports, and expose admin state
   - launches a privileged bundled host runner when local TUN is configured
   - can create and configure a real local `utun` interface during normal app
     startup
   - uses the same Darwin TUN hook script family as the Python runtime

That means the Python/macOS path is the proven reference, and the Swift app is
now close enough that the main remaining work is parity hardening rather than
basic capability creation.

## What is already working on macOS

### Python runtime

The Python path now demonstrates the intended macOS TUN behavior:

- local `utun` creation succeeds when the process is started with sufficient
  privilege
- the Darwin-specific TUN hook scripts can configure the local interface
- IPv4 and IPv6 default routes can be redirected to the tunnel
- a host route to the overlay peer can be preserved on the physical underlay
- public traffic can exit through the remote peer as expected

This is important because it proves the ObstacleBridge protocol and control
model are suitable on macOS down to the OS-specific TUN boundary. The problem
is no longer "can macOS do it at all?" The problem is now "how should the
Swift app obtain and use the same privilege correctly?"

### Swift app runtime

The Swift app now does the important parts of the macOS tunnel flow:

- loads runtime config from the app support config path
- starts the overlay runtime
- supports the transport matrix used elsewhere in the project
- exposes admin APIs and connection state
- carries the TUN service definition into runtime state
- launches the privileged bundled host runner when TUN is configured
- passes DNS servers, included routes, excluded routes, and preserved underlay
  peer-route hints into the same macOS hook used by Python
- resolves the hook path to the bundled app resources so rebuilds carry the
  latest hook logic into the app bundle

The important practical consequence is that Swift is no longer missing the real
`utun` step. The remaining gap is behavioral parity: making sure the app bundle
reliably realizes the same routing and DNS outcome that Python already proves.

## Proven macOS-specific constraint

The project reproduced a concrete macOS platform boundary:

- raw Darwin `utun` creation from a normal process can fail with
  `Operation not permitted`
- the same Python runtime succeeds when relaunched through an elevated path
- the Swift app therefore needs an equivalent privileged helper path

This explains the earlier product split:

- Python on the command line can ask the user for admin permission and then
  continue
- a GUI app cannot rely on the same ad hoc terminal-style `sudo` interaction

That boundary is handled by the bundled `SMAppService` daemon and its XPC
client. The remaining question is reliable qualification of that packaged
helper in the primary application lifecycle.

## Why Python can work without Network Extension

It is tempting to think "if Python can do it, the app should simply do the
same." The subtle difference is the execution model:

- the Python CLI can be relaunched with elevated privilege
- once elevated, it can open `utun`, configure routes, and run the TUN hooks
- this is acceptable as a developer or power-user flow

The Swift app, by contrast, is a normal macOS application process:

- it does not automatically become privileged
- it should not rely on deprecated one-off privilege APIs
- it needs a structured, system-approved privileged path if it wants to own the
  same `utun` and route-management responsibilities

So the fact that Python works without a real macOS Network Extension is useful
and encouraging, but it does not remove the need for a proper privilege design
for the app.

## Current helper implementation

The app bundle contains three executables with distinct responsibilities:

- `ObstacleBridge` is the primary AppKit application and its
  `CFBundleExecutable`.
- `ObstacleBridgeHostRunner` owns the Swift overlay/runtime and invokes the
  TUN-helper client.
- `ObstacleBridgeTunHelper` is the privileged system daemon managed through
  `SMAppService` and reached over its Mach XPC service.

When a configuration needs a local TUN, the primary app starts its app-scoped
host runner. The host runner requests the packaged helper through the shared
XPC contract; the helper, rather than the GUI process, owns `utun` and route
operations. The GUI application remains a user process. For a local-TUN
configuration, its host-runner launch can require administrator authorization;
the qualification-only admin configuration deliberately contains no TUN
service, so it can validate BTM registration and XPC without prompting.

## Packaged XPC qualification and test preconditions

The packaged helper is a product boundary, not a unit-test substitute. A test
must exercise the same signed bundle and the same application lifecycle as a
user launch, otherwise macOS Background Task Management (BTM) can reject a
validly packaged daemon before XPC is available.

### Observed macOS qualification blocker

On the macOS 26 qualification host, the elevated packaged-XPC test has
observed BTM rejecting the daemon with `fullPath is nil` and a null container.
The diagnostic also reports that the BTM item has no container, even though the
bundle inspection reports the daemon as registered and enabled. The resulting
XPC ping times out because launchd never starts the service.

The confirmed host is **macOS Tahoe 26.5 (build 25F71)**. Its interactive GUI
app can establish a working local TUN session, but that success is not
packaged-XPC success: the app runs an administrator-authorized root
`ObstacleBridgeHostRunner`, and its Admin snapshot reports
`transport: loopback`, `backend: darwin-native`, and a connected local TUN.
The same snapshot reports the packaged daemon as registered and enabled but
not running, with `xpc_reachable: false` and an XPC ping timeout. The host
runner selects XPC only after the package reports it reachable; otherwise it
uses the in-process loopback helper. A working `utun` therefore proves the
host-runner fallback and route hooks, not the SMAppService/XPC product
boundary.

This is a failing qualification result, not an approval skip. The test records
the BTM error, plist contents, signing identity, helper location, registration
state, and XPC reachability so a failure cannot be misreported as Swift/Python
parity.

It does **not** demonstrate that a GUI-launched app cannot use TUN. The normal
macOS app has successfully launched its TUN helper. The original test executed
the nested `ObstacleBridgeHostRunner` directly, which is not the primary
bundle executable and bypasses the AppKit/LaunchServices application context
from which BTM derives the associated container. The qualification harness now
uses the primary `ObstacleBridge` executable as the invoking user and provides
an isolated test config through `OBSTACLEBRIDGE_APP_RUNTIME_CONFIG`. The
interactive Terminal.app qualification run launches that primary bundle through
LaunchServices and still reproduces `fullPath is nil`; the failure is therefore
not explained by direct executable launch or an SSH-only environment.

### External evidence and version scope

Apple documents `SMAppService` as the macOS 13-and-later mechanism for helpers
inside the main app bundle, and requires a daemon plist in
`Contents/Library/LaunchDaemons`; its `BundleProgram` path is relative to that
bundle. [Apple's SMAppService documentation](https://developer.apple.com/documentation/servicemanagement/smappservice)
and [helper-migration guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)
therefore support the bundle shape used here. Apple DTS’s
[Getting Started with SMAppService](https://developer.apple.com/forums/thread/802443)
is the reference minimal daemon project: it was tested with Xcode 26.0 on
macOS 15.6.1, embeds a command-line daemon at `Contents/MacOS`, copies its
plist to `Contents/Library/LaunchDaemons`, and registers it by plist name. It
intentionally stops short of XPC; the minimal reproducer below adds only a
single XPC ping/echo to that structure. Apple DTS also shows a matching
Mach-service name and privileged `NSXPCConnection` pattern in a
[working SMAppService daemon example](https://developer.apple.com/forums/thread/799910).

ObstacleBridge has confirmed the failure only on macOS 26.5 (25F71); it has
not yet qualified this exact app bundle on macOS 13, 14, 15, or an earlier
macOS 26 release. Apple’s published macOS release-note index currently lists
26.6 beta material, but no ServiceManagement/BTM fix for this symptom was
identified. The version plan is consequently evidence-driven:

- run the unchanged signed installer-owned artifact on a macOS 15 host first;
  a successful XPC packet-carry result would establish a usable earlier-version
  route while isolating the macOS 26 behavior;
- repeat on the newest available macOS 26 update only as a new qualification
  run, not as an assumed fix;
- retain the loopback/privileged-host-runner path as an observable fallback,
  but do not label it packaged-XPC parity;
- if the failure persists for an installed artifact, attach BTM/launchd logs,
  bundle identity, plist, and signing diagnostics to an Apple Feedback report.

### Resolution path for the BTM blocker

The failing BTM state is internal to macOS: it has accepted the daemon's
registration but cannot associate the relative LaunchDaemon plist URL with a
container. Repeated retries, longer XPC timeouts, or treating the result as an
approval skip cannot correct that state. Resolution work proceeds in this
order:

1. **MAPP-XPC-MIN-001 — build a minimal SMAppService/XPC reproducer.** Create
   a standalone macOS sample project, outside the ObstacleBridge runtime and
   with no TUN, overlay, WebAdmin, runtime-config, or route-hook code. It must
   follow Apple DTS’s [minimal SMAppService
   structure](https://developer.apple.com/forums/thread/802443): one
   unsandboxed SwiftUI container app, one Swift command-line daemon embedded
   at `Contents/MacOS`, and one daemon plist copied to
   `Contents/Library/LaunchDaemons`. Add only the following XPC surface beyond
   the DTS example: a single Mach service in the daemon plist, an
   `NSXPCListener` in the daemon, a privileged `NSXPCConnection` in the app,
   and a request/reply `ping` that returns a fixed version string.

   Its source, build script, and README must let an external reviewer build
   the artifact with their own Team ID, inspect its exact bundle tree and
   signatures, approve registration from the app UI, and run one command that
   records registration status, `launchctl` system status, unified-log
   first-light output, and ping result. The result matrix must distinguish
   registration denied, daemon not launched, connection failure, incorrect
   reply, and successful ping. Run the unchanged artifact first on macOS
   15.6.1-or-equivalent and then on macOS 26.5; publish the macOS version,
   Xcode version, signing mode, bundle tree, plist, and diagnostic transcript
   with each result. This small reproducer is the communication artifact for
   Apple DTS, developer forums, and third parties; it must be independently
   runnable without the ObstacleBridge repository.

2. Qualify an installer-owned app location. Build the team-signed bundle once,
   install that exact artifact through the product installation flow in
   `/Applications`, then start its primary executable through LaunchServices.
   The test must target the installed path, not copy, re-sign, or mutate it.
   This checks whether BTM's container database rejects the development-tree
   artifact rather than the bundle contract.

   Test sequence:
   1. Run ios/scripts/build_macos_app.sh with the Apple Development identity.
   2. Install that exact resulting ObstacleBridge.app into /Applications without copying/re-signing/mutating it afterward.
   3. Start /Applications/ObstacleBridge.app normally through Finder, Dock, or open -a ObstacleBridge.
   4. Use a TUN-enabled config and observe that the helper registers, starts, and becomes XPC-reachable; then verify utun/route behavior.

3. Keep the structural contract fixed while testing that installation: same
   app and helper Team ID, nested-first/outer-last signing order, daemon plist
   location, associated app bundle identifier, Mach service name, and helper
   executable path. Capture `codesign`, plist, `SMAppService` status, launchd
   status, and BTM logs with every failure.
4. If an installed, LaunchServices-started artifact still reports `fullPath is
   nil`, collect a sysdiagnose plus the BTM and launchd records and file an
   Apple feedback report. The evidence should include the app path, BTM item
   UUID, helper label, and the complete signing/plist diagnostics. There is no
   safe application-code workaround for a BTM container lookup failure.
5. Keep the qualification test failing until an approved, reachable XPC daemon
   carries packets. Do not mask the platform failure with a loopback client or
   an ad-hoc helper launch. The existing privileged host-runner path remains a
   separately observable runtime path, not proof that the packaged XPC product
   boundary qualified. While the BTM blocker is known, packaged-XPC tests are
   explicitly opt-in with `--run-packaged-xpc-qualification`; they are not part
   of the routine elevated functional matrix.

### Required bundle and signing shape

The build is qualified only when all of these conditions hold:

- The app bundle contains `Contents/MacOS/ObstacleBridge`,
  `Contents/MacOS/ObstacleBridgeHostRunner`, and
  `Contents/MacOS/ObstacleBridgeTunHelper`.
- The daemon plist is at
  `Contents/Library/LaunchDaemons/com.obstaclebridge.macos.ObstacleBridge.TunHelper.plist`.
  Its `Label` is the helper bundle identifier,
  `MachServices` exposes `<helper-id>.xpc`, `BundleProgram` is
  `Contents/MacOS/ObstacleBridgeTunHelper`, and
  `AssociatedBundleIdentifiers` contains the app bundle identifier.
- App, host runner, and helper carry non-ad-hoc signatures from the same Apple
  Development team. The nested executables are signed with their explicit
  identifiers first; the outer app bundle is signed last. Do not use `--deep`,
  which can replace the carefully constructed nested signature chain.
- The signed artifact is rebuilt after any source change that affects an
  executable, plist, entitlement, or bundle resource. A source-tree build is
  not evidence for a previously built `.app` bundle.

The normal signed build on the macOS host is:

```bash
cd ~/briidge_lossy
OBSTACLEBRIDGE_CODESIGN_IDENTITY='Apple Development: Oliver Wackerl (K844X8Y374)' \
  ios/scripts/build_macos_app.sh
```

The signing key must be available to the interactive user/keychain session.
Non-interactive SSH signing can fail with `errSecInternalComponent` even when
the identity is listed by `security find-identity`.

### CI build evidence and preview distribution

The macOS Swift-backed CI lane builds the same complete normal `.app` bundle
that its HostRunner tests reuse. It validates the outer app and each nested
executable with `codesign --verify --strict`, validates both plists, and stores
one ZIP together with its SHA-256 and embedded build-info JSON as a CI
artifact. This makes the artifact evidence refer to the exact bundle compiled
for the tests rather than to a second, untested build.

On successful `main` builds, the release workflow replaces the assets on the
`macos-preview` GitHub Release. This provides a toolchain-free download for
evaluation. Hosted CI does not have the product Team ID signing key or a
notarization credential, so this preview is ad-hoc signed and is not evidence
for Gatekeeper acceptance, installer ownership, or the packaged SMAppService
path. Users must verify its published SHA-256; a team-signed and notarized
release remains the required production distribution path.

### Required test execution shape

- Run the elevated wrapper with an absolute `--app-bundle` path to test that
  exact signed artifact without rebuilding it. Start with one selected test;
  later selected tests may reuse the same artifact.
- The wrapper may run elevated to perform privileged TUN assertions, but the
  app/host-runner launch must drop back to `SUDO_UID`/`SUDO_GID`. Its isolated
  runtime config and log directory must be owned and readable by that invoking
  user. Both `ObstacleBridgeTunnelControl` and `ObstacleBridgeHostRunner` must
  honor `OBSTACLEBRIDGE_APP_RUNTIME_CONFIG`; otherwise the primary app falls
  back to its regular user configuration and can trigger an unrelated
  administrator prompt.
- Run from an active graphical login session. `SMAppService` registration and
  AppKit/LaunchServices lifecycle are user-session operations; a root-only or
  headless daemon context is not equivalent. An elevated test must enter the
  invoking user's GUI launch domain with `launchctl asuser <SUDO_UID>` before
  calling `open`; merely dropping UID retains the root bootstrap namespace and
  fails with LaunchServices error `-10810`. A remote SSH process remains
  headless even if `launchctl print gui/<uid>` succeeds: on macOS 26 it still
  receives `-10810` from `open`. Run the LaunchServices qualification command
  from Terminal.app (or another process already in the Aqua session), not from
  SSH.
- Keep the primary app alive long enough for registration and first XPC use.
  The helper's synchronous ping may take up to 15 seconds, so status and
  activation requests use at least a 20-second timeout and the test process
  needs a lifetime beyond the initial registration window.

The intended one-case invocation is:

```bash
sudo -n ./scripts/run_macos_swift_elevated_tests.sh \
  --app-bundle /Users/ohnoohweh/briidge_lossy/ios/build/macos/ObstacleBridge.app \
  tests/integration/test_macos_swift_elevated.py::test_macos_swift_elevated_packaged_xpc_helper_carries_packets_when_approved
```

Do not convert the BTM failure into a skip or repair the global helper state as
part of the test. The failure is a useful qualification signal; diagnostic or
repair commands must remain explicit operator actions.

### Functional fallback lane

The elevated HostRunner packet-carry lane covers the same post-authorization
behavior as the running GUI app. The GUI asks through macOS's AppleScript
administrator sheet; the harness instead requires an explicit `sudo` grant
before it starts the same bundled HostRunner, and does not automate that GUI
sheet. The bundled HostRunner then selects the packaged XPC client only when
it is reachable and otherwise selects the in-process Darwin-native loopback
helper. It must still create the real `utun`, apply the route hooks, and carry
packets to the Python peer.

Run it in a local Terminal on the Mac with:

```bash
./scripts/run_macos_swift_elevated_tests.sh --interactive-elevation --reuse-macos-build \
  2>&1 | tee logs/test-swift-elevated-functional.txt
```

`--interactive-elevation` asks the operator for the Terminal administrator
credential; it is the harness equivalent of the GUI application's approval
boundary. Unattended CI leaves that option out and requires its scoped
passwordless `sudo` rule instead.

The default invocation runs only the packet-carry and route/DNS fallback
cases. Packaged-XPC cases are deliberately excluded until the BTM blocker is
resolved; run them only with `--run-packaged-xpc-qualification` when performing
the focused resolution qualification.

The route/DNS case treats an individual slow Admin verification response as
transient and retries within its bounded convergence window. That endpoint
performs synchronous local probe and name-resolution work; a single read
timeout is not evidence that the real `utun`, route, or DNS state failed.

This functional fallback result must be reported as `transport: loopback`; it
does not close the strict packaged-XPC qualification lane.

This lane was manually qualified on the confirmed macOS Tahoe 26.5 (25F71)
host. The default functional matrix selected its two cases and passed in 28.79
seconds: HostRunner real-`utun` packet carry, plus route/DNS apply and cleanup.
The three packaged-XPC qualification cases were deselected as intended. This
establishes the usable fallback contract—explicit operator authorization,
bundled HostRunner, real `utun`, route hooks, DNS restoration, and packet
carriage—while leaving the packaged-XPC/BTM qualification independently open.

### Python Darwin-native elevated matrix

The same Tahoe 26.5 (25F71) host also passed the complete Python elevated
matrix on 2026-09-16: **5 passed in 82.13 seconds**. It covers inline TUN
route/DNS verification, helper-created `utun` packet carriage and hook
application, a live helper-owned scoped-route/DNS apply/remove case, and both
helper-death cleanup paths. The final diagnostics contained no
ObstacleBridge helper process and no test-owned IPv4 route.

The Darwin client hook preserves valid scoped included routes when no underlay
route is available to protect a non-loopback overlay peer. That condition is
fatal only for a full-tunnel switch, where retaining the included default route
could capture the overlay transport itself. The hook logs the missing underlay
explicitly, so a constrained network is distinguishable from a loopback peer.

## Current parity status

What is already aligned with Python on macOS:

- the app bundle ships the same `scripts/client-tun-hook-macos.sh` logic that
  the Python runtime uses
- the Swift host runner passes the tunnel addresses, gateways, MTU, DNS
  servers, included routes, excluded routes, and preserved underlay peer route
  metadata into that hook
- the bundled app resources are now the source of truth at runtime, so hook
  changes require an app rebuild exactly as expected
- the app/helper environment exports a fixed system `PATH`, so privileged hook
  execution can resolve `route`, `ifconfig`, `netstat`, and related tools

What still needs attention for true day-to-day parity:

- repeated app starts should realize the same routing outcome as Python without
  landing in the transient "connecting" or "handshaking" stalls we observed
- full-tunnel DNS behavior should stay consistent across app restart cycles
- the Swift transport path still needs routine regression testing against the
  Python reference path whenever the hook contract changes

### Swift shared-first policy

To keep macOS and iOS Swift drift as small as possible, changes should land in
the shared Swift layer whenever the behavior is not inherently bound to one OS.

Policy:

- prefer `ios/native/ObstacleBridgeShared/` for runtime logic, payload
  vocabulary, counters, state naming, helper structs, and Admin/API field shape
- keep `ios/native/ObstacleBridgeApp/` focused on macOS-specific wiring such as
  helper/XPC packaging, `utun` host integration, lifecycle ownership, and other
  OS-bound APIs
- treat edits in platform-specific Swift files as a last resort; when a macOS
  platform file must change for shared runtime behavior, the corresponding iOS
  runtime must stay in parity in the same change unless the difference is
  intentionally platform-specific and documented
- when a shared/runtime Swift change touches observable behavior, update the
  Swift parity source guards in `ios/tests/test_m3_native_sources.py` and/or
  `ios/tests/test_macos_swift_host_runner.py`

Enforcement:

- repository guard `scripts/check_swift_shared_parity_guard.py`
- CI workflow `.github/workflows/swift-shared-parity-guard.yml`

Practical interpretation:

- if the change is about behavior, schema, counters, verification semantics, or
  operator-visible vocabulary, start in shared Swift
- if the change is about macOS privilege packaging or host-only OS integration,
  keep it local to the macOS app layer

## Runtime architecture

The Swift host-runner and dedicated privileged helper architecture is the
current runtime shape. Remaining work is qualification hardening: prove the
primary GUI application lifecycle can register and reach the packaged helper
reliably across supported macOS releases, and preserve the Python reference
runtime's observed route, DNS, and teardown behavior.

The current packaged-helper architecture preserves the design investment already made
in:

- overlay transports
- secure-link
- ChannelMux
- admin observability
- config and invite handling

It also keeps the Python and Swift products conceptually aligned:

- same runtime model
- same tunnel plan
- same service model
- different OS-specific privilege packaging

## Why not jump straight to Network Extension

A real macOS `NetworkExtension` remains a valid long-term target, but it is not
the next required step.

Reasons:

- the Python/macOS runtime already proves the protocol and tunnel model can work
  on macOS without rearchitecting around Network Extension first
- the Swift app already has substantial transport, mux, and config work that
  should be reused
- introducing a macOS packet tunnel extension is a much larger packaging,
  entitlement, lifecycle, and observability step

So the current recommended sequence is:

1. make the Swift app functionally match the working Python/macOS TUN path
   through a privileged helper
2. only then decide whether a full Network Extension product is worth the added
   complexity and platform ceremony

## Apple platform guidance

Current Apple guidance points away from older privilege approaches:

- `AuthorizationExecuteWithPrivileges` is deprecated
- `SMJobBless` is also deprecated
- the modern direction is `SMAppService` for helper management

The hardened macOS app uses:

- a privileged helper managed via `SMAppService`
- XPC communication between app and helper
- a clear helper API for TUN and route lifecycle operations

The outstanding task is not selecting a privilege mechanism; it is qualifying
the existing `SMAppService` + XPC implementation under the real primary-app
launch context and detecting macOS BTM regressions accurately.

## Responsibilities of the privileged helper

The helper should own the operations that require elevated system access:

- create and tear down the local `utun` interface
- report the realized interface name back to the app
- configure IPv4 and IPv6 point-to-point tunnel addressing
- apply and remove default routes for full-tunnel mode
- preserve an underlay host route to the overlay peer
- perform teardown cleanup on disconnect or app stop

The main Swift app should continue to own:

- overlay transport lifecycle
- ChannelMux and secure-link runtime logic
- config loading and validation
- admin UI and observability
- user-initiated connect and disconnect flow

This keeps the helper small and focused, which is good both for reliability and
for future review of the privileged boundary.

## Parity target with Python and Linux

The parity goal is not merely "a TUN row appears in WebAdmin." The parity goal
is:

- Swift app establishes a real local macOS `utun`
- the interface is configured using the same tunnel plan semantics as Linux and
  Python/macOS
- default routing moves to the tunnel
- the underlay route to the overlay peer is preserved
- live traffic really flows through the tunnel
- admin state reflects real TUN open/connected behavior instead of only a
  logical listener row

## Observed macOS IPv6 route behavior

Recent live tracing on macOS showed an important difference from the Linux and
Python-host-TUN path:

- IPv4 default-route takeover onto `utun` can succeed and verify cleanly
- direct IPv6 `default` replacement on macOS is much less reliable
- `route -n get -inet6 default` can fail or return unstable results even while
  the kernel still holds other scoped IPv6 defaults
- rolling back after that partial IPv6 failure can leave the machine in an
  awkward split state unless the script is careful

To keep the behavior config-driven while still matching what macOS will accept,
the client hook now interprets the configured IPv6 full-tunnel intent
(`included_routes6` containing `::/0`) as two explicit routes:

- `::/1`
- `8000::/1`

Those two routes together capture the global IPv6 space without requiring the
script to replace the system's own IPv6 `default` route directly. This is not
a separate product policy hard-coded outside config; it is the macOS-specific
realization of the same configured full-tunnel intent.

That gives the project a safer operating model:

- config remains the source of truth
- macOS-specific route programming happens in the hook
- IPv4 and IPv6 can now be debugged independently without needlessly tearing
  down the whole routing session

## macOS full-tunnel route activation learnings

Recent Swift-app testing narrowed the remaining macOS full-tunnel problem to
route ordering and underlay preservation, not to `utun` creation itself.

The current observed sequence is:

- the Swift host runner can establish the WebSocket overlay to the peer first
- when `ws_peer_addresses` is non-empty, that Swift owner connects through the
  selected literal IPv4/IPv6 underlay endpoint while retaining `ws_peer` for
  the HTTP Host header and TLS server identity
- the privileged app bundle can create a real local `utun`
- the hook can configure the TUN address pair, for example
  `192.168.106.3 -> 192.168.106.1`
- full-tunnel included routes can be installed as split routes, for example
  `0.0.0.0/1` and `128.0.0.0/1`
- if the overlay peer host route is missing or installed too late, macOS can
  clone the peer route onto `utun` and the WebSocket transport immediately loses
  its own underlay path

This makes the key rule explicit:

- the physical underlay route to the overlay peer must be captured while the
  overlay is connected but before the TUN full-tunnel routes are installed
- the peer bypass route must be installed as a more-specific host route before
  the split full-tunnel routes are allowed to attract general traffic

For the current server peer this means the healthy route shape is:

- `198.51.100.5/32` stays on the physical interface, currently `en0` via
  `192.168.179.2`
- public IPv4 destinations such as `142.251.20.94` move to `utun`
- the same principle applies to IPv6 peer exclusion, with `/128` host routes
  used for explicitly excluded IPv6 peers

Several macOS-specific operational details were also proven:

- the configured full-tunnel route `0.0.0.0/0` should be realized on macOS as
  split routes instead of by deleting/replacing the system default route
- the hook must treat `/32` and `/128` excludes as host routes, not generic
  network routes
- the hook must not install explicit excluded routes for loopback ranges such
  as `127.0.0.0/8`, `127.0.0.1/32`, or `::1/128`; macOS already owns those
  through the kernel loopback route, and adding an underlay route for them can
  make even `127.0.0.1` resolve through a physical interface such as `en0`
- the Swift app passes `./scripts/client-tun-hook-macos.sh`, but the running
  app resolves that to the bundled copy inside
  `ObstacleBridge.app/Contents/Resources/scripts`
- rebuilding the app bundle is therefore required after hook changes
- the app/helper environment cannot be assumed to have an interactive shell
  `PATH`; the hook exports `/usr/sbin:/sbin:/usr/bin:/bin` explicitly so tools
  such as `netstat`, `route`, and `ifconfig` resolve in the privileged context
- Swift can call `down ios-utun` while the actual realized interface was
  `utun4`, so teardown must remove route state recorded under any
  ObstacleBridge-managed interface name, not only the requested symbolic name

The Swift host runner now captures the overlay peer's working IPv4 underlay
route immediately on overlay-connect and passes that gateway/interface into the
macOS hook. The hook then installs the peer host route before the split
full-tunnel routes are installed. The healthy observed route state is:

- `route -n get 198.51.100.5` returns the physical underlay route on `en0`
- `route -n get <public IPv4>` returns one of the split full-tunnel routes on
  `utun`

If the peer still lands on `utun`, the next diagnostic should be a route monitor
redirected to a file across app startup, plus the hook log and the
`/tmp/obbridge/*.excluded*` state files. The specific failure signature to look
for is an excluded peer entry such as `198.51.100.5/32||`, which means the hook
knows the peer should be excluded but did not receive or discover an underlay
gateway/interface for it.

After IPv4 underlay preservation was proven, the next observed blocker moved up
to the WebSocket transport layer: the Swift runtime opened the WebSocket and
entered SecureLink handshaking, but logged repeated
`unsupported websocket overlay kind 1` failures. Python's WebSocket transport
uses the following one-byte overlay kinds:

- `0x00`: app payload
- `0x01`: ping control frame
- `0x02`: pong control frame

Swift must therefore treat kind `1` and kind `2` as WebSocket overlay control
frames, not as corrupt app payload. The macOS app now answers kind `1` ping
frames with kind `2` pong frames before app payload is passed into SecureLink
and ChannelMux.

## Python macOS helper learnings

The Python `darwin-native` helper path added another useful macOS data point:
the same helper split used on Linux can own a real Darwin `utun` fd and run the
existing macOS hook scripts from the privileged side. The elevated test lane
for that path is intentionally narrow, but it exposed several design rules that
also apply to the Swift app/helper direction.

First, `utun` names are realized by the kernel. A caller can request a symbolic
or desired name, but the opened device may come back as `utun4`, `utun5`, or
another concrete interface. The helper must return that actual name to the
unprivileged runtime, and all later apply/remove operations must use the actual
name rather than the requested one. Teardown and route-state lookup have the
same rule.

Second, helper-owned network apply must run only after `OPEN_TUN` has completed
and the actual interface name is known. Scheduling `OPEN_TUN` and
`APPLY_NETWORK` as independent client requests is fragile on macOS because the
apply step may otherwise target a name that never existed. The Swift/XPC helper
contract should preserve this ordering explicitly:

- open `utun`
- return actual interface name and MTU
- apply addresses/routes/DNS using that actual interface
- publish a runtime snapshot that includes `opened`, `network_applied`, hook
  action, hook argv, and last failure details

Third, route env vars need "unset" and "explicit empty" semantics. For example,
the Python elevated lane intentionally passes an empty excluded-route list to
avoid touching loopback or default DNS in a non-invasive test. Shell hooks must
therefore use parameter expansion that distinguishes unset from empty
(`${VAR-default}` rather than `${VAR:-default}`) when an empty value is a real
operator/test intent.

Fourth, loopback integrity is a hard preflight for macOS helper tests and app
startup diagnostics. A bad route such as:

- `route -n get 127.0.0.1` returning gateway `192.168.179.2` on `en0`

means the machine's loopback route has been corrupted, often by a stale or
over-broad excluded route. The healthy state is:

- `route -n get 127.0.0.1` returns interface `lo0`

The macOS elevated lane now repairs stale ObstacleBridge-created loopback route
damage before starting, and skips if loopback cannot be restored. The app
should use the same diagnostic shape when WebAdmin or localhost helper IPC
appears unreachable: check loopback routing before assuming Admin Web failed.
The route hooks must also treat a loopback overlay peer, such as
`127.0.0.1`, as already underlay-protected; adding a more-specific
`127.0.0.1/32` peer-preservation route through `en0` breaks local Admin Web,
helper IPC, and loopback test probes.

Finally, non-invasive elevated tests should avoid default-route and DNS changes
unless that behavior is the subject of the test. A narrow helper launch test can
prove privileged `utun` creation, hook invocation, Admin Web runtime reporting,
and teardown cleanup with small host routes and empty DNS. Full-tunnel route and
DNS behavior should live in separate, explicit tests because failures there can
affect the developer machine's own reachability.

## Swift Packet Adapter Behavior Versus Python

One subtle but important difference has now been observed between the Python
TUN clients and the Swift packet-adapter path used by the macOS app.

Python on Linux and Python on macOS use host-style TUN adapters:

- the operating system routes packets onto the local TUN interface
- the packet source identity seen by ObstacleBridge already aligns with the
  tunnel-owned address space often enough that shared-TUN ownership checks do
  not require additional packet rewriting in the mux layer

The Swift macOS app uses a different path:

- a native packet adapter reads packets from the local `utun`
- those packets can still carry the machine's original local source identity
  when they first enter the shared Swift runtime
- shared-TUN ownership on the server is stricter and expects the peer to source
  packets from its assigned tunnel-owned address, such as `192.168.106.3` or
  `fd20:106::3`

That means the Swift path needs one explicit normalization step that Python did
not need in practice:

- before ChannelMux frames a local TUN packet for shared-TUN forwarding, the
  Swift runtime rewrites the packet source to the configured tunnel-owned IPv4
  or IPv6 address and updates the affected checksums

This is not treated as a protocol change. It is a parity fix that makes the
Swift packet-adapter path present the same effective tunnel identity that the
Python host-TUN path already provides implicitly.

Design consequence:

- shared-TUN server ownership rules stay strict
- Python behavior stays unchanged
- Swift packet adapters normalize local source identity before shared-TUN mux
  forwarding

The same shared Swift runtime is used by both the macOS app and the iOS packet
tunnel implementation, so this source-normalization behavior is intentionally
shared across both Apple-platform clients.

That is the standard the Swift app should meet before we call the macOS app TUN
path complete.

## Current known gap

At the time of writing, the Swift app can still end up in the following state:

- overlay connected
- local `utun` created and addressed
- split full-tunnel routes installed
- the overlay peer route incorrectly cloned onto `utun`
- WebSocket transport drops and the app remains in "connecting"

This should now be interpreted as:

- config is present
- ChannelMux/service wiring is present
- privilege-backed local TUN realization is present
- route preservation for the overlay peer remains the fragile part
- helper/app localhost diagnostics must also treat corrupted loopback routing
  as a first-class failure mode, because WebAdmin can appear unreachable even
  when the process is alive if `127.0.0.1` no longer routes through `lo0`

That diagnosis is much better than the earlier uncertainty, because it gives a
narrow next step: capture and preserve the overlay peer underlay route before
the full-tunnel routes are installed, while keeping loopback routes owned by
the operating system rather than by ObstacleBridge hook exclusions.

## Further steps

1. Prove the bundled privileged host-runner path fully matches the working
   Python/macOS path:
   - real `utun` appears
   - routes are installed
   - underlay route is preserved
   - loopback still routes through `lo0`
   - traffic exits through the remote peer
   - admin state shows a real TUN channel
2. Introduce a dedicated privileged helper managed through `SMAppService`.
3. Define an XPC contract for:
   - create local TUN
   - report the actual kernel-assigned `utun` name
   - configure addressing and routes
   - preserve underlay route
   - teardown and cleanup
4. Wire the Swift host-runner TUN path to request that helper service instead
   of assuming unprivileged local TUN access.
5. Reevaluate whether a full macOS Network Extension remains necessary after
   the helper-backed design is working.

## Relationship to other design notes

This document should be read together with:

- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md)
- [IOSAPP_DESIGN.md](./IOSAPP_DESIGN.md)
- [QUIC_DESIGN.md](./QUIC_DESIGN.md)

`CHANNELMUX_DESIGN.md` explains the shared TUN and service semantics.
`IOSAPP_DESIGN.md` describes the iOS packet-tunnel direction. This macOS design
note exists because macOS currently sits in between:

- more native-app freedom than iOS
- but still a real privilege boundary for raw TUN and route control

That middle ground is exactly why the privileged-helper step is the natural next
move.
