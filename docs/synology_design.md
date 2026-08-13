# Synology Deployment Design

## Purpose

This document records the intended Synology deployment path for
ObstacleBridge.

The current working approach is deliberately simple:

- copy the Python sources to the Synology host
- connect through SSH
- start ObstacleBridge manually from the shell

That is good enough for development validation, but it is not the desired
operator experience. The target state is a Synology `.spk` package that can be
installed through DSM and that starts automatically again after a NAS reboot.

## Current working baseline

The currently proven shape is:

1. prepare the ObstacleBridge Python sources on another machine
2. copy them to the Synology system
3. install SynoCommunity `python3.14`
4. log in over SSH
5. run `sudo python3.14 -m pip install -e .`
6. run `sudo python3.14 -m obstacle_bridge`

This proves an important product point:

- ObstacleBridge does not require a native Synology-specific application
  binary in order to function
- the primary payload is the Python runtime plus project assets and
  configuration

In other words, Synology packaging is mainly an installation and lifecycle
problem, not a native-runtime porting problem.

## Current repository state

The repository now includes an initial phase-2 SPK wrapper scaffold under:

- `synology/`
- `scripts/build_synology_spk.py`

This first delivered slice can:

- assemble a DSM-style `.spk`
- package the Python runtime sources, WebAdmin assets, and helper scripts
- provide DSM service lifecycle scripts
- seed a persistent config file under the Synology package var directory
- start the runtime again after DSM service start or reboot
- prepare a dedicated helper interpreter copy under the Synology package var
  directory and point helper-mode launches at that copy

This is intentionally a first wrapper, not the finished Synology product.

Current limitations of the delivered wrapper:

- it assumes SynoCommunity `python3.14` is available on the NAS
- it bootstraps Python dependencies at install time instead of shipping
  Synology-architecture-specific wheels inside the current `noarch` package
- it currently prototypes the privileged-helper lane through a dedicated helper
  Python interpreter with best-effort `CAP_NET_ADMIN`, not yet through a
  narrow native Synology helper binary

## Target state

The desired Synology operator workflow is:

1. build an `.spk` package from the ObstacleBridge project
2. install that package through Synology DSM
3. let DSM place files into the package location
4. let DSM register and control service startup
5. have ObstacleBridge start automatically after NAS reboot
6. keep configuration and logs in stable Synology-appropriate locations

The package should behave as a normal DSM-managed service rather than as a
manually launched SSH session.

## Non-goal

The Synology package does not need to introduce a native compiled application
just for the sake of packaging.

The important distinction is:

- some Synology packaging examples focus on compiling and shipping a native
  executable
- ObstacleBridge instead needs the SPK framework for file layout, install
  hooks, service registration, and restart/autostart behavior

The runtime payload itself should stay Python-first.

## Packaging model

The recommended package model is:

- package the ObstacleBridge Python sources
- package the required static assets such as WebAdmin files and scripts
- bootstrap the required Python dependencies in a DSM-compatible way
- provide DSM service scripts that start and stop the runtime
- persist runtime configuration outside the ephemeral install flow

That means the SPK should act as a thin service wrapper around the existing
runtime instead of introducing a second implementation path.

## Expected package responsibilities

The Synology package should own the following concerns:

- install files into a predictable package directory
- provide a service start command
- provide a service stop command
- arrange autostart on NAS reboot
- define where configuration is stored
- define where logs are written
- define how package upgrades preserve operator configuration

ObstacleBridge itself should continue to own:

- transport behavior
- secure-link behavior
- ChannelMux and shared TUN behavior
- admin web behavior
- runtime config interpretation

This keeps Synology-specific logic at the packaging boundary.

## Runtime assumptions

The general project requirement keeps the Python runtime broadly compatible, but
the current proven Synology operator path is now pinned to SynoCommunity
Python 3.14.

For Synology deployment, we should continue to assume:

- SynoCommunity `python3.14` is the supported DSM interpreter for this path
- not every NAS should be expected to provide a development toolchain
- package installation should minimize manual post-install shell work

That leads to a preference for a deterministic dependency-install strategy
around the Synology-provided Python runtime, rather than assuming ad hoc manual
package installation after deployment.

## Privilege boundary on Synology

The current manual Synology workflow is an important clue about the real
privilege model:

- when starting from SSH, the working path uses `sudo`
- that means the tested runtime shape is not merely "Python on DSM"
- it is "Python on DSM with elevated privilege for the parts that need it"

This matters because a normal DSM package service is not automatically the same
thing as an interactive `sudo` shell.

The current first-pass SPK wrapper runs as the Synology package user. That is
good enough for:

- package-managed file layout
- DSM start/stop/autostart
- WebAdmin lifecycle
- non-privileged runtime paths

It is not yet a proven solution for runtime responsibilities that require
elevated capability, especially:

- local TUN creation/ownership
- route changes
- firewall/NAT changes
- other host-network mutations that currently work from the SSH `sudo` path

### What the SPK cannot do yet

The current wrapper should not be described as "the SPK can just do what the
SSH + sudo launch does."

Today it cannot assume that DSM package startup will:

- prompt for a password like interactive `sudo`
- inherit root privilege merely because the package is installed
- safely run the whole ObstacleBridge Python process as root by default

So if ObstacleBridge needs elevated operations on Synology, the package must
gain an explicit privilege design rather than relying on the current
package-user service shape.

### Likely Synology-compatible approaches

There are two realistic directions:

1. run the whole package service with elevated privilege
2. keep the main package service unprivileged and introduce a narrow
   privileged helper

The second model is the better architectural match for ObstacleBridge.

Why:

- it mirrors the direction already taken on macOS, Linux helper mode, and
  Windows helper mode
- it keeps privilege concentrated in the small subset that actually needs it
- it avoids turning the whole Python runtime and WebAdmin surface into a
  permanently privileged process

### Recommended direction

For Synology, the recommended long-term model is:

- DSM starts the normal ObstacleBridge package service
- that normal service runs as the package user
- when privileged TUN or host-network work is required, it talks to a
  dedicated privileged helper
- that helper owns only the privileged operations such as TUN open/configure,
  route programming, and firewall changes

In other words, the Synology end state should look much closer to the existing
helper-oriented privilege split than to "run the whole bridge as root forever."

### Current project status

The repository does not yet implement that Synology-specific privileged helper
path.

So the current status is:

- manual SSH validation demonstrates that elevated execution is sometimes
  required
- the SPK wrapper currently solves packaging and DSM lifecycle only
- privileged Synology runtime support remains a follow-up design and
  implementation task

This is the main reason the current SPK wrapper should be understood as a
first deployment scaffold, not the final productive Synology packaging story.

## DSM-specific privileged helper options

The Synology DSM 7 privilege model adds an important platform constraint for
ObstacleBridge:

- packages are expected to run with lowered privilege
- `run-as system` is no longer the normal package model
- privileged work is expected to use DSM-approved mechanisms such as resource
  workers where those mechanisms exist

For ObstacleBridge, that means the question is not simply "how do we start the
SPK at boot?" The harder question is "how do we let the SPK perform TUN and
host-network operations that currently work through SSH + `sudo`?"

The following options are the realistic design space for a DSM-specific
privileged helper solution.

### Option 1: official DSM resource workers where available

DSM provides official resource-acquisition mechanisms for certain kinds of
system integration work.

This is a good fit for things such as:

- package lifecycle integration
- reverse-proxy or nginx-facing configuration
- some port and service registration cases
- container-manager or Docker-oriented package integration

For ObstacleBridge, this is useful but incomplete.

Why:

- these workers are good for DSM-managed integration concerns
- they do not appear to provide a general-purpose "run arbitrary
  `CAP_NET_ADMIN` helper for TUN and route manipulation" solution

Conclusion:

- use resource workers where they naturally fit
- do not expect them alone to solve ObstacleBridge local TUN privilege needs

### Option 2: package-user service plus narrow native helper with Linux capabilities

This is the best architectural fit for ObstacleBridge.

Model:

- DSM starts the main ObstacleBridge package service as the package user
- the main service remains the Python-first runtime and WebAdmin owner
- when privileged operations are required, the runtime talks over a local
  authenticated socket to a tiny helper binary
- that helper binary carries only the minimum Linux capabilities needed, most
  likely centered on `CAP_NET_ADMIN`

Why this matches the project well:

- it mirrors the helper split already used or planned on Linux, macOS, and
  Windows
- it keeps the privileged surface much smaller than the full runtime
- it avoids running the whole Python stack permanently with elevated privilege
- it preserves the current ObstacleBridge architecture rather than replacing it

Likely privileged responsibilities for that helper:

- local TUN creation and ownership
- interface address programming
- route changes
- firewall or NAT changes
- any other host-network mutation currently proven only via SSH + `sudo`

Main validation questions:

- whether DSM allows the helper binary to retain and use the needed file
  capabilities after package install
- whether `/dev/net/tun` access is available under that capability model
- whether DSM security policy or AppArmor blocks some of the needed network
  operations even when Linux capabilities are present

Conclusion:

- this should be the first real privileged-helper direction to prototype on a
  NAS

### Option 3: whole package or service running as root-like privileged code

This is the most direct mental model from the SSH workflow, but it is the
least attractive product direction.

Why it is unattractive:

- DSM 7 intentionally moved away from broad package privilege
- whole-runtime root execution gives far more privilege to the Python runtime,
  WebAdmin surface, and package code than ObstacleBridge should need
- Synology documents special handling for root-privilege package installation,
  including signing or development-token style exceptions, which is not a
  normal third-party package story

This may still be useful for:

- lab testing
- development appliances
- strictly controlled internal deployments

Conclusion:

- do not treat this as the preferred production design
- keep it only as an exceptional or temporary path

### Option 4: SPK control plane plus separately installed root daemon

This is the fallback if DSM packaging policy prevents capability-bearing helper
delivery inside the normal SPK path.

Model:

- the SPK installs and runs the normal unprivileged package service
- a separate root-owned daemon is installed or enabled outside the normal SPK
  privilege model
- the SPK talks to that daemon locally for privileged work

Benefits:

- still allows a narrow privileged helper model
- can work even if DSM package policy is stricter than expected

Costs:

- worse operator experience
- less self-contained than a normal SPK
- more fragile across DSM updates and appliance migrations
- less elegant than a package-contained helper design

Conclusion:

- keep this as the fallback if the preferred capability-bearing helper model is
  blocked in practice

## Recommended DSM privilege path

The recommended order for ObstacleBridge is:

1. use official DSM resource workers where they fit naturally
2. prototype a narrow native privileged helper binary that the SPK-owned Python
   runtime can call locally
3. validate that helper on real DSM hardware for `/dev/net/tun`, route, and
   firewall behavior
4. fall back to a separately installed root daemon only if the DSM package path
   blocks the helper-capability model
5. avoid whole-runtime root execution except for development or tightly
   controlled internal deployments

This keeps the Synology design aligned with the existing ObstacleBridge helper
direction:

- normal runtime stays unprivileged
- privileged code is isolated
- the helper owns only TUN and host-network responsibilities
- the SPK remains the installer, service manager, and operator-facing control
  surface

## Likely SPK contents

The first practical `.spk` should likely include:

- the `obstacle_bridge` Python package
- entrypoint/start scripts
- WebAdmin assets
- helper scripts used by the runtime
- package metadata required by Synology DSM
- DSM service-control scripts
- a default configuration template or first-run config location

Depending on what DSM expects in the target environment, it may also need:

- vendored Python wheels
- a packaged virtual environment
- an install-time dependency bootstrap step

The exact dependency strategy should be chosen based on what is most stable on
the target DSM generation.

## Service lifecycle expectation

The intended DSM lifecycle is:

1. install package
2. create or discover persistent config location
3. start service
4. expose WebAdmin and runtime logs
5. stop cleanly through DSM service control
6. restart automatically after reboot
7. preserve config and logs across package upgrades when appropriate

This service model should replace the current manual SSH session lifecycle.

## Configuration model

A Synology package should avoid baking operator-specific runtime configuration
directly into the immutable package payload.

The preferred split is:

- package payload contains the runtime and defaults
- persistent storage contains the operator-edited config

That makes upgrades safer and avoids losing configuration when a new `.spk` is
installed.

At minimum, the design should define:

- where the active config file lives
- how the package seeds that file on first install
- what happens when the config is missing or invalid
- how logs and diagnostics are exposed for support

## Migration path

The recommended delivery path is incremental.

### Phase 1: manual SSH deployment

Current known-working state:

- copy source tree
- start manually over SSH

Purpose:

- prove runtime behavior on Synology
- validate Python and dependency compatibility

### Phase 2: SPK wrapper around existing runtime

Delivered first package milestone:

- create an `.spk` that installs the existing Python-first runtime
- use DSM service scripts for start/stop/autostart
- keep the runtime architecture unchanged
- fail early with explicit messages when `python3` or required Python packages
  are missing

Purpose:

- improve installation and reboot resilience
- reduce manual operator steps

Remaining work inside phase 2:

- decide whether dependency bundling should use vendored wheels, a packaged
  virtual environment, or an install-time bootstrap path
- validate the package on a real DSM system
- confirm whether package-user execution is sufficient or whether some runtime
  modes require an explicit elevated helper design on Synology
- define the Synology privilege boundary for TUN and host-network operations,
  most likely through a dedicated privileged helper rather than whole-runtime
  root execution

### Phase 3: hardening

Follow-up package work:

- dependency bundling improvements
- upgrade-safe config migration
- clearer log collection and diagnostics
- possibly tighter DSM UI integration if it adds real value

Purpose:

- make the package maintainable for repeated deployment

## Build guidance

There is an external example for building Synology packages:

- `/mnt/project/how_to_build_wsclient_for_synology.txt`

That example is useful as process guidance for creating an SPK, but
ObstacleBridge should not copy it mechanically if that example assumes a native
application build. The useful part for ObstacleBridge is the Synology package
framework itself:

- package metadata
- build layout
- install scripts
- service scripts
- DSM packaging conventions

The ObstacleBridge-specific adaptation is to keep the payload Python-based.

## Open design questions

The first SPK implementation should answer these questions explicitly:

- will the package vendor dependencies or create them on install
- what exact DSM/Python combinations must be supported
- where should persistent config and logs live on Synology
- how should the package expose or document the WebAdmin port
- what should the service do when the config is invalid at boot
- how should package upgrades handle changed defaults

## Recommended next implementation slice

The next practical step is not a native app build. It is:

1. define the minimal Synology package directory layout
2. add DSM service start/stop scripts that launch the existing Python runtime
3. define the persistent config path
4. build a first installable `.spk`
5. verify reboot autostart and config persistence on a real NAS

That would establish the first real DSM-managed ObstacleBridge deployment path
without disturbing the existing Python runtime architecture.
