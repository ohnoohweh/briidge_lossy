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
3. log in over SSH
4. start the Python runtime manually

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

This is intentionally a first wrapper, not the finished Synology product.

Current limitations of the delivered wrapper:

- it assumes a working `python3` interpreter already exists on the NAS
- it assumes Python dependencies are already installed for that interpreter
- it does not yet provide a Synology-native privileged helper for TUN-specific
  ownership or host-network operations

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
- package or bootstrap the required Python dependencies in a DSM-compatible
  way
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

The current project requirement already keeps runtime compatibility aligned
with Synology DSM Python 3.8 expectations.

For Synology deployment, we should continue to assume:

- Python 3.8 compatibility matters
- not every NAS should be expected to provide a development toolchain
- package installation should minimize manual post-install shell work

That leads to a preference for packaging a ready-to-run Python environment, or
at least a deterministic dependency-install strategy, rather than assuming
interactive setup after installation.

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
