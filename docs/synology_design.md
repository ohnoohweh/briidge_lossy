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

## Learned packaging details

Real DSM installation attempts clarified an important SPK-format detail that is
easy to get wrong when building packages outside the Synology toolchain.

The working package shape is:

- outer `.spk`: plain POSIX tar archive
- one top-level `INFO`
- one top-level `package.tgz`
- lifecycle metadata files such as `scripts/preinst`,
  `scripts/postinst`, and `conf/privilege`
- inner `package.tgz`: the gzipped payload archive

Two builder mistakes were enough to make DSM reject the package up front with
`Invalid file format`:

- writing the outer `.spk` as `tar.gz` instead of plain tar
- adding duplicate archive members to either the outer SPK or `package.tgz`

In practice that means:

- only `package.tgz` should be gzip-compressed
- the outer SPK should not contain duplicate entries
- the payload should also avoid duplicate entries and should not include
  transient build artifacts such as `__pycache__` or `.pyc` files

This matters because DSM can reject the upload before package install scripts
run, which means the failure may not leave package-specific runtime logs.

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

The current observed operator flow is therefore slightly more concrete:

1. build the SPK
2. verify the SPK has the expected archive shape
3. install it through DSM
4. let `postinst` seed config and bootstrap Python dependencies
5. start or restart the package service from DSM
6. inspect package logs under `/var/packages/obstaclebridge/var/log/` when
   service startup fails

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

## Service-start diagnostics

When DSM reports `Failed to run package service`, the useful distinction is:

1. package-format rejection before install
2. install-time bootstrap failure
3. runtime service-start failure

The current repository has already seen both of the first two classes.

### 1. Format rejection before install

Typical symptom:

- DSM shows `Invalid file format`

In that case:

- `preinst` and `postinst` usually never run
- package runtime logs may not exist yet
- the right debugging target is the SPK archive structure itself

One additional learned DSM behavior from live testing:

- `Invalid file format` does not always mean the new SPK archive is malformed
- on August 13, 2026, DSM 7.2.2-72806 Update 9 rejected a rebuilt
  ObstacleBridge SPK during manual installation until the previously installed
  ObstacleBridge package was uninstalled first
- after uninstalling the prior package, the exact same rebuilt SPK file
  installed successfully

So the practical recovery sequence for this error is:

1. verify the SPK archive shape if the package is genuinely new
2. if this is a reinstall or upgrade attempt and DSM still reports `Invalid
   file format`, uninstall the previous ObstacleBridge package
3. retry installation of the same SPK before assuming the builder output is
   broken

This is important because the DSM error text can point at package format even
when the blocking condition is really the existing installed package state.

### 2. Install succeeds but `Run` fails

For the current wrapper, `Run` failures are most likely to come from one of
these checks in `synology/scripts/start-stop-status`:

- `python3.14` not found on PATH for the package runtime
- Python runtime dependencies missing from
  `/var/packages/obstaclebridge/var/python-packages`
- the runtime exits immediately after launch
- a permission/runtime mismatch on actions that still need privilege

### 3. Package-specific diagnostics to run

The current package layout gives a concrete inspection checklist:

```bash
sudo /var/packages/obstaclebridge/scripts/start-stop-status status
sudo ls -l /var/packages/obstaclebridge/target
sudo ls -l /var/packages/obstaclebridge/var
sudo ls -l /var/packages/obstaclebridge/var/python-packages
sudo ls -l /var/packages/obstaclebridge/var/helper-venv/bin
sudo cat /var/packages/obstaclebridge/var/ObstacleBridge.cfg
sudo tail -n 100 /var/packages/obstaclebridge/var/log/service.log
sudo tail -n 100 /var/packages/obstaclebridge/var/log/obstaclebridge.log
sudo which python3.14
python3.14 -V
```

To reproduce the package start logic more directly:

```bash
sudo /var/packages/obstaclebridge/scripts/start-stop-status start
echo $?
sudo /var/packages/obstaclebridge/scripts/start-stop-status status
```

The current service script starts:

```bash
python3.14 -c "from obstacle_bridge.bridge import main; main()" \
  --config /var/packages/obstaclebridge/var/ObstacleBridge.cfg \
  --log-file /var/packages/obstaclebridge/var/log/obstaclebridge.log
```

with:

- `PYTHONPATH=/var/packages/obstaclebridge/var/python-packages:/var/packages/obstaclebridge/target/src`
- optional `OBSTACLEBRIDGE_TUN_HELPER_EXECUTABLE=/var/packages/obstaclebridge/var/helper-venv/bin/python3`

So if DSM still reports only a generic failure, the package logs above are the
first place to look.

One additional learned detail from live DSM testing:

- launching the interactive `python -m obstacle_bridge.launcher` wrapper is not
  the right default for the DSM package service
- DSM already owns the package lifecycle and expects one long-running service
  process
- the direct bridge entrypoint is a better fit for the package script because
  it stays attached to the actual runtime process instead of adding a second
  supervisory layer intended for interactive CLI use

### 4. Most likely current failure causes after successful install

Given the present wrapper design, the most likely startup blockers are:

- dependency bootstrap did not complete successfully during `postinst`
- package-user runtime cannot find `python3.14`
- runtime starts but exits immediately due to missing Python modules
- runtime reaches privileged TUN or host-network code that still assumes the
  manual `sudo` launch path

That last point is expected for some modes. The current SPK should still be
treated as a DSM packaging and service-lifecycle scaffold, not as the final
privileged Synology runtime model.

## Troubleshooting: package does not autostart after installation or reboot

One important DSM behavior learned during live testing is that "the package can
be started" and "the package is enabled for DSM autostart" are not the same
thing.

The concrete observed failure mode was:

- ObstacleBridge ran correctly when started manually
- after NAS reboot, the package was stopped
- `synopkg` reported that the package was not turned on

The key checks are:

```bash
sudo synopkg status obstaclebridge
sudo synopkg is_onoff obstaclebridge
sudo tail -n 100 /var/packages/obstaclebridge/var/log/obstaclebridge.log
sudo tail -n 100 /var/packages/obstaclebridge/var/log/service.log
```

Interpretation:

- if `status` says `stop` and `is_onoff` says the package is not turned on,
  DSM does not currently consider the package enabled for autostart
- if the runtime log shows normal operation before reboot and no new lines
  after boot, the failure is usually not a runtime crash; it is that DSM never
  started the package
- if the log shows fresh startup lines after boot followed by an error, treat
  that as a normal service-start failure instead

### Recommended recovery flow

If the package was started through the raw lifecycle script during testing,
switch back to DSM package control:

```bash
sudo /var/packages/obstaclebridge/scripts/start-stop-status stop
sudo synopkg start obstaclebridge
sudo synopkg status obstaclebridge
sudo synopkg is_onoff obstaclebridge
```

Why this matters:

- `start-stop-status` is useful for debugging the package wrapper directly
- `synopkg start` is the DSM-managed path that should also mark the package as
  enabled in the normal package lifecycle
- validating both commands after install gives a much better signal about
  whether reboot autostart will work

### What to check after restart

After a NAS reboot, verify all three layers:

```bash
sudo synopkg status obstaclebridge
sudo synopkg is_onoff obstaclebridge
sudo netstat -apn | grep 18090
```

Healthy signs:

- `synopkg status obstaclebridge` reports the package is running
- `synopkg is_onoff obstaclebridge` no longer reports status `262`
- the expected listener such as `0.0.0.0:18090` is present

If those checks pass, DSM autostart is working and the deployed package change
has survived reboot in the intended service path.

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

### Option 2: package-user service plus existing helper protocol with a
Synology-specific elevated launch path

This is the best architectural fit for ObstacleBridge.

Model:

- DSM starts the main ObstacleBridge package service as the package user
- the main service remains the Python-first runtime and WebAdmin owner
- when privileged operations are required, the runtime talks over the existing
  local authenticated helper socket protocol
- the Synology-specific work is then not a new helper protocol, but a
  Synology-specific way to launch the helper side with elevated rights
- the first practical reuse target is the existing Python helper lane, not a
  brand-new Synology-only protocol

Why this matches the project well:

- it reuses the helper split already implemented across Linux, macOS, and
  Windows
- it keeps the privileged surface much smaller than the full runtime
- it avoids running the whole Python stack permanently with elevated privilege
- it preserves the current ObstacleBridge architecture rather than replacing it
- it lets Synology focus on the package privilege boundary and launch
  mechanics, which is the real missing piece today

Likely privileged responsibilities for that helper:

- local TUN creation and ownership
- interface address programming
- route changes
- firewall or NAT changes
- any other host-network mutation currently proven only via SSH + `sudo`

Main validation questions:

- whether the existing helper server can be launched by the Synology package in
  a root-owned `prestart` or equivalent lifecycle step and then handed off to
  the package-user runtime
- whether the existing helper socket and token flow work unchanged when the
  helper is started by the package rather than by interactive `sudo`
- whether `/dev/net/tun` access, route mutation, firewall mutation, and DNS
  mutation all work through that package-started elevated helper on real DSM
- whether DSM security policy or AppArmor blocks some of the needed network
  operations even when the helper itself is running with elevated rights

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
2. reuse the existing ObstacleBridge helper client/server protocol and Python
   helper implementation, but give Synology a package-owned elevated helper
   launch path
3. validate that package-launched helper on real DSM hardware for
   `/dev/net/tun`, route, firewall, and DNS behavior
4. only introduce a narrower native Synology helper binary later if the Python
   helper proves too broad, too fragile, or too hard to package safely
5. fall back to a separately installed root daemon only if the DSM package path
   blocks the helper-launch model entirely
6. avoid whole-runtime root execution except for development or tightly
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
- reuse the existing ObstacleBridge helper transport and startup contract
  through that package-owned elevated launch path instead of introducing a new
  Synology-only helper protocol

Current package-side helper PoC:

- `conf/privilege` keeps the package default at `run-as: package`
- `prestart` calls a narrow packaged probe script,
  `bin/synology_elevated_probe.sh`
- that probe records:
  - effective uid/gid and user/group
  - whether `/dev/net/tun` exists
  - whether `/dev/net/tun` is readable and writable
- the probe writes its evidence to:
  - `/var/packages/obstaclebridge/var/elevated-probe.json`
  - `/var/packages/obstaclebridge/var/log/elevated-probe.log`

The helper-handoff path is now proven on real DSM 7.2.2-72806 Update 9:

- `prestart` is invoked by DSM when `precheckstartstop="yes"` is present in
  `INFO`
- `prestart` can generate helper launch metadata under the package var
  directory
- helper mode creates:
  - `tun-helper-attach.json`
  - `tun-helper-launch.json`
  - `tun-helper.pid`
  - `tun-helper.sock`
- the package-user bridge runtime can attach through the existing helper client
  and complete the authenticated `HELLO` handshake
- after the package service wrapper was adjusted to use a stable runner script,
  DSM package start, running-state detection, on/off state, PID tracking, and
  the active listener state aligned successfully

However, DSM installation policy also became clear:

- on August 13, 2026, DSM 7.2.2 blocked installation of the package when the
  SPK explicitly requested root privilege through `conf/privilege`
- the install error said the package ran with root privileges and could
  compromise system security
- DSM offered no local override other than cancelling installation

That means the current installable SPK must remain package-user only unless
the package is Synology-signed or covered by a Synology developer token.

This helper-handoff proof has therefore moved one step further while staying
inside the installable DSM package policy.

Practical product consequence:

- the current installable SPK does not have a deployable local TUN path on
  Synology
- helper mode can still prestart and attach correctly, but it cannot own the
  privileged Linux TUN and host-network operations while running as the package
  user
- for now, Synology deployment should be understood as an ObstacleBridge
  transport endpoint and service wrapper rather than as a full local TUN
  appliance

That still leaves useful near-term deployment shapes:

- users may run WireGuard, OpenVPN, or another VPN component separately and
  carry that traffic over ObstacleBridge-managed ports or listeners
- users may also use ObstacleBridge on Synology purely for TCP/UDP service
  exposure, relay, or secure-link transport without local TUN ownership

In other words, the current package is still useful even though the
Synology-hosted TUN interface itself is effectively disabled in the
installable package configuration.

The Synology package scripts now also prepare a package-owned helper handoff:

- `prestart` can generate helper launch metadata under the package var
  directory
- `prestart` can launch the existing Python helper server as the package user
- `start` exports
  `OBSTACLEBRIDGE_PRESTARTED_TUN_HELPER_CONFIG=/var/packages/obstaclebridge/var/run/tun-helper-attach.json`
  for the package-user bridge runtime
- the Python `Runner` now understands that handoff file and attaches to the
  prestarted helper instead of trying to spawn its own helper subprocess
- the helper launch config now carries a longer authenticated-client idle
  timeout so the DSM `prestart` to service-start handoff does not race the
  helper watchdog

So the Python runtime now has the attach path needed for Synology-managed
helper startup, even though the current installable SPK does not cross the DSM
root-privilege boundary.

## Reusing the existing Python TUN helper on Synology

The repository already has the helper machinery needed for Synology:

- helper settings, protocol, client, and server scaffolding
- helper launch and token wiring in `Runner`
- helper-backed TUN open/read/write/apply/remove paths in `ChannelMux`
- helper status, diagnostics, and repair reporting in the runtime snapshots

So the missing Synology work is not "build a new helper."

It is:

1. keep the Synology-specific helper launch mode at the package/runtime
   boundary
2. launch the existing helper server from the root-run package hook or a
   root-started package-owned launcher
3. hand the resulting helper socket path and token to the package-user bridge
   process
4. run the bridge runtime in `tun_execution.mode=helper` with the existing
   helper protocol
5. validate that the existing helper-owned Linux network apply/remove behavior
   works unchanged on DSM

The package/runtime handoff shape is now:

- `prestart` remains narrow and package-owned
- it writes helper metadata into the package var directory
- it starts the existing Python helper server with that launch config
- `start` exports the attach-config path to the package-user runtime
- `Runner._start_tun_helper()` now consumes that attach config when present
- in attach mode, the runtime waits for the prestarted helper socket and then
  connects the existing `TunHelperClient`
- in attach mode, the runtime does not attempt to launch or stop the helper
  process itself

What still remains to prove on real DSM is the privileged backend behavior
rather than the handoff mechanics:

- whether the helper can actually open the DSM TUN device through the existing
  Linux helper backend
- whether route programming works unchanged on DSM
- whether firewall and DNS mutation work unchanged on DSM
- whether helper-owned cleanup is reliable across package stop, restart, and
  crash scenarios

At the moment, those checks are expected to fail in the installable SPK
configuration because the helper still runs as the package user.

That makes the current implementation boundary explicit:

- helper attach and helper lifecycle handoff are working
- privileged TUN open/apply/remove on Synology are not currently available in
  the installable SPK
- alternative deployments such as WireGuard or OpenVPN layered over
  ObstacleBridge remain viable and should be documented as the near-term
  Synology use case

Only after that reuse path is fully validated should the project decide
whether Synology really needs a narrower native helper binary. The existing
Python helper should still be treated as the first reuse target because it
already encapsulates the privileged TUN and host-network responsibilities that
Synology needs.

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
