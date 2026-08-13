# Synology SPK Wrapper

This directory contains the Synology DSM package wrapper for ObstacleBridge.

## Proven manual install path

The currently proven Synology runtime flow is:

1. Install SynoCommunity `python3.14` on the NAS.
2. Copy or clone this repository onto the NAS.
3. Log in over SSH.
4. Run:

```bash
sudo python3.14 -m pip install -e .
sudo python3.14 -m obstacle_bridge
```

That path is still the reference operator workflow for first validation because
it matches the privilege level some ObstacleBridge modes need on DSM.

## What the SPK does

- builds a `noarch` `.spk` around the existing Python runtime sources
- installs the project sources, WebAdmin assets, and helper scripts
- seeds a persistent config file under the package var directory
- declares a Synology package dependency on SynoCommunity `python314`
- bootstraps Python package dependencies into `/var/packages/obstaclebridge/var/python-packages`
- starts and stops ObstacleBridge through DSM service control
- requests autostart through the normal DSM package lifecycle

## Current elevated-execution PoC

The package now includes the first runtime handoff needed to reuse the existing
Python TUN helper, while remaining installable on DSM 7.x without Synology
signing.

Current shape:

- the package default remains `run-as: package`
- `prestart` still invokes
  `/var/packages/obstaclebridge/target/bin/synology_elevated_probe.sh`
- when helper mode is enabled, `prestart` also prepares helper launch metadata
  and starts the existing Python helper server as the package user
- `start` exports
  `OBSTACLEBRIDGE_PRESTARTED_TUN_HELPER_CONFIG=/var/packages/obstaclebridge/var/run/tun-helper-attach.json`
  so the package-user bridge runtime can attach to that helper
- the probe writes:
  - `/var/packages/obstaclebridge/var/log/elevated-probe.log`
  - `/var/packages/obstaclebridge/var/elevated-probe.json`

This PoC proves two things:

- the Python runtime can consume a package-written helper handoff instead of
  trying interactive `sudo`
- the package can prestart a helper-managed control socket before the bridge
  process attaches

Expected validation after install/start:

```bash
sudo cat /var/packages/obstaclebridge/var/elevated-probe.json
sudo tail -n 50 /var/packages/obstaclebridge/var/log/elevated-probe.log
```

The successful PoC signal is:

- helper handoff files appear under `/var/packages/obstaclebridge/var/run/`
- the package `start-stop-status` script exports
  `OBSTACLEBRIDGE_PRESTARTED_TUN_HELPER_CONFIG` when helper mode is enabled

On DSM 7.2.2, a package that explicitly requests root privilege is blocked from
installation unless it is Synology-signed or covered by Synology's developer
token program. For that reason, the current SPK intentionally keeps package
privilege at the normal package-user level.

## Important limitation

The SPK now handles the Python dependency bootstrap, but it does not yet
replace the proven `sudo python3.14 -m obstacle_bridge` path for full
privileged operation.

In particular, the current package shape still does not fully prove the DSM
privilege boundary for:

- local TUN creation
- route changes
- firewall or NAT changes
- other host-network mutations that are known to work from an SSH `sudo`
  session

So the current SPK should still be treated as a packaging and service-lifecycle
scaffold plus helper-handoff prototype, not the final privileged Synology
deployment model.

## Build

```bash
python3 scripts/build_synology_spk.py
```

By default the resulting package is written to `dist/synology/`.

Use `--keep-staging` if you want the unpacked SPK staging tree for inspection.

## Package runtime layout

- package target: `/var/packages/obstaclebridge/target`
- persistent config: `/var/packages/obstaclebridge/var/ObstacleBridge.cfg`
- packaged Python dependencies: `/var/packages/obstaclebridge/var/python-packages/`
- helper interpreter: `/var/packages/obstaclebridge/var/helper-venv/bin/python3`
- runtime logs: `/var/packages/obstaclebridge/var/log/`
- pid file: `/var/packages/obstaclebridge/var/run/obstaclebridge.pid`

## Current operator expectations

- DSM 7.x
- SynoCommunity `python3.14` installed and available as `python3.14`
- working `pip` support for that interpreter
- network access during package install so `pip` can fetch `aioquic`,
  `cryptography`, and `websockets`
- `python3.14 -m venv --system-site-packages --copies` available so package
  install can prepare a dedicated helper interpreter copy
- `setcap` available if capability-based helper startup should avoid `sudo`

If any prerequisite is missing, install or startup fails with an explicit
message in the package logs.
