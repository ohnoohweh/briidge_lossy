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

## Important limitation

The SPK now handles the Python dependency bootstrap, but it does not yet
replace the proven `sudo python3.14 -m obstacle_bridge` path for full
privileged operation.

In particular, the current package shape still does not solve the full DSM
privilege boundary for:

- local TUN creation
- route changes
- firewall or NAT changes
- other host-network mutations that are known to work from an SSH `sudo`
  session

So the current SPK should still be treated as a packaging and service-lifecycle
scaffold, not the final privileged Synology deployment model.

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
