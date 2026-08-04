# Synology SPK Wrapper

This directory contains the first phase-2 Synology DSM package wrapper for
ObstacleBridge.

What this slice does:

- builds a `noarch` `.spk` around the existing Python runtime
- installs the project sources, WebAdmin assets, and helper scripts
- seeds a persistent config file under the Synology package var directory
- starts and stops ObstacleBridge through DSM service control
- requests autostart through the normal DSM package lifecycle

What this slice intentionally does not do yet:

- vendor Python dependencies into the package
- guarantee every DSM/Python combination out of the box without a host
  `python3` runtime and the required packages already installed

What this slice now prototypes:

- a package-user main service plus a dedicated helper Python under
  `/var/packages/obstaclebridge/var/helper-venv/`
- best-effort `CAP_NET_ADMIN` preparation on that helper Python through
  `setcap`
- runtime export of `OBSTACLEBRIDGE_TUN_HELPER_EXECUTABLE` so the Linux helper
  subprocess can launch through that dedicated helper interpreter instead of
  the main service interpreter

## Privilege note

The currently proven manual Synology runtime path is started from SSH with
`sudo`. That means some ObstacleBridge modes need elevated privilege on DSM,
especially for TUN and host-network operations.

This first SPK wrapper does not solve that privilege boundary yet. It currently
models:

- DSM package installation
- DSM service lifecycle
- package-user runtime startup

It does not yet model:

- interactive `sudo`-style privilege escalation
- whole-runtime root execution as the default package shape
- a narrow native Synology helper binary distinct from the current helper
  interpreter approach

So the current SPK should be treated as a packaging/autostart scaffold, not as
the final privileged Synology deployment model for full TUN-capable operation.

## Build

```bash
python3 scripts/build_synology_spk.py
```

By default the resulting package is written to:

```text
dist/synology/
```

Use `--keep-staging` if you want the unpacked SPK staging tree for inspection.

## Runtime layout assumptions

The package service uses these locations on the NAS:

- package target: `/var/packages/obstaclebridge/target`
- persistent config: `/var/packages/obstaclebridge/var/ObstacleBridge.cfg`
- runtime logs: `/var/packages/obstaclebridge/var/log/`
- pid file: `/var/packages/obstaclebridge/var/run/obstaclebridge.pid`

## Current operator expectations

This first wrapper assumes:

- DSM 7.x package installation
- a usable `python3` executable on the NAS
- the Python runtime dependencies `aioquic`, `cryptography`, and `websockets`
  are already installed for that interpreter
- `python3 -m venv --system-site-packages --copies` is available so package
  install can prepare a dedicated helper interpreter copy
- `setcap` is available if capability-based helper startup should avoid `sudo`

If those prerequisites are missing, install or startup will fail with an
explicit message in the Synology package logs.
