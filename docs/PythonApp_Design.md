# Python Application Deployment Design

## Purpose

This document defines how the Python ObstacleBridge application is identified,
installed, started, and upgraded outside a developer Git checkout. It covers
the Python runtime only; the native Linux Swift archive and the macOS/iOS
products have their own packaging contracts.

The deployment boundary has two goals:

- an operator can reproduce which source revision is running;
- the Python runtime does not require Git on a deployed host.

## Build identity contract

`/api/meta` and `/api/status` expose build identity. The Python runtime uses
this order without a deployment-mode switch:

1. a usable Git checkout is authoritative and supplies the live revision plus
   tracked/untracked working-tree state;
2. without Git, the runtime consumes `src/obstacle_bridge/_generated/build_info_generated.py`;
3. if neither is available, identity is unavailable rather than guessed.

The generated stamp records the first eight Git commit characters, whether the
build input was dirty, an optional diff digest, and its UTC creation time. It
is build input, not tracked source. Its producer is
`scripts/write_build_info.py`.

A deployment artifact must contain a stamp created from the exact source that
it delivers. Copying an old ignored stamp is invalid because it can describe a
different release. The SHA-256 file attached to a release asset verifies the
download, while the embedded stamp identifies the source used to build it;
both are required for an auditable installation.

## Common runtime layout

Each deployment method separates immutable program files from mutable operator
state:

| Concern | Owner | Rule |
| --- | --- | --- |
| Application code, WebAdmin assets, generated build stamp | deployment artifact | Replace atomically on upgrade; do not edit in place. |
| Configuration, certificates, PSKs, logs, runtime-health record | operator/service owner | Keep outside the extracted application directory and back up according to the deployment's security policy. |
| Python dependencies | virtual environment or package wrapper | Pin/install per deployment revision; do not rely on a developer's global environment. |
| Service lifecycle | systemd, DSM, or explicit foreground shell | Stop the old process before replacing its executable source tree; preserve the configured runtime user and required privilege boundary. |

`python -m obstacle_bridge` is the normal Python entrypoint. TUN/helper mode
may require additional OS privileges; deployment must grant those narrowly and
does not make the entire application root-owned by default.

## Deployment scenarios

| Scenario | Git available at runtime | Identity source | Status |
| --- | --- | --- | --- |
| Developer clone | yes | live Git | supported development workflow |
| `scripts/update_VPS.sh` from a clone | source side only | freshly generated stamp | supported VPS update workflow |
| Repository-page **Download ZIP** | no | none in the GitHub-generated archive | runnable source, but not identity-preserving |
| Release `ObstacleBridge-python*.zip` asset | no | generated stamp packaged with asset | supported portable Python artifact |
| Release **Source code** ZIP/TAR.GZ | no | none in GitHub-generated archive | source inspection/bootstrap only, not identity-preserving |
| Synology DSM SPK | no | stamp inside SPK payload | supported DSM package workflow within documented privilege limits |
| Local wheel/sdist or container image | normally no | artifact stamp/label | future distribution form; must meet the same contract |

### Developer clone

The developer clones the repository and runs from that working tree. Git is
present, so the WebAdmin reports the checked-out commit and any local changes.
A stale generated deployment stamp must never override this view. This is the
only scenario where a dirty state is expected during normal operation.

### VPS update from a clone

`scripts/update_VPS.sh` runs on the source machine, executes
`scripts/write_build_info.py`, then rsyncs the source tree to the VPS. The VPS
does not need `.git`; it reads the copied stamp. The updater should be invoked
from a clean, reviewed checkout for a production release. If it is deliberately
run from a dirty checkout, the stamp must retain that fact.

The remote service should use a stable config path outside the synchronised
tree. A restart should be coordinated with the service manager or the
application's controlled restart path so source replacement and process
lifecycle do not overlap unpredictably.

### Repository-page Download ZIP

GitHub's **Download ZIP** produces a source archive, not a project-built
release artifact. It contains no `.git` directory and does not include ignored
generated files, including the build stamp. It can be used for source review,
experimentation, or a manually stamped deployment:

1. verify the archive against the intended commit/tag in GitHub;
2. extract it into a staging directory;
3. from a separate trusted checkout at that exact revision, run
   `scripts/write_build_info.py --python-target` against the extracted
   archive's `src/obstacle_bridge/_generated/build_info_generated.py` path;
4. otherwise leave identity unavailable rather than claiming a revision;
5. create a virtual environment, install dependencies, configure, and start.

It is not an identity-preserving release path today. An operator who needs a
reproducible production deployment should use the release Python artifact or a
VPS update from a checked-out revision.

### Release `ObstacleBridge-python*.zip` artifact

The named Python release asset is the portable Python delivery format. The
release workflow must create a staging tree, generate its build stamp from the
release target, archive that staged tree, and publish both ZIP and SHA-256
sidecar. It must not use a bare `git archive` as the final asset, because that
archive omits ignored generated files.

Installation is:

1. download the ZIP and matching `.sha256` from the same release;
2. verify the SHA-256 before extraction;
3. extract into a versioned immutable directory;
4. create or update a dedicated virtual environment and install dependencies;
5. point the service at external configuration/state; and
6. start or restart the service.

The publishing workflow stages tracked source, writes the stamp directly into
that staged tree, creates the ZIP from the staged tree, and probes the
extracted artifact with Git unavailable before publishing it.

### Release Source Code ZIP/TAR.GZ

GitHub automatically provides **Source code (zip)** and **Source code
(tar.gz)** entries for a release. They are convenient reference snapshots and
should not be confused with an application artifact. They do not carry the
generated Python stamp or package-managed dependencies.

Use them only for inspection, local development, or as input to a separately
controlled build process that records the selected release tag/commit and
generates a new stamp. The release's named Python ZIP is the appropriate
download once its staging requirement above is implemented.

### Synology DSM SPK

The SPK is a DSM-managed delivery format. `scripts/build_synology_spk.py`
packages Python source, WebAdmin assets, scripts, and DSM lifecycle files;
DSM owns installation, upgrade, and restart. Persistent configuration and logs
belong under DSM package state rather than the replaceable payload.

The SPK builder writes the same build stamp into its temporary payload before
the payload archive is assembled, and the release workflow probes the extracted
payload with Git unavailable. The package remains Python-first and depends on
SynoCommunity `python3.14`; its current helper handoff is an experimental
package-user privilege boundary, not a root-owned TUN appliance. See
[synology_design.md](synology_design.md) for DSM layout and lifecycle detail.

## Additional delivery forms

These are valid future deployment options only when they preserve the build
identity contract and common runtime layout:

- **Wheel/sdist:** publish a versioned Python package with package data for
  WebAdmin assets and generated build metadata. A wheel should be preferred for
  repeatable production installation; an sdist remains a build input.
- **Container image:** include the build stamp as image content, expose the
  immutable image digest, mount configuration/state separately, and run as a
  non-root user unless a narrowly scoped helper mechanism is required.
- **OS package:** a Debian/RPM-style package may own a system user and systemd
  unit, but must keep `/etc` configuration and `/var/lib` state across upgrade
  and package the same generated stamp.
- **Air-gapped tarball:** create it from the same stamped staging tree as the
  release ZIP and ship its checksum through the offline approval channel.

## Release pipeline responsibilities

The release producer, not the deployed Python process, knows the selected
commit. Every non-Git artifact therefore follows this sequence:

1. check out the exact release target;
2. verify whether the build input is clean;
3. run `scripts/write_build_info.py` into a staging tree;
4. package that staging tree without dropping `_generated` metadata;
5. emit a SHA-256 sidecar and publish both under the release target; and
6. test the extracted artifact with Git unavailable and assert that WebAdmin
   reports the embedded commit.

The final extracted-artifact probe is the release acceptance criterion. It
prevents a source archive, an outdated stamp, or an archive exclusion rule from
silently changing the identity shown to operators.

## Current limitations and next work

The following are delivered behaviors, not limitations:

- The VPS updater refreshes the generated stamp before copying source.
- Source checkouts prefer live Git identity over a generated stamp.

The remaining limitation is intentional: generic GitHub download/source-code
archives have no stamp, so they cannot report an auditable runtime identity
without an external trusted build step. The named Python preview ZIP and SPK
use a staged stamp plus an extracted-artifact probe.

- A release artifact should eventually include a machine-readable manifest
  containing artifact name, commit, timestamp, dirty state, and SHA-256, in
  addition to the runtime stamp.
