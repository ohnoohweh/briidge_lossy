#!/usr/bin/env python3
"""Build a first-pass Synology DSM SPK for the Python ObstacleBridge runtime."""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import tarfile
import tempfile
from typing import List, Sequence


PACKAGE_ID = "obstaclebridge"
DISPLAY_NAME = "ObstacleBridge"
OS_MIN_VER = "7.0-40000"
DESCRIPTION = "ObstacleBridge Python runtime packaged for Synology DSM."
MAINTAINER = "ohnoohweh"
SUPPORT_URL = "https://github.com/ohnoohweh/briidge_lossy"


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def project_version(root: pathlib.Path) -> str:
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', pyproject)
    if not match:
        raise RuntimeError("could not determine project version from pyproject.toml")
    return match.group(1)


def spk_version(version: str) -> str:
    return f"{version}-1000"


def render_info(version: str) -> str:
    return "\n".join(
        [
            f'package="{PACKAGE_ID}"',
            f'version="{spk_version(version)}"',
            f'os_min_ver="{OS_MIN_VER}"',
            f'displayname="{DISPLAY_NAME}"',
            f'description="{DESCRIPTION}"',
            'arch="noarch"',
            f'maintainer="{MAINTAINER}"',
            f'support_url="{SUPPORT_URL}"',
            'thirdparty="yes"',
            'startable="yes"',
            'ctl_stop="yes"',
            'ctl_preuninst="yes"',
            'install_dep_packages="python314"',
            'silent_install="no"',
            'silent_upgrade="no"',
            'silent_uninstall="no"',
            "",
        ]
    )


def _reset_tree(path: pathlib.Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _copy_tree(src: pathlib.Path, dst: pathlib.Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _copy_file(src: pathlib.Path, dst: pathlib.Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _iter_archive_files(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if "__pycache__" in path.parts:
            continue
        if path.suffix == ".pyc":
            continue
        yield path


def stage_payload(root: pathlib.Path, payload_root: pathlib.Path) -> List[str]:
    staged: List[str] = []
    mappings = [
        ("src", "src"),
        ("admin_web", "admin_web"),
        ("scripts", "scripts"),
        ("synology/package", "."),
        ("README.md", "README.md"),
        ("pyproject.toml", "pyproject.toml"),
    ]
    for rel_src, rel_dst in mappings:
        src = root / rel_src
        dst = payload_root / rel_dst
        if src.is_dir():
            _copy_tree(src, dst)
        else:
            _copy_file(src, dst)
        staged.append(rel_src)
    return staged


def make_tgz(source_dir: pathlib.Path, out_path: pathlib.Path) -> None:
    with tarfile.open(out_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for path in _iter_archive_files(source_dir):
            relative = path.relative_to(source_dir)
            archive.add(path, arcname=str(relative))


def _write_info(info_path: pathlib.Path, version: str) -> None:
    info_path.write_text(render_info(version), encoding="utf-8")


def _copy_metadata(root: pathlib.Path, spk_root: pathlib.Path) -> None:
    synology_root = root / "synology"
    for rel_path in (
        "conf/privilege",
        "scripts/preinst",
        "scripts/postinst",
        "scripts/preuninst",
        "scripts/postuninst",
        "scripts/start-stop-status",
    ):
        _copy_file(synology_root / rel_path, spk_root / rel_path)
    icon_src = root / "ios/resources/obstaclebridge-icon-1024.png"
    _copy_file(icon_src, spk_root / "PACKAGE_ICON.PNG")
    _copy_file(icon_src, spk_root / "PACKAGE_ICON_256.PNG")


def build_spk(
    *,
    root: pathlib.Path,
    output_dir: pathlib.Path,
    keep_staging: bool = False,
) -> pathlib.Path:
    version = project_version(root)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="obstaclebridge-spk-") as temp_dir:
        temp_root = pathlib.Path(temp_dir)
        payload_root = temp_root / "payload"
        spk_root = temp_root / "spk"
        _reset_tree(payload_root)
        _reset_tree(spk_root)
        stage_payload(root, payload_root)
        _copy_metadata(root, spk_root)
        _write_info(spk_root / "INFO", version)
        make_tgz(payload_root, spk_root / "package.tgz")
        spk_name = f"{PACKAGE_ID}-{spk_version(version)}-noarch.spk"
        spk_path = output_dir / spk_name
        with tarfile.open(spk_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in _iter_archive_files(spk_root):
                relative = path.relative_to(spk_root)
                archive.add(path, arcname=str(relative))
        if keep_staging:
            staging_out = output_dir / f"{PACKAGE_ID}-{spk_version(version)}-staging"
            _reset_tree(staging_out)
            shutil.copytree(spk_root, staging_out, dirs_exist_ok=True)
        return spk_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the Synology DSM SPK wrapper for ObstacleBridge.")
    parser.add_argument(
        "--output-dir",
        default=str(repo_root() / "dist" / "synology"),
        help="Directory where the built SPK should be written.",
    )
    parser.add_argument(
        "--keep-staging",
        action="store_true",
        help="Keep a copy of the generated SPK staging tree next to the output file.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    out_dir = pathlib.Path(args.output_dir).resolve()
    built = build_spk(root=repo_root(), output_dir=out_dir, keep_staging=bool(args.keep_staging))
    print(built)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
