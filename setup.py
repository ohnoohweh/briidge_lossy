from __future__ import annotations

from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


ROOT = Path(__file__).resolve().parent
CANONICAL_ADMIN_WEB_DIR = ROOT / "admin_web"
PACKAGE_ADMIN_WEB_REL = Path("obstacle_bridge") / "admin_web"


class build_py(_build_py):
    def run(self):
        super().run()
        self._stage_admin_web_assets()

    def get_source_files(self):
        files = super().get_source_files()
        if CANONICAL_ADMIN_WEB_DIR.is_dir():
            files.extend(
                str(path.relative_to(ROOT))
                for path in sorted(CANONICAL_ADMIN_WEB_DIR.rglob("*"))
                if path.is_file()
            )
        return files

    def _stage_admin_web_assets(self):
        if not CANONICAL_ADMIN_WEB_DIR.is_dir():
            return
        target_dir = Path(self.build_lib) / PACKAGE_ADMIN_WEB_REL
        target_dir.mkdir(parents=True, exist_ok=True)
        for source_path in sorted(CANONICAL_ADMIN_WEB_DIR.rglob("*")):
            if source_path.is_dir():
                continue
            relative = source_path.relative_to(CANONICAL_ADMIN_WEB_DIR)
            destination = target_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)


setup(cmdclass={"build_py": build_py})
