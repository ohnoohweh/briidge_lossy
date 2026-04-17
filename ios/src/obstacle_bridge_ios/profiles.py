"""Profile persistence for the iOS M1 prototype."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from .secure_store import InMemorySecretStore, SecretStore

_SECRET_KEYS = ("secure_link_psk", "admin_web_password")


class ProfileStore:
    """Store profile metadata on disk while keeping secrets in secret storage."""

    def __init__(self, base_dir: Path | str, secret_store: Optional[SecretStore] = None) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.secret_store = secret_store or InMemorySecretStore()

    def _profile_path(self, profile_id: str) -> Path:
        return self.base_dir / f"{profile_id}.json"

    def save_profile(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        doc = json.loads(json.dumps(dict(profile)))
        profile_id = str(doc.get("profile_id", "") or "").strip()
        if not profile_id:
            raise ValueError("profile_id is required")

        ob_cfg = doc.get("obstacle_bridge")
        if isinstance(ob_cfg, dict):
            for key in _SECRET_KEYS:
                secret_value = ob_cfg.get(key)
                if isinstance(secret_value, str) and secret_value.strip():
                    self.secret_store.put_secret(profile_id, key, secret_value)
                    ob_cfg[key] = ""
                    ob_cfg[f"{key}_present"] = True

        path = self._profile_path(profile_id)
        path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
        return doc

    def load_profile(self, profile_id: str, include_secrets: bool = False) -> dict[str, Any]:
        path = self._profile_path(profile_id)
        if not path.exists():
            raise FileNotFoundError(path)
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not include_secrets:
            return doc

        ob_cfg = doc.get("obstacle_bridge")
        if isinstance(ob_cfg, dict):
            for key in _SECRET_KEYS:
                present = bool(ob_cfg.get(f"{key}_present"))
                if present:
                    secret_value = self.secret_store.get_secret(profile_id, key)
                    if isinstance(secret_value, str) and secret_value:
                        ob_cfg[key] = secret_value
        return doc

    def list_profile_ids(self) -> list[str]:
        return sorted(path.stem for path in self.base_dir.glob("*.json"))
