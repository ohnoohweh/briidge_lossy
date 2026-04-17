"""Shared onboarding helpers for non-WebAdmin hosts.

This module exposes invite/config import preview functions that reuse the same
runtime validation rules as the existing admin onboarding APIs.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .bridge import AdminWebUI, build_runtime_args_from_config


def encode_invite_token(payload: Mapping[str, Any]) -> str:
    """Encode an onboarding invite payload into a token string."""
    if not isinstance(payload, Mapping):
        raise ValueError("invite payload must be a mapping")
    return AdminWebUI._encode_onboarding_token(dict(payload))


def decode_invite_token(token: str) -> dict[str, Any]:
    """Decode an onboarding invite token into a payload mapping."""
    return AdminWebUI._decode_onboarding_token(token)


def suggested_updates_from_invite(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Derive runtime config updates from a decoded invite payload."""
    if not isinstance(payload, Mapping):
        raise ValueError("invite payload must be a mapping")
    return AdminWebUI._onboarding_updates_from_invite(dict(payload))


def preview_invite_token(token: str) -> dict[str, Any]:
    """Return a redacted invite preview and runtime update suggestions."""
    payload = decode_invite_token(token)
    preview = dict(payload)
    if isinstance(preview.get("secure_link_psk"), str) and preview.get("secure_link_psk"):
        preview["secure_link_psk"] = "***hidden***"
        preview["secure_link_psk_present"] = True
    return {
        "kind": "invite",
        "preview": preview,
        "suggested_updates": suggested_updates_from_invite(payload),
    }


def preview_config_snippet(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a runtime config snippet and return a compact preview."""
    if not isinstance(config, Mapping):
        raise ValueError("config snippet must be a JSON object")
    args = build_runtime_args_from_config(dict(config), apply_logging=False)
    return {
        "kind": "config",
        "preview": {
            "overlay_transport": str(getattr(args, "overlay_transport", "") or ""),
            "secure_link_mode": str(getattr(args, "secure_link_mode", "") or ""),
            "admin_web": bool(getattr(args, "admin_web", False)),
        },
        "suggested_updates": dict(config),
    }


def preview_import_text(raw_text: str) -> dict[str, Any]:
    """Preview user-provided import text as invite token or JSON config snippet."""
    text = str(raw_text or "").strip()
    if not text:
        raise ValueError("import text is empty")
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except Exception as exc:
            raise ValueError(f"config snippet has invalid JSON payload: {exc}") from exc
        return preview_config_snippet(payload)
    return preview_invite_token(text)
