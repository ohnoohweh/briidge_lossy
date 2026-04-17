"""iOS onboarding import/preview helpers."""

from __future__ import annotations

from typing import Any

from obstacle_bridge.onboarding import preview_import_text as shared_preview_import_text


def preview_import_text(raw_text: str) -> dict[str, Any]:
    """Preview user-provided invite tokens or JSON runtime snippets."""
    return shared_preview_import_text(raw_text)
