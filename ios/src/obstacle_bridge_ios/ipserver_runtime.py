"""Minimal Python runtime shim used by iOS extension-style integration tests.

The real on-device path is Swift-owned today. The integration suite still uses
this Python harness to exercise the same runtime config and service topology on
one machine.
"""

from __future__ import annotations

from typing import Any

LAST_PROVIDER_CONFIGURATION: dict[str, Any] | None = None

