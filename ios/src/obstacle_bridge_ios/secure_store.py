"""Secret-store abstraction for the iOS prototype.

Production iOS builds should back this interface with Keychain APIs.
The in-memory implementation is used for local tests and early spikes.
"""

from __future__ import annotations

from typing import Dict, Optional, Protocol


class SecretStore(Protocol):
    def put_secret(self, profile_id: str, key: str, value: str) -> None:
        ...

    def get_secret(self, profile_id: str, key: str) -> Optional[str]:
        ...

    def delete_profile(self, profile_id: str) -> None:
        ...


class InMemorySecretStore:
    """Test/prototype secret store that never writes secrets to disk."""

    def __init__(self) -> None:
        self._values: Dict[tuple[str, str], str] = {}

    def put_secret(self, profile_id: str, key: str, value: str) -> None:
        self._values[(str(profile_id), str(key))] = str(value)

    def get_secret(self, profile_id: str, key: str) -> Optional[str]:
        return self._values.get((str(profile_id), str(key)))

    def delete_profile(self, profile_id: str) -> None:
        pid = str(profile_id)
        for entry in [item for item in self._values if item[0] == pid]:
            self._values.pop(entry, None)
