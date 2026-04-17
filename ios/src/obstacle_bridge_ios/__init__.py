"""ObstacleBridge iOS companion app prototype package."""

from .app import ObstacleBridgeIOSApp
from .dependency_spike import (
    run_m2_dependency_spike,
    run_m2_dependency_spike_sync,
    write_m2_dependency_spike_report,
)
from .m25_ui import M25Config, profile_from_m25_config, tcp_status_probe
from .onboarding import preview_import_text
from .profiles import ProfileStore
from .secure_store import InMemorySecretStore, SecretStore

__all__ = [
    "ObstacleBridgeIOSApp",
    "run_m2_dependency_spike",
    "run_m2_dependency_spike_sync",
    "write_m2_dependency_spike_report",
    "M25Config",
    "profile_from_m25_config",
    "tcp_status_probe",
    "preview_import_text",
    "ProfileStore",
    "SecretStore",
    "InMemorySecretStore",
]
