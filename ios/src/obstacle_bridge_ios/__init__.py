"""ObstacleBridge iOS companion app prototype package."""

from .app import ObstacleBridgeIOSApp
from .dependency_spike import (
    run_m2_dependency_spike,
    run_m2_dependency_spike_sync,
    write_m2_dependency_spike_report,
)
from .m25_ui import M25Config, profile_from_m25_config, tcp_status_probe
from .m3_tunnel import (
    M3NetworkSettings,
    M3TunnelConfig,
    m3_tunnel_config_from_profile,
    m3_vpn_profile_from_profile,
    provider_configuration_from_m3_config,
)
from .onboarding import preview_import_text
from .profiles import ProfileStore
from .secure_store import InMemorySecretStore, SecretStore

__all__ = [
    "ObstacleBridgeIOSApp",
    "run_m2_dependency_spike",
    "run_m2_dependency_spike_sync",
    "write_m2_dependency_spike_report",
    "M25Config",
    "M3NetworkSettings",
    "M3TunnelConfig",
    "profile_from_m25_config",
    "m3_tunnel_config_from_profile",
    "m3_vpn_profile_from_profile",
    "provider_configuration_from_m3_config",
    "tcp_status_probe",
    "preview_import_text",
    "ProfileStore",
    "SecretStore",
    "InMemorySecretStore",
]
