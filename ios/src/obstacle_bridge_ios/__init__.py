"""ObstacleBridge iOS companion app prototype package."""

from .app import ObstacleBridgeIOSApp
from .dependency_spike import (
    run_m2_dependency_spike,
    run_m2_dependency_spike_sync,
    write_m2_dependency_spike_report,
)
from .ipserver_extension import handle_message as handle_ipserver_message
from .ipserver_extension import handle_message_json as handle_ipserver_message_json
from .m25_ui import M25Config, profile_from_m25_config, tcp_status_probe
from .m3_tunnel import (
    M3_APP_MESSAGE_SCHEMA,
    M3NetworkSettings,
    M3TunnelConfig,
    M3TunnelStatus,
    m3_tunnel_config_from_profile,
    m3_vpn_profile_from_profile,
    provider_status_request_message,
    provider_configuration_from_m3_config,
    tunnel_status_from_provider_payload,
)
from .onboarding import preview_import_text
from .profiles import ProfileStore
from .secure_store import InMemorySecretStore, SecretStore

__all__ = [
    "ObstacleBridgeIOSApp",
    "run_m2_dependency_spike",
    "run_m2_dependency_spike_sync",
    "write_m2_dependency_spike_report",
    "handle_ipserver_message",
    "handle_ipserver_message_json",
    "M25Config",
    "M3_APP_MESSAGE_SCHEMA",
    "M3NetworkSettings",
    "M3TunnelConfig",
    "M3TunnelStatus",
    "profile_from_m25_config",
    "m3_tunnel_config_from_profile",
    "m3_vpn_profile_from_profile",
    "provider_status_request_message",
    "provider_configuration_from_m3_config",
    "tunnel_status_from_provider_payload",
    "tcp_status_probe",
    "preview_import_text",
    "ProfileStore",
    "SecretStore",
    "InMemorySecretStore",
]
