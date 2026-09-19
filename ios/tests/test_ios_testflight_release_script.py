from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ios" / "scripts" / "release_ios_testflight.sh"


def test_testflight_release_archives_container_and_uploads_with_api_key() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert '-scheme ObstacleBridge' in source
    assert 'CURRENT_PROJECT_VERSION="${IOS_BUILD_NUMBER}"' in source
    assert 'MARKETING_VERSION="${IOS_MARKETING_VERSION}"' in source
    assert 'app-store-connect' in source
    assert '/usr/bin/plutil -create xml1 "${EXPORT_OPTIONS_PATH}"' in source
    assert '/usr/bin/plutil -lint "${EXPORT_OPTIONS_PATH}" >/dev/null' in source
    assert source.index('plutil -create xml1') < source.index('Add :method string app-store-connect')
    assert '--upload-package "${IPA_PATH}"' in source
    assert '--api-key "${OB_APPSTORE_API_KEY_ID}"' in source
    assert '--api-issuer "${OB_APPSTORE_API_ISSUER_ID}"' in source
    assert '--p8-file-path "${OB_APPSTORE_API_KEY_PATH}"' in source
    assert '--wait' in source
    assert 'IPServer is an embedded packet-tunnel extension' in source
    assert 'export OB_IOS_PREPARE_ONLY=1' in source
    assert 'OB_TESTFLIGHT_GROUP_NAME:-ObstacleBridgeTesters' in source
    assert 'assign_testflight_group.py' in source
    assert '--group-name "${TESTFLIGHT_GROUP_NAME}"' in source
    assert "Apple Distribution signing identity is required" in source
    assert 'validate_bundle_version' in source
    assert 'container and IPServer bundle versions differ' in source
    assert 'load_release_environment "${HOME}/.local-device-env"' in source
    assert 'OB_APPSTORE_API_KEY_ID|OB_APPSTORE_API_ISSUER_ID' in source
    assert 'unrelated credentials' in source


def test_device_build_script_accepts_release_version_and_generic_signing_update() -> None:
    source = (ROOT / "ios" / "scripts" / "build_ios_app.sh").read_text(encoding="utf-8")

    assert 'OB_IOS_MARKETING_VERSION' in source
    assert 'OB_IOS_BUILD_NUMBER' in source
    assert 'OB_IOS_ALLOW_PROVISIONING_UPDATES' in source
    assert 'OB_IOS_PREPARE_ONLY' in source
    assert 'skipping Debug xcodebuild' in source
