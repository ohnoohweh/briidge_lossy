import io
import pathlib
import tarfile

from scripts.build_synology_spk import build_spk, render_info, repo_root


def test_render_info_contains_required_synology_fields():
    info = render_info("0.1.0")
    assert 'package="obstaclebridge"' in info
    assert 'version="0.1.0-1000"' in info
    assert 'arch="noarch"' in info
    assert 'startable="yes"' in info


def test_build_spk_emits_info_and_payload_archive(tmp_path: pathlib.Path):
    built = build_spk(root=repo_root(), output_dir=tmp_path)

    assert built.exists()
    assert built.name.endswith(".spk")

    with tarfile.open(built, "r:gz") as spk_archive:
        names = set(spk_archive.getnames())
        assert "INFO" in names
        assert "PACKAGE_ICON.PNG" in names
        assert "PACKAGE_ICON_256.PNG" in names
        assert "scripts/start-stop-status" in names
        assert "conf/privilege" in names
        assert "package.tgz" in names

        info_member = spk_archive.extractfile("INFO")
        assert info_member is not None
        info_text = info_member.read().decode("utf-8")
        assert 'displayname="ObstacleBridge"' in info_text

        payload_member = spk_archive.extractfile("package.tgz")
        assert payload_member is not None
        payload_bytes = io.BytesIO(payload_member.read())
        with tarfile.open(fileobj=payload_bytes, mode="r:gz") as payload_archive:
            payload_names = set(payload_archive.getnames())
            assert "src/obstacle_bridge/bridge.py" in payload_names
            assert "admin_web/app.js" in payload_names
            assert "share/defaults/ObstacleBridge.cfg" in payload_names
