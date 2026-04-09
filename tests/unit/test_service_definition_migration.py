import json
import shutil
import uuid
from pathlib import Path

from scripts.migrate_service_definitions import main as migrate_main


def test_migrate_service_definition_catalogs():
    tmp_path = Path("test_tmp_service_migration_" + uuid.uuid4().hex)
    tmp_path.mkdir(parents=True, exist_ok=True)
    try:
        src = tmp_path / "ObstacleBridge.cfg"
        dst = tmp_path / "ObstacleBridge.migrated.json"
        src.write_text(json.dumps({
            "own_servers": [
                "tcp,80,0.0.0.0,tcp,127.0.0.1,8080",
                "tun,1400,obtun0,tun,obtun1,1400",
            ],
            "admin_web_port": 18080,
            "secure_link": {
                "remote_servers": [
                    "udp,16667,::,udp,127.0.0.1,16666",
                ]
            },
        }), encoding="utf-8")

        rc = migrate_main([str(src), "--output", str(dst)])

        assert rc == 0
        migrated = json.loads(dst.read_text(encoding="utf-8"))
        assert migrated["own_servers"][0]["listen"] == {"protocol": "tcp", "bind": "0.0.0.0", "port": 80}
        assert migrated["own_servers"][0]["target"] == {"protocol": "tcp", "host": "127.0.0.1", "port": 8080}
        assert migrated["own_servers"][1]["listen"] == {"protocol": "tun", "ifname": "obtun0", "mtu": 1400}
        assert migrated["own_servers"][1]["target"] == {"protocol": "tun", "ifname": "obtun1", "mtu": 1400}
        assert migrated["secure_link"]["remote_servers"][0]["listen"] == {"protocol": "udp", "bind": "::", "port": 16667}
        assert migrated["secure_link"]["remote_servers"][0]["target"] == {"protocol": "udp", "host": "127.0.0.1", "port": 16666}
        assert migrated["admin_web_port"] == 18080
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)
