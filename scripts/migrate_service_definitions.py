#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _convert_legacy_token(token: str) -> dict:
    parts = [p.strip() for p in str(token or "").split(",")]
    if len(parts) != 6:
        raise ValueError(f"legacy service item must have 6 comma-separated fields: {token}")
    l_proto, l_port, l_bind, r_proto, r_host, r_port = parts
    l_proto = l_proto.lower()
    r_proto = r_proto.lower()
    if l_proto not in {"udp", "tcp", "tun"}:
        raise ValueError(f"unsupported local protocol in {token}")
    if r_proto not in {"udp", "tcp", "tun"}:
        raise ValueError(f"unsupported remote protocol in {token}")
    if l_proto == "tun":
        listen = {"protocol": "tun", "ifname": l_bind, "mtu": int(l_port)}
    else:
        listen = {"protocol": l_proto, "bind": l_bind, "port": int(l_port)}
    if r_proto == "tun":
        target = {"protocol": "tun", "ifname": r_host.strip("[]"), "mtu": int(r_port)}
    else:
        target = {"protocol": r_proto, "host": r_host.strip("[]"), "port": int(r_port)}
    return {"listen": listen, "target": target}


def _convert_service_catalog(value: Any) -> tuple[Any, bool]:
    if value is None:
        return value, False
    if isinstance(value, dict):
        return value, False
    if isinstance(value, list):
        changed = False
        converted = []
        for item in value:
            if isinstance(item, dict):
                converted.append(item)
                continue
            if item is None or (isinstance(item, str) and not item.strip()):
                changed = True
                continue
            if not isinstance(item, str):
                raise ValueError(f"unsupported service catalog entry type: {type(item).__name__}")
            tokens = item.split() if item.strip() else []
            if not tokens:
                changed = True
                continue
            for token in tokens:
                converted.append(_convert_legacy_token(token))
                changed = True
        return converted, changed
    raise ValueError(f"unsupported service catalog value type: {type(value).__name__}")


def _migrate_obj(obj: Any) -> tuple[Any, bool]:
    changed = False
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key in {"own_servers", "remote_servers"}:
                migrated, local_changed = _convert_service_catalog(value)
                out[key] = migrated
                changed = changed or local_changed
            else:
                migrated, local_changed = _migrate_obj(value)
                out[key] = migrated
                changed = changed or local_changed
        return out, changed
    if isinstance(obj, list):
        out = []
        for item in obj:
            migrated, local_changed = _migrate_obj(item)
            out.append(migrated)
            changed = changed or local_changed
        return out, changed
    return obj, False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate legacy own_servers/remote_servers tuple config into structured service objects.")
    parser.add_argument("input", help="Path to the source JSON config file")
    parser.add_argument("--output", "-o", help="Path for the migrated JSON output. Defaults to <input>.migrated.json")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite the input file in place")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"input file not found: {input_path}")
    output_path = input_path if args.overwrite else Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".migrated.json")

    payload = json.loads(input_path.read_text(encoding="utf-8"))
    migrated, changed = _migrate_obj(payload)
    output_path.write_text(json.dumps(migrated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{'migrated' if changed else 'verified'} service definitions -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
