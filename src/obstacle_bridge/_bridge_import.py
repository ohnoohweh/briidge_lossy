from __future__ import annotations

import sys
from types import ModuleType
from typing import Any


_EXCLUDED_GLOBALS = {
    "__builtins__",
    "__name__",
    "__package__",
    "__file__",
    "__cached__",
    "__doc__",
    "__spec__",
    "__loader__",
}


def resolve_bridge_module() -> ModuleType:
    main_mod = sys.modules.get("__main__")
    if isinstance(main_mod, ModuleType):
        main_spec = getattr(main_mod, "__spec__", None)
        main_name = getattr(main_spec, "name", "") if main_spec is not None else ""
        if main_name == "obstacle_bridge.bridge":
            return main_mod

    module = sys.modules.get("obstacle_bridge.bridge")
    if isinstance(module, ModuleType):
        return module

    from . import bridge as bridge_module

    return bridge_module


def export_bridge_globals(namespace: dict[str, Any]) -> ModuleType:
    bridge_module = resolve_bridge_module()
    namespace.update(
        {
            key: value
            for key, value in bridge_module.__dict__.items()
            if key not in _EXCLUDED_GLOBALS
        }
    )
    return bridge_module
