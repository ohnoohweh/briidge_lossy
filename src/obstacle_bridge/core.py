"""Embeddable ObstacleBridge runtime facade.

This module is intentionally small. It gives non-CLI hosts, such as future iOS
apps, a stable lifecycle API over the existing ``Runner`` while the lower-level
transport and packet-I/O boundaries are refactored incrementally.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence

from .bridge import Runner, build_runtime_args_from_config
from .packet_io import PacketIO


RuntimeConfig = Mapping[str, Any]
RuntimeSnapshot = Dict[str, Any]


@dataclass
class ObstacleBridgeClient:
    """Programmatic runtime controller for embedders.

    The facade mirrors the milestone-0 API from ``IOSAPP_DESIGN.md``. It does
    not own event-loop creation; callers should await it from their host loop.
    """

    config: RuntimeConfig = field(default_factory=dict)
    argv: Sequence[str] = field(default_factory=tuple)
    config_path: Optional[str] = None
    packet_io: Optional[PacketIO] = None
    apply_logging: bool = False
    _args: Optional[argparse.Namespace] = field(default=None, init=False, repr=False)
    _runner: Optional[Runner] = field(default=None, init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)

    @property
    def args(self) -> argparse.Namespace:
        if self._args is None:
            self._args = build_runtime_args_from_config(
                self.config,
                self.argv,
                config_path=self.config_path,
                apply_logging=self.apply_logging,
            )
        return self._args

    @property
    def runner(self) -> Optional[Runner]:
        return self._runner

    async def start(
        self,
        config: Optional[RuntimeConfig] = None,
        packet_io: Optional[PacketIO] = None,
    ) -> None:
        if self._started:
            return
        if config is not None:
            self.config = config
            self._args = None
        if packet_io is not None:
            self.packet_io = packet_io
        self._runner = Runner(self.args)
        # Reserved for the upcoming TUN adapter refactor. Keeping the reference
        # on Runner makes early embedders/test spikes able to verify handoff
        # without changing current desktop ChannelMux behavior.
        setattr(self._runner, "packet_io", self.packet_io)
        await self._runner.start()
        self._started = True

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.stop()
        self._runner = None
        self._started = False

    async def update_config(self, config: RuntimeConfig) -> None:
        was_started = self._started
        if was_started:
            await self.stop()
        self.config = config
        self._args = None
        if was_started:
            await self.start()

    def snapshot(self) -> RuntimeSnapshot:
        if self._runner is None:
            return {"started": False}
        return {
            "started": self._started,
            "status": self._runner.get_status_snapshot(),
            "connections": self._runner.get_connections_snapshot(),
            "config": self._runner.get_config_snapshot(include_secrets=False),
        }
