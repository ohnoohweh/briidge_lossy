#!/usr/bin/env python3
import argparse
import os
import struct
import unittest
import zlib

from obstacle_bridge.bridge import CompressLayerSession, SessionMetrics


class FakeInnerSession:
    def __init__(self, *, max_payload=4096):
        self._max_payload = int(max_payload)
        self.sent = []
        self._on_app = None
        self._on_state = None
        self._on_peer_rx = None
        self._on_peer_tx = None
        self._on_peer_set = None
        self._on_peer_disconnect = None
        self._on_app_from_peer_bytes = None
        self._on_transport_epoch_change = None

    async def start(self):
        return None

    async def stop(self):
        return None

    async def wait_connected(self, timeout=None):
        return True

    def is_connected(self):
        return True

    def send_app(self, payload: bytes, peer_id=None):
        self.sent.append((bytes(payload), peer_id))
        return len(payload)

    def get_max_app_payload_size(self):
        return self._max_payload

    def get_metrics(self):
        return SessionMetrics()

    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb


class CompressLayerSessionTests(unittest.TestCase):
    MUX_HDR = struct.Struct(">HBHBH")

    @staticmethod
    def _args(**overrides):
        base = dict(
            compress_layer=True,
            compress_layer_algo="zlib",
            compress_layer_level=3,
            compress_layer_min_bytes=64,
            compress_layer_types="data,data_frag",
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    @classmethod
    def _pack_mux(cls, mtype: int, data: bytes, *, chan=7, proto=1, counter=2):
        return cls.MUX_HDR.pack(int(chan), int(proto), int(counter), int(mtype), len(data)) + bytes(data)

    @classmethod
    def _unpack_mux(cls, payload: bytes):
        chan, proto, counter, mtype, dlen = cls.MUX_HDR.unpack(payload[:cls.MUX_HDR.size])
        return chan, proto, counter, mtype, payload[cls.MUX_HDR.size:cls.MUX_HDR.size + dlen]

    def test_send_app_compresses_when_profitable_and_restores_on_rx(self):
        inner = FakeInnerSession()
        wrapper = CompressLayerSession(inner, self._args(compress_layer_min_bytes=1), "tcp")
        payload = self._pack_mux(0x00, b"A" * 512)

        out = []
        wrapper.set_on_app_payload(lambda p, peer_id=None: out.append((bytes(p), peer_id)))

        self.assertEqual(wrapper.send_app(payload), len(payload))
        self.assertEqual(len(inner.sent), 1)
        sent_payload, _peer_id = inner.sent[0]
        _chan, _proto, _counter, sent_mtype, sent_body = self._unpack_mux(sent_payload)
        self.assertEqual(sent_mtype, 0x80)
        self.assertLess(len(sent_body), 512)

        wrapper._on_inner_payload(sent_payload, peer_id=11)
        self.assertEqual(len(out), 1)
        restored_payload, restored_peer_id = out[0]
        self.assertEqual(restored_peer_id, 11)
        self.assertEqual(restored_payload, payload)

    def test_client_peer_snapshot_reports_configured_enabled_before_counters_exist(self):
        inner = FakeInnerSession()
        wrapper = CompressLayerSession(
            inner,
            self._args(peer="127.0.0.1", compress_layer=True),
            "tcp",
        )

        snap = wrapper.get_compress_layer_status_snapshot(peer_id=0)

        self.assertTrue(snap["enabled"])
        self.assertEqual(int(snap["compress_applied_total"]), 0)

    def test_send_app_bypasses_when_no_gain(self):
        inner = FakeInnerSession()
        wrapper = CompressLayerSession(inner, self._args(compress_layer_min_bytes=1), "tcp")
        body = os.urandom(256)
        payload = self._pack_mux(0x00, body)

        self.assertEqual(wrapper.send_app(payload), len(payload))
        self.assertEqual(len(inner.sent), 1)
        sent_payload, _peer_id = inner.sent[0]
        _chan, _proto, _counter, sent_mtype, sent_body = self._unpack_mux(sent_payload)
        self.assertEqual(sent_mtype, 0x00)
        self.assertEqual(sent_body, body)
        snap = wrapper.get_compress_layer_status_snapshot()
        self.assertEqual(int(snap["compress_attempts_total"]), 1)
        self.assertEqual(int(snap["compress_skipped_no_gain_total"]), 1)
        self.assertEqual(int(snap["compress_input_bytes_total"]), len(body))
        self.assertEqual(int(snap["compress_output_bytes_total"]), len(body))

    def test_receive_invalid_compressed_frame_is_dropped(self):
        inner = FakeInnerSession()
        wrapper = CompressLayerSession(inner, self._args(), "tcp")
        out = []
        wrapper.set_on_app_payload(lambda p, peer_id=None: out.append((bytes(p), peer_id)))

        invalid = self._pack_mux(0x80, b"not-zlib")
        wrapper._on_inner_payload(invalid, peer_id=2)
        self.assertEqual(out, [])
        snap = wrapper.get_compress_layer_status_snapshot()
        self.assertEqual(int(snap["decompress_fail_total"]), 1)

    def test_receive_compressed_frame_exceeding_cap_is_dropped(self):
        inner = FakeInnerSession(max_payload=80)
        wrapper = CompressLayerSession(inner, self._args(), "tcp")
        out = []
        wrapper.set_on_app_payload(lambda p, peer_id=None: out.append((bytes(p), peer_id)))

        oversized_plain = b"B" * 500
        compressed = zlib.compress(oversized_plain, 3)
        incoming = self._pack_mux(0x80, compressed)
        wrapper._on_inner_payload(incoming, peer_id=3)

        self.assertEqual(out, [])
        snap = wrapper.get_compress_layer_status_snapshot()
        self.assertEqual(int(snap["decompress_fail_total"]), 1)

    def test_server_passive_wrapper_activates_peer_after_compressed_rx(self):
        inner = FakeInnerSession()
        wrapper = CompressLayerSession(
            inner,
            self._args(
                compress_layer=False,
                compress_layer_min_bytes=4096,
                compress_layer_level=1,
                compress_layer_types="data",
            ),
            "tcp",
        )
        out = []
        wrapper.set_on_app_payload(lambda p, peer_id=None: out.append((bytes(p), peer_id)))
        peer_id = 44
        payload = self._pack_mux(0x00, b"C" * 512)

        self.assertFalse(wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)["enabled"])
        self.assertEqual(wrapper.send_app(payload, peer_id=peer_id), len(payload))
        sent_before_active, _ = inner.sent[-1]
        self.assertEqual(self._unpack_mux(sent_before_active)[3], 0x00)

        compressed_in = self._pack_mux(0x80, zlib.compress(b"D" * 512, 9))
        wrapper._on_inner_payload(compressed_in, peer_id=peer_id)
        self.assertEqual(len(out), 1)
        self.assertTrue(wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)["enabled"])
        self.assertEqual(wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)["min_bytes"], 64)

        self.assertEqual(wrapper.send_app(payload, peer_id=peer_id), len(payload))
        sent_after_active, _ = inner.sent[-1]
        self.assertEqual(self._unpack_mux(sent_after_active)[3], 0x80)
        self.assertGreaterEqual(
            int(wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)["compress_applied_total"]),
            1,
        )

        self.assertEqual(wrapper.send_app(payload), len(payload))
        sent_routed_later, routed_peer_id = inner.sent[-1]
        self.assertIsNone(routed_peer_id)
        self.assertEqual(self._unpack_mux(sent_routed_later)[3], 0x80)
        self.assertGreaterEqual(
            int(wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)["compress_applied_total"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
