from obstacle_bridge.bridge_transport_common import DeliveryFenceCodec
from obstacle_bridge.bridge_delivery_fence import DeliveryFenceSession


def test_delivery_fence_data_ping_and_pong_share_stable_big_endian_layout():
    data = DeliveryFenceCodec.encode_data(0x0102030405060708, b"hello")
    assert data.hex() == "4f4252540100010203040506070868656c6c6f"
    assert DeliveryFenceCodec.decode(data) == (DeliveryFenceCodec.KIND_DATA, 0x0102030405060708, b"hello")

    ping = DeliveryFenceCodec.encode_ping(1, 2, 9)
    kind, sequence, body = DeliveryFenceCodec.decode(ping) or (-1, -1, b"")
    assert (kind, sequence) == (DeliveryFenceCodec.KIND_PING, 0)
    assert DeliveryFenceCodec.decode_ping(body) == (1, 2, 9)

    pong = DeliveryFenceCodec.encode_pong(1, 9)
    kind, sequence, body = DeliveryFenceCodec.decode(pong) or (-1, -1, b"")
    assert (kind, sequence) == (DeliveryFenceCodec.KIND_PONG, 0)
    assert DeliveryFenceCodec.decode_pong(body) == (1, 9)


def test_delivery_fence_rejects_truncated_unknown_and_bad_control_records():
    assert DeliveryFenceCodec.decode(b"") is None
    assert DeliveryFenceCodec.decode(b"OBRT\x02\x00" + b"\0" * 8) is None
    assert DeliveryFenceCodec.decode(b"OBRT\x01\x01" + b"\0" * 8) is None


class _Inner:
    def __init__(self):
        self.connected = True
        self.sent = []

    def set_on_app_payload(self, callback): self.on_app = callback
    def set_on_state_change(self, callback): self.on_state = callback
    def set_on_connection_lifecycle(self, callback): self.on_lifecycle = callback
    def is_connected(self): return self.connected
    def send_app(self, payload, peer_id=None): self.sent.append((bytes(payload), peer_id)); return len(payload)
    def get_max_app_payload_size(self): return 65535
    def get_connection_layers_snapshot(self): return []


def test_delivery_fence_replays_only_unconfirmed_plaintext_after_reconnect():
    inner = _Inner()
    fence = DeliveryFenceSession(inner)
    fence._on_inner_state(True)
    payload = bytes(range(251)) * 17

    assert fence.send_app(payload) == len(payload)
    first = inner.sent[-1][0]
    assert DeliveryFenceCodec.decode(first) == (DeliveryFenceCodec.KIND_DATA, 1, payload)

    fence._on_inner_app(DeliveryFenceCodec.encode_pong(0, 1))
    assert fence._pending_bytes == 0
    assert fence.send_app(b"unconfirmed") == len(b"unconfirmed")
    unconfirmed = inner.sent[-1][0]
    fence._on_inner_state(True)

    assert inner.sent[-2][0] == unconfirmed
    assert DeliveryFenceCodec.decode(inner.sent[-2][0]) == (DeliveryFenceCodec.KIND_DATA, 2, b"unconfirmed")


def test_delivery_fence_acks_data_and_suppresses_its_replay_after_peer_confirmation():
    inner = _Inner()
    fence = DeliveryFenceSession(inner)
    delivered = []
    fence.set_on_app_payload(delivered.append)

    fence._on_inner_app(DeliveryFenceCodec.encode_data(1, b"random-payload-\x01\xfe"))
    assert delivered == [b"random-payload-\x01\xfe"]
    kind, _sequence, body = DeliveryFenceCodec.decode(inner.sent[-1][0]) or (-1, -1, b"")
    assert kind == DeliveryFenceCodec.KIND_PONG
    assert DeliveryFenceCodec.decode_pong(body)[1] == 1


def test_delivery_fence_routes_colliding_listener_mux_channels_without_exposing_its_envelope():
    inner = _Inner()
    fence = DeliveryFenceSession(inner)
    received = []
    fence.set_on_app_payload(lambda payload, peer_id=None: received.append((payload, peer_id)))

    mux_one = fence._MUX_HDR.pack(1, 1, 0, 1, 1) + b"a"
    mux_other = fence._MUX_HDR.pack(1, 1, 0, 1, 1) + b"b"
    fence._on_inner_app(DeliveryFenceCodec.encode_data(1, mux_one), peer_id=11)
    fence._on_inner_app(DeliveryFenceCodec.encode_data(1, mux_other), peer_id=12)

    first_channel = fence._MUX_HDR.unpack(received[0][0][:fence._MUX_HDR.size])[0]
    second_channel = fence._MUX_HDR.unpack(received[1][0][:fence._MUX_HDR.size])[0]
    assert (first_channel, second_channel) == (1, 3)
    assert [peer_id for _payload, peer_id in received] == [11, 12]

    fence._on_inner_state(True)
    assert fence.send_app(received[1][0]) == len(received[1][0])
    _kind, _sequence, body = DeliveryFenceCodec.decode(inner.sent[-1][0]) or (-1, -1, b"")
    assert fence._MUX_HDR.unpack(body[:fence._MUX_HDR.size])[0] == 1
    assert inner.sent[-1][1] == 12
