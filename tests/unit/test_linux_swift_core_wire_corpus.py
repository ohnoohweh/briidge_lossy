"""Python acceptance check for the shared Linux Swift Core wire corpus."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from obstacle_bridge.bridge import ChannelMux
from obstacle_bridge.bridge_channelmux import ChannelMux as ServiceChannelMux
from obstacle_bridge.bridge_securelink import SecureLinkPskSession
import obstacle_bridge.bridge_transport_udp as myudp
from obstacle_bridge.bridge_transport_ws import WebSocketBinaryPayloadCodec


CORPUS = Path(__file__).resolve().parents[2] / "swift/Tests/ObstacleBridgeCoreTests/Fixtures/python_wire_codec_corpus.json"


def test_core_wire_corpus_matches_python_protocol_layouts() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    tcp = corpus["tcp_application"]
    payload = bytes.fromhex(tcp["payload_hex"])
    assert struct.pack(">I", len(payload) + 1) + b"\x00" + payload == bytes.fromhex(tcp["wire_hex"])

    myudp_data = corpus["myudp_data"]
    data_payload = bytes.fromhex(myudp_data["payload_hex"])
    batch = myudp.MyUDP2BatchCodec.encode_batch([
        myudp.StreamChunk(int(myudp_data["counter"]), data_payload),
    ])
    original_now_ns = myudp.now_ns
    try:
        myudp.now_ns = lambda: int(myudp_data["transmitted_nanoseconds"])
        protocol = myudp.Protocol(myudp.BaseFrameV2)
        protocol._last_rx_tx_ns = int(myudp_data["echoed_nanoseconds"])
        protocol._last_rx_wall_ns = int(myudp_data["transmitted_nanoseconds"])
        wire = protocol.build_frame(myudp.Protocol.PTYPE_DATA, batch)
    finally:
        myudp.now_ns = original_now_ns
    assert wire.hex() == myudp_data["wire_hex"]
    parsed = myudp.Protocol(myudp.BaseFrameV2).parse_frame_with_times(wire)
    assert parsed is not None
    packet_type, parsed_batch, transmitted_nanoseconds, echoed_nanoseconds = parsed
    assert packet_type == myudp.Protocol.PTYPE_DATA
    assert transmitted_nanoseconds == int(myudp_data["transmitted_nanoseconds"])
    assert echoed_nanoseconds == int(myudp_data["echoed_nanoseconds"])
    decoded_chunks = myudp.MyUDP2BatchCodec.decode_batch(parsed_batch)
    assert [(chunk.counter, chunk.data) for chunk in decoded_chunks] == [(int(myudp_data["counter"]), data_payload)]

    control = corpus["myudp_control"]
    protocol = myudp.Protocol(myudp.BaseFrameV2)
    original_now_ns = myudp.now_ns
    try:
        myudp.now_ns = lambda: int(control["transmitted_nanoseconds"])
        protocol._last_rx_tx_ns = int(control["echoed_nanoseconds"])
        protocol._last_rx_wall_ns = int(control["transmitted_nanoseconds"])
        wire = protocol.build_frame(myudp.Protocol.PTYPE_CONTROL, struct.pack(">HHH", control["last_in_order"], control["highest_received"], len(control["missing"])) + b"".join(struct.pack(">H", value) for value in control["missing"]))
    finally:
        myudp.now_ns = original_now_ns
    assert wire.hex() == control["wire_hex"]

    websocket = corpus["websocket_binary"]
    websocket_payload = bytes.fromhex(websocket["payload_hex"])
    websocket_wire = WebSocketBinaryPayloadCodec().encode(b"\x00" + websocket_payload)
    assert websocket_wire.hex() == websocket["wire_hex"]
    assert WebSocketBinaryPayloadCodec().decode(websocket_wire) == websocket_wire

    securelink = corpus["securelink_psk"]
    psk = bytes.fromhex(securelink["psk_hex"])
    client_nonce = bytes.fromhex(securelink["client_nonce_hex"])
    server_nonce = bytes.fromhex(securelink["server_nonce_hex"])
    session = object.__new__(SecureLinkPskSession)
    session._psk = psk
    client_to_server, server_to_client = session._derive_keys(int(securelink["session_id"]), client_nonce, server_nonce)
    assert client_to_server.hex() == securelink["client_to_server_key_hex"]
    assert server_to_client.hex() == securelink["server_to_client_key_hex"]
    assert session._server_proof(int(securelink["session_id"]), client_nonce, server_nonce).hex() == securelink["server_proof_hex"]
    assert session._client_rekey_commit_proof(int(securelink["session_id"]), client_nonce, server_nonce).hex() == securelink["client_rekey_commit_proof_hex"]
    client_hello = SecureLinkPskSession._build_frame(1, int(securelink["session_id"]), 0, client_nonce + b"\x01\x00")
    server_hello = SecureLinkPskSession._build_frame(2, int(securelink["session_id"]), 0, server_nonce + b"\x01" + bytes.fromhex(securelink["server_proof_hex"]))
    assert client_hello.hex() == securelink["client_hello_hex"]
    assert server_hello.hex() == securelink["server_hello_hex"]
    assert all(SecureLinkPskSession._parse_frame(bytes.fromhex(value)) is None for value in securelink["malformed_envelope_hex"])

    chunk = corpus["control_chunk"]
    payload = bytes.fromhex(chunk["payload_hex"])
    maximum = int(chunk["maximum_application_payload"])
    capacity = maximum - 8 - ChannelMux.CTRL_CHUNK_HDR.size
    expected = []
    for index in range((len(payload) + capacity - 1) // capacity):
        expected.append(ChannelMux.CTRL_CHUNK_HDR.pack(ChannelMux.CTRL_CHUNK_MAGIC, int(chunk["transaction_id"]), index, 3) + payload[index * capacity:(index + 1) * capacity])
    assert [item.hex() for item in expected] == chunk["chunks_hex"]

    service = corpus["service_records"]
    bind = host = b"127.0.0.1"
    metadata = b'{"name":"echo","lifecycle_hooks":null,"options":null}'
    o4 = b"O4" + struct.pack(">QIHB", service["instance_id"], service["connection_sequence"], service["service_id"], 1) + bytes([len(bind)]) + bind + struct.pack(">HB", 7001, 1) + bytes([len(host)]) + host + struct.pack(">H", 7002)
    o5 = b"O5" + struct.pack(">QIHBH", service["instance_id"], service["connection_sequence"], service["service_id"], 1, len(bind)) + bind + struct.pack(">HBH", 7001, 1, len(host)) + host + struct.pack(">HI", 7002, len(metadata)) + metadata
    row = b'{"svc_id":7,"l_proto":"tcp","l_bind":"127.0.0.1","l_port":7001,"r_proto":"tcp","r_host":"127.0.0.1","r_port":7002,"name":"echo","lifecycle_hooks":null,"options":null}'
    rs3 = b"RS3" + struct.pack(">QII", service["instance_id"], service["connection_sequence"], len(row) + 2) + b"[" + row + b"]"
    rs2 = b"RS2" + struct.pack(">QIH", service["instance_id"], service["connection_sequence"], 1) + struct.pack(">HB", service["service_id"], 1) + bytes([len(bind)]) + bind + struct.pack(">HB", 7001, 1) + bytes([len(host)]) + host + struct.pack(">H", 7002)
    assert o4.hex() == service["open_o4_hex"]
    assert o5.hex() == service["open_o5_hex"]
    assert rs2.hex() == service["rs2_hex"]
    assert rs3.hex() == service["rs3_hex"]

    service_codec = object.__new__(ServiceChannelMux)
    assert service_codec._parse_open_with_meta(o4) is not None
    assert service_codec._parse_open_with_meta(o5) is not None
    assert service_codec._decode_remote_services_set_v2(rs2) is not None
    assert service_codec._decode_remote_services_set_v2(rs3) is not None
    trailing = bytes.fromhex(service["trailing_hex"])
    assert service_codec._parse_open_with_meta(o4 + trailing) is None
    assert service_codec._parse_open_with_meta(o5 + trailing) is None
    assert service_codec._decode_remote_services_set_v2(rs2 + trailing) is None
    assert service_codec._decode_remote_services_set_v2(rs3 + trailing) is None
    for count in service["truncated_bytes"]:
        assert service_codec._parse_open_with_meta(o4[:-count]) is None
        assert service_codec._parse_open_with_meta(o5[:-count]) is None
        assert service_codec._decode_remote_services_set_v2(rs2[:-count]) is None
        assert service_codec._decode_remote_services_set_v2(rs3[:-count]) is None
