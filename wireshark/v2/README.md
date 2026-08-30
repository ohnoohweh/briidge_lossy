# myUDP2 Wireshark Analysis

Install `udp_bidirectional_transfer_v2.lua` through Wireshark's personal Lua
plugin directory, restart Wireshark, then select `Analyze -> Decode As` and map
the captured ObstacleBridge UDP port to `myUDP2`.

Useful display filters:

- `myudp2.ptype == 1` for DATA batches
- `myudp2.chunk.counter == 42` for one reliable chunk
- `myudp2.control.missed == 42` for loss feedback about that chunk
- `myudp2.batch.record_count > 1` for coalesced datagrams

Add these columns to the profile: `myudp2.ptype`,
`myudp2.batch.record_count`, `myudp2.chunk.counter`, `myudp2.tx_ns`, and
`myudp2.echo_ns`. The dissector intentionally leaves chunk bytes opaque; it
does not decode SecureLink, Compression, or ChannelMux payloads.
