-- myUDP2 Wireshark dissector. Use Analyze -> Decode As for the active UDP port.
-- Wire contract: docs/MYUDP2_WIRE_VECTORS.json
local p = Proto("myudp2", "ObstacleBridge myUDP2")

local f = p.fields
f.ptype = ProtoField.uint8("myudp2.ptype", "PTYPE", base.DEC)
f.plen = ProtoField.uint16("myudp2.payload_len", "Payload Length")
f.tx = ProtoField.uint64("myudp2.tx_ns", "TX Time (ns)")
f.echo = ProtoField.uint64("myudp2.echo_ns", "Echo Time (ns)")
f.batch_version = ProtoField.uint8("myudp2.batch.version", "Batch Version")
f.record_count = ProtoField.uint8("myudp2.batch.record_count", "Batch Record Count")
f.record_length = ProtoField.uint16("myudp2.batch.record_length", "Record Length")
f.counter = ProtoField.uint16("myudp2.chunk.counter", "Chunk Counter")
f.chunk_length = ProtoField.uint16("myudp2.chunk.length", "Chunk Length")
f.chunk_bytes = ProtoField.bytes("myudp2.chunk.bytes", "Opaque Chunk Bytes")
f.last = ProtoField.uint16("myudp2.control.last_in_order", "Last In-Order")
f.highest = ProtoField.uint16("myudp2.control.highest_rx", "Highest RX")
f.missed_count = ProtoField.uint16("myudp2.control.missed_count", "Missed Count")
f.missed = ProtoField.uint16("myudp2.control.missed", "Missed Counter")

local HEADER = 19
local DATA_BATCH, CONTROL, IDLE = 1, 2, 0
local BATCH_VERSION, MAX_RECORDS, MIN_RECORD = 1, 64, 5

local function malformed(tree, message)
  tree:add_expert_info(PI_MALFORMED, PI_ERROR, message)
end

function p.dissector(buffer, pinfo, tree)
  if buffer:len() < HEADER then return end
  local ptype, plen = buffer(0, 1):uint(), buffer(1, 2):uint()
  if buffer:len() ~= HEADER + plen then return end

  pinfo.cols.protocol = "MYUDP2"
  local subtree = tree:add(p, buffer())
  subtree:add(f.ptype, buffer(0, 1))
  subtree:add(f.plen, buffer(1, 2))
  subtree:add(f.tx, buffer(3, 8))
  subtree:add(f.echo, buffer(11, 8))
  local payload = buffer(HEADER, plen)

  if ptype == IDLE then
    if plen ~= 0 then malformed(subtree, "IDLE payload must be empty") end
    pinfo.cols.info = "IDLE"
    return
  end
  if ptype == CONTROL then
    if plen < 6 then malformed(subtree, "CONTROL header truncated") return end
    local count = payload(4, 2):uint()
    if plen ~= 6 + count * 2 then malformed(subtree, "CONTROL length mismatch") return end
    subtree:add(f.last, payload(0, 2))
    subtree:add(f.highest, payload(2, 2))
    subtree:add(f.missed_count, payload(4, 2))
    for i = 0, count - 1 do subtree:add(f.missed, payload(6 + i * 2, 2)) end
    pinfo.cols.info = string.format("CONTROL last=%u highest=%u missed=%u", payload(0,2):uint(), payload(2,2):uint(), count)
    return
  end
  if ptype ~= DATA_BATCH then
    pinfo.cols.info = string.format("Unknown ptype=%u", ptype)
    return
  end
  if plen < 2 then malformed(subtree, "DATA batch header truncated") return end
  local version, count = payload(0, 1):uint(), payload(1, 1):uint()
  subtree:add(f.batch_version, payload(0, 1))
  subtree:add(f.record_count, payload(1, 1))
  if version ~= BATCH_VERSION then malformed(subtree, "Unsupported batch version") return end
  if count == 0 or count > MAX_RECORDS then malformed(subtree, "Invalid batch record count") return end

  local offset, first_counter, last_counter = 2, nil, nil
  for _ = 1, count do
    if offset + 2 > plen then malformed(subtree, "Record length truncated") return end
    local record_length = payload(offset, 2):uint()
    subtree:add(f.record_length, payload(offset, 2))
    offset = offset + 2
    if record_length < MIN_RECORD or offset + record_length > plen then malformed(subtree, "Invalid record length") return end
    local record = payload(offset, record_length)
    local counter, chunk_length = record(0, 2):uint(), record(2, 2):uint()
    if record_length ~= 4 + chunk_length then malformed(subtree, "Chunk length mismatch") return end
    subtree:add(f.counter, record(0, 2))
    subtree:add(f.chunk_length, record(2, 2))
    subtree:add(f.chunk_bytes, record(4, chunk_length))
    first_counter, last_counter = first_counter or counter, counter
    offset = offset + record_length
  end
  if offset ~= plen then malformed(subtree, "Trailing bytes after final record") return end
  pinfo.cols.info = string.format("DATA_BATCH records=%u counters=%u-%u", count, first_counter, last_counter)
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(443, p)
udp_table:add(40001, p)
