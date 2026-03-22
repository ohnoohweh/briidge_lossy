-- udp_bidirectional_transfer_v2.lua
-- Wireshark dissector for variable-length framing, no MAGIC, no padding.
-- New Protocol header:
--   [ ptype:1 | plen:2 | tx_time_ns:8 | echo_time_ns:8 ] + payload[plen]
-- IDLE is PTYPE=0 with empty payload.
local p = Proto("udp_biditransfer_v2", "UDP Bidirectional Transfer (v2 framing)")

-- --------------------------
-- Fields
-- --------------------------
local f = p.fields
-- Header
f.ptype  = ProtoField.uint8 ("bidi2.ptype",  "PTYPE", base.HEX)
f.plen   = ProtoField.uint16("bidi2.plen",   "Payload Length")
f.h_tx   = ProtoField.uint64("bidi2.hdr.tx",   "Header TX Time (ns)")
f.h_echo = ProtoField.uint64("bidi2.hdr.echo", "Header Echo Time (ns)")

-- DATA payload (timestamps removed)
f.counter   = ProtoField.uint16("bidi2.data.counter", "Packet Counter")
f.frame_t   = ProtoField.uint8 ("bidi2.data.ftype",   "Frame Type", base.HEX)
f.len_off   = ProtoField.uint16("bidi2.data.len_off", "Length/Offset")
f.chunk_len = ProtoField.uint16("bidi2.data.chunk",   "Chunk Length")
f.payload   = ProtoField.bytes ("bidi2.data.payload", "Chunk Payload")

-- CONTROL payload (timestamps removed)
f.ctl_last = ProtoField.uint16("bidi2.ctrl.last",  "Last In-Order RX")
f.ctl_high = ProtoField.uint16("bidi2.ctrl.high",  "Highest RX")
f.ctl_mcnt = ProtoField.uint16("bidi2.ctrl.mcnt",  "Missed Count")
f.ctl_miss = ProtoField.uint16("bidi2.ctrl.missed","Missed Counter")

-- --------------------------
-- Constants
-- --------------------------
local PTYPE_IDLE    = 0x00
local PTYPE_DATA    = 0x01
local PTYPE_CONTROL = 0x02

-- --------------------------
-- Helpers
-- --------------------------
local function parse_header(buf)
  -- need at least 19 bytes header (1+2+8+8)
  if buf:len() < 19 then return nil end
  local ptype = buf(0,1):uint()
  local plen  = buf(1,2):uint()
  -- total must be header + payload (padding not used in v2)
  if buf:len() < 19 + plen then return nil end
  return ptype, plen
end

-- --------------------------
-- Main dissector
-- --------------------------
function p.dissector(buffer, pinfo, tree)
  local ptype, plen = parse_header(buffer)
  if not ptype then return end

  pinfo.cols.protocol = "BIDITRANS2"
  local subtree = tree:add(p, buffer())

  subtree:add(f.ptype,  buffer(0,1))
  subtree:add(f.plen,   buffer(1,2))
  subtree:add(f.h_tx,   buffer(3,8))
  subtree:add(f.h_echo, buffer(11,8))

  local payload = buffer(19, plen)

  if ptype == PTYPE_IDLE then
    pinfo.cols.info = "IDLE"
    return

  elseif ptype == PTYPE_DATA then
    if plen < 7 then return end -- ctr(2)+ft(1)+len/off(2)+chunk_len(2)
    local counter   = payload(0,2):uint()
    local frame_t   = payload(2,1):uint()
    local len_off   = payload(3,2):uint()
    local chunk_len = payload(5,2):uint()

    if (7 + chunk_len) > plen then return end

    subtree:add(f.counter,   payload(0,2))
    subtree:add(f.frame_t,   payload(2,1))
    subtree:add(f.len_off,   payload(3,2))
    subtree:add(f.chunk_len, payload(5,2))
    if chunk_len > 0 then
      subtree:add(f.payload, payload(7, chunk_len))
    end

    pinfo.cols.info = string.format(
      "DATA cnt=%u type=0x%02X len/off=%u chunk=%u",
      counter, frame_t, len_off, chunk_len
    )

  elseif ptype == PTYPE_CONTROL then
    if plen < 6 then return end -- last(2)+highest(2)+num_missed(2)
    local last = payload(0,2):uint()
    local high = payload(2,2):uint()
    local mcnt = payload(4,2):uint()

    subtree:add(f.ctl_last, payload(0,2))
    subtree:add(f.ctl_high, payload(2,2))
    subtree:add(f.ctl_mcnt, payload(4,2))

    local missed_end = 6 + 2 * mcnt
    if missed_end > plen then return end
    for i = 0, mcnt - 1 do
      subtree:add(f.ctl_miss, payload(6 + 2*i, 2))
    end

    pinfo.cols.info = string.format(
      "CONTROL last=%u highest=%u missed=%u", last, high, mcnt
    )

  else
    pinfo.cols.info = string.format("Unknown ptype=0x%02X", ptype)
  end
end

-- --------------------------
-- Port bindings (adjust as needed)
-- --------------------------
local udp_table = DissectorTable.get("udp.port")
udp_table:add(443, p)
udp_table:add(40001, p)