-- udp_bidirectional_transfer.lua
-- Wireshark dissector for custom UDP overlay using BaseFrame envelope
-- (MAGIC + fixed-size 1158-byte frames) with Protocol inner header times.
--
-- Inner Protocol header layout (immediately after 20B MAGIC):
--   [ ptype:1 | plen:2 | tx_time_ns:8 | echo_time_ns:8 | payload[plen] ]
--   * IDLE is PTYPE=0 with empty payload.
--   * DATA payload:  ctr(2) | frame_type(1) | len_or_off(2) | chunk_len(2) | data...
--   * CONTROL payload: last(2) | highest(2) | num_missed(2) | missed[num_missed]*u16
--
-- This file matches the Python BaseFrame implementation and the Protocol header
-- defined in obstacle_bridge.transfer (BaseFrame). Offsets below are
-- absolute from the start of the UDP payload.

local p = Proto("udp_biditransfer", "UDP Bidirectional Transfer Protocol (BaseFrame)")

-- --------------------------
-- Fields
-- --------------------------
local f = p.fields

-- Envelope
f.magic   = ProtoField.bytes ("udp_biditransfer.magic", "Magic")
f.ptype   = ProtoField.uint8 ("udp_biditransfer.ptype", "Packet Type", base.HEX)
f.plen    = ProtoField.uint16("udp_biditransfer.plen",  "Payload Length")
-- Header times (moved from payloads into the header)
f.h_tx    = ProtoField.uint64("udp_biditransfer.hdr.tx_ns",   "Header TX Time (ns)")
f.h_echo  = ProtoField.uint64("udp_biditransfer.hdr.echo_ns", "Header Echo Time (ns)")

-- DATA payload (timestamps removed from payload)
f.counter = ProtoField.uint16("udp_biditransfer.counter",       "Packet Counter")
f.frame_t = ProtoField.uint8 ("udp_biditransfer.frame_type",    "Frame Type", base.HEX)
f.len_off = ProtoField.uint16("udp_biditransfer.len_or_offset", "Length/Offset")
f.chunklen= ProtoField.uint16("udp_biditransfer.chunk_len",     "Chunk Length")
f.payload = ProtoField.bytes ("udp_biditransfer.payload",       "Payload")

-- CONTROL payload (timestamps removed from payload)
f.ctl_last   = ProtoField.uint16("udp_biditransfer.ctl_last",   "Last In-Order RX")
f.ctl_high   = ProtoField.uint16("udp_biditransfer.ctl_highest", "Highest RX")
f.ctl_mcnt   = ProtoField.uint16("udp_biditransfer.ctl_mcnt",   "Missed Count")
f.ctl_missed = ProtoField.uint16("udp_biditransfer.ctl_missed", "Missed Counter")

-- --------------------------
-- Constants / layout
-- --------------------------
local UDP_FRAME_SIZE = 1158
local MAGIC_BYTES = ByteArray.new("C8 00 00 00 02 08 01 02 03 04 05 06 07 05 63 5F 63 69 64 00")

-- PTYPE values
local PTYPE_IDLE    = 0x00
local PTYPE_DATA    = 0x01
local PTYPE_CONTROL = 0x02

-- Envelope offsets (absolute)
local MAGIC_LEN = 20
local PTYPE_OFF = 20           -- starts immediately after the 20B MAGIC
local PLEN_OFF  = 21           -- 2 bytes
local H_TX_OFF  = 23           -- 8 bytes (tx_time_ns)
local H_EC_OFF  = 31           -- 8 bytes (echo_time_ns)
local PAYLOAD_OFF = 39         -- start of inner payload

-- DATA payload constants (lengths)
local DATA_FIXED = 2 + 1 + 2 + 2 -- ctr + frame_type + len/off + chunk_len

-- CONTROL payload constants (lengths)
local CTL_FIXED_BASE = 2 + 2 + 2 -- last + highest + num_missed

-- Frame types inside DATA
local FRAME_FIRST = 0x01
local FRAME_CONT  = 0x02

-- --------------------------
-- Helpers
-- --------------------------
local function magic_ok(buf)
  return buf(0, MAGIC_LEN):bytes() == MAGIC_BYTES
end

local function in_range(start_off, length, buf)
  return start_off >= 0 and (start_off + length) <= buf:len()
end

-- --------------------------
-- Dissector
-- --------------------------
function p.dissector(buffer, pinfo, tree)
  -- Enforce fixed outer frame size & magic per BaseFrame envelope
  if buffer:len() ~= UDP_FRAME_SIZE then return end
  if not magic_ok(buffer) then return end

  pinfo.cols.protocol = "BIDITRANS"

  local subtree = tree:add(p, buffer())
  subtree:add(f.magic, buffer(0, MAGIC_LEN))

  -- Inner Protocol header (ptype/len/times)
  local ptype = buffer(PTYPE_OFF,1):uint()
  subtree:add(f.ptype, buffer(PTYPE_OFF,1))

  local plen = buffer(PLEN_OFF,2):uint()
  subtree:add(f.plen, buffer(PLEN_OFF,2))

  subtree:add(f.h_tx,   buffer(H_TX_OFF, 8))
  subtree:add(f.h_echo, buffer(H_EC_OFF, 8))

  -- Inner payload (may be empty for IDLE)
  if not in_range(PAYLOAD_OFF, plen, buffer) then
    pinfo.cols.info = string.format("Truncated inner payload (plen=%u)", plen)
    return
  end

  local payload_tvb = buffer(PAYLOAD_OFF, plen)
  local paytree = subtree:add(payload_tvb, "Inner Payload")

  if ptype == PTYPE_IDLE then
    pinfo.cols.info = "IDLE"
    return

  elseif ptype == PTYPE_DATA then
    if plen < DATA_FIXED then return end

    local ctr       = payload_tvb(0,2):uint()
    local frame_t   = payload_tvb(2,1):uint()
    local len_off   = payload_tvb(3,2):uint()
    local chunk_len = payload_tvb(5,2):uint()

    if (7 + chunk_len) > plen then return end

    paytree:add(f.counter,  payload_tvb(0,2))
    paytree:add(f.frame_t,  payload_tvb(2,1))
    paytree:add(f.len_off,  payload_tvb(3,2))
    paytree:add(f.chunklen, payload_tvb(5,2))
    if chunk_len > 0 then
      paytree:add(f.payload, payload_tvb(7, chunk_len))
    end

    pinfo.cols.info = string.format(
      "DATA cnt=%u type=0x%02X len/off=%u chunk=%u",
      ctr, frame_t, len_off, chunk_len
    )

  elseif ptype == PTYPE_CONTROL then
    if plen < CTL_FIXED_BASE then return end

    local last = payload_tvb(0,2):uint()
    local high = payload_tvb(2,2):uint()
    local mcnt = payload_tvb(4,2):uint()

    paytree:add(f.ctl_last, payload_tvb(0,2))
    paytree:add(f.ctl_high, payload_tvb(2,2))
    paytree:add(f.ctl_mcnt, payload_tvb(4,2))

    local missed_end = 6 + 2 * mcnt
    if missed_end > plen then return end

    for i = 0, mcnt - 1 do
      local off = 6 + 2*i
      paytree:add(f.ctl_missed, payload_tvb(off, 2))
    end

    pinfo.cols.info = string.format(
      "CONTROL last=%u highest=%u missed=%u", last, high, mcnt
    )

  else
    pinfo.cols.info = string.format("Unknown ptype=0x%02X", ptype)
  end
end

-- --------------------------
-- Port binding
-- --------------------------
local udp_table = DissectorTable.get("udp.port")
udp_table:add(443, p)    -- default overlay port
udp_table:add(40001, p)  -- commonly used alternate port
