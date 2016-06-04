local pcie_proto = Proto("PCIe", "PCI Express Transport Layer Packet with UDP encapslation")

-- Timestamp header: Byte 6
--
-- 15               7             0
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- | Ver |Dir|Rsrvd|               |
-- +-+-+-+-+-+-+-+-+               |
-- |           Timestamp           |
-- |                               |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Version:3bit, default:0
-- Direction:2bit, Host->Dev:00 Dev->Host:01
-- Reserved:3bit, default:0
-- Timestamp:40bit, default:0, Clock_source:PCIe_clock(4ns)
-- 
local cap_ver    = ProtoField.new("Protocol Version", "pcie_proto.version", ftypes.UINT8, nil, base.HEX)
local cap_pktdir = ProtoField.new("Packet Direction", "pcie_proto.pktdir", ftypes.UINT8, nil, base.HEX)
local cap_rsvd   = ProtoField.new("Reserved", "pcie_proto.reserved", ftypes.UINT8, nil, base.HEX)
local cap_ts     = ProtoField.new("Timestamp", "pcie_proto.timestamp", ftypes.BYTES)

pcie_proto.fields = { cap_version,
                      cap_packet_direction,
                      cap_reserved,
                      cap_timestamp }

function pcie_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "PCIe"
	local subtree = tree:add(pcie_proto, buffer(), "My Protocol Data (" .. buffer:len() .. ")")
	subtree:add(cap_ver,    buffer(0,1), buffer(0,1):bitfield(0,3))
	subtree:add(cap_pktdir, buffer(0,1), buffer(0,1):bitfield(3,2))
	subtree:add(cap_rsvd,   buffer(0,1), buffer(0,1):bitfield(5,3))
	subtree:add(cap_ts,     buffer(1,5))
end

DissectorTable.get("udp.port"):add(14198, pcie_proto)

