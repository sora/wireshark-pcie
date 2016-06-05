local pcie_proto = Proto("PCIe", "PCI Express Transport Layer Packet")

local f = pcie_proto.fields

-- PCIe TLP capture header: Byte 6
--  2               1             0B
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
f.tcap_ver    = ProtoField.new("Version", "pcie.tcap.version", ftypes.UINT8, nil, base.DEC)
f.tcap_pktdir = ProtoField.new("Packet Direction", "pcie.tcap.packet_direction", ftypes.UINT8, nil, base.HEX)
f.tcap_rsvd   = ProtoField.new("Reserved", "pcie.tcap.reserved", ftypes.UINT8, nil, base.NONE)
f.tcap_ts     = ProtoField.new("Timestamp", "pcie.tcap.timestamp", ftypes.BYTES)


-- PCI Express TLP 3DW Header:
-- |       0       |       1       |       2       |       3       |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |R|FMT|   Type  |R| TC  |   R   |T|E|Atr| R |       Length      |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |           Request ID          |      Tag      |LastBE |FirstBE|
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |                           Address                         | R |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
f.tlp_rsvd0   = ProtoField.new("Reserved0", "pcie.tlp.reserved0", ftypes.UINT8, nil, base.NONE)
-- f.tlp_fmt     = ProtoField.new("Packet Format", "pcie.tlp.format", ftypes.UINT8, nil, base.HEX)
local TLPPacketFormat = {
	[0] = "MRd_3DW_NO_DATA",
	[1] = "MRd_4DW_NO_DATA",
	[2] = "MWr_3DW_DATA",
	[3] = "MWr_4DW_DATA"
}
f.tlp_fmt = ProtoField.uint8("pcie.tlp.format", "Packet Format", base.DEC, TLPPacketFormat)

-- f.tlp_type    = ProtoField.new("Packet Type", "pcie.tlp.pkttype", ftypes.UINT8, nil, base.HEX)
local TLPPacketType = {
	[ 0] = "MEMORY_RW",
	[ 4] = "Cfg0_RW",
	[10] = "Cpl"
}
f.tlp_type = ProtoField.uint8("pcie.tlp.pkttype", "Packet Type", base.DEC, TLPPacketType)

f.tlp_rsvd1   = ProtoField.new("Reserved1", "pcie.tlp.reserved1", ftypes.UINT8, nil, base.NONE)
f.tlp_tclass  = ProtoField.new("Tclass", "pcie.tlp.tclass", ftypes.UINT8, nil, base.HEX)
f.tlp_rsvd2   = ProtoField.new("Reserved2", "pcie.tlp.reserved2", ftypes.UINT8, nil, base.NONE)
f.tlp_digest  = ProtoField.new("Digest", "pcie.tlp.digest", ftypes.UINT8, nil, base.HEX)
f.tlp_poison  = ProtoField.new("Poison", "pcie.tlp.poison", ftypes.UINT8, nil, base.HEX)
f.tlp_attr    = ProtoField.new("Attr", "pcie.tlp.attr", ftypes.UINT8, nil, base.HEX)
f.tlp_rsvd3   = ProtoField.new("Reserved3", "pcie.tlp.reserved3", ftypes.UINT8, nil, base.NONE)
f.tlp_length  = ProtoField.new("Length", "pcie.tlp.length", ftypes.UINT8, nil, base.HEX)
f.tlp_reqid   = ProtoField.new("Request ID", "pcie.tlp.reqid", ftypes.UINT8, nil, base.HEX)
f.tlp_tag     = ProtoField.new("Tag", "pcie.tlp.tag", ftypes.UINT8, nil, base.HEX)
f.tlp_lastbe  = ProtoField.new("LastBE", "pcie.tlp.lastbe", ftypes.UINT8, nil, base.HEX)
f.tlp_firstbe = ProtoField.new("FirstBE", "pcie.tlp.firstbe", ftypes.UINT8, nil, base.HEX)
f.tlp_addr    = ProtoField.new("Address", "pcie.tlp.addr", ftypes.UINT8, nil, base.HEX)
f.tlp_rsvd4   = ProtoField.new("Reserved4", "pcie.tlp.reserved4", ftypes.UINT8, nil, base.NONE)

function pcie_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "PCIe TLP"
	local subtree = tree:add(pcie_proto, buffer(0, buffer:len()))

	local tcap_subtree = subtree:add("TLP Capture Header", buffer(0,6))
	tcap_subtree:add(f.tcap_ver,    buffer(0,1), buffer(0,1):bitfield(0,3))
	tcap_subtree:add(f.tcap_pktdir, buffer(0,1), buffer(0,1):bitfield(3,2))
	tcap_subtree:add(f.tcap_rsvd,   buffer(0,1), buffer(0,1):bitfield(5,3))
	tcap_subtree:add(f.tcap_ts,     buffer(1,5))

	local tlp_subtree = subtree:add("Transaction Layer Packet", buffer(6, buffer:len()-6))
	tlp_subtree:add(f.tlp_rsvd0,   buffer( 6,1):bitfield(0, 1))
	tlp_subtree:add(f.tlp_fmt,     buffer( 6,1):bitfield(0, 2))
	tlp_subtree:add(f.tlp_type,    buffer( 6,1):bitfield(0, 5))
	tlp_subtree:add(f.tlp_rsvd1,   buffer( 7,1):bitfield(0, 1))
	tlp_subtree:add(f.tlp_tclass,  buffer( 7,1):bitfield(0, 3))
	tlp_subtree:add(f.tlp_rsvd2,   buffer( 7,1):bitfield(0, 4))
	tlp_subtree:add(f.tlp_digest,  buffer( 8,1):bitfield(0, 1))
	tlp_subtree:add(f.tlp_poison,  buffer( 8,1):bitfield(0, 1))
	tlp_subtree:add(f.tlp_attr,    buffer( 8,1):bitfield(0, 2))
	tlp_subtree:add(f.tlp_rsvd3,   buffer( 8,1):bitfield(0, 2))
	tlp_subtree:add(f.tlp_length,  buffer( 8,2):bitfield(0,10))
	tlp_subtree:add(f.tlp_reqid,   buffer(10,2):bitfield(0,16))
	tlp_subtree:add(f.tlp_tag,     buffer(12,1):bitfield(0, 8))
	tlp_subtree:add(f.tlp_lastbe,  buffer(13,1):bitfield(0, 4))
	tlp_subtree:add(f.tlp_firstbe, buffer(13,1):bitfield(0, 4))
	tlp_subtree:add(f.tlp_addr,    buffer(14,4):bitfield(0,30))
	tlp_subtree:add(f.tlp_rsvd4,   buffer(17,1):bitfield(0, 2))

end


DissectorTable.get("udp.port"):add(14198, pcie_proto)

