-- create myproto protocol and its fields
p_mmdvm = Proto ("mmdvm","MMDVM")

local FRAMETYPE = {[0x18] = "DMR DATA1", 
		[0x19] = "DMR LOST1", 
		[0x1A] = "DMR DATA2", 
		[0x1B] = "DMR LOST2", 
                [0x1C] = "DMR SHORTLC", 
		[0x1D] = "DMR START", 
		[0x1E] = "DMR ABORT"}

local DATATYPE = { [0x0] = "PI Header",
		[0x01] = "Voice LC Header",
		[0x02] = "Terminator with LC",
		[0x03] = "CSBK",
		[0x04] = "MBC Header",
		[0x05] = "MBC Continuation",
		[0x06] = "Data Header",
		[0x07] = "Rate 1/2 Data",
		[0x08] = "Rate 3/4 Data",
		[0x09] = "Idle",
		[0x0A] = "Rate 1 Data",
		[0x0B] = "Reserved",
		[0x0C] = "Reserved",
		[0x0D] = "Reserved",
		[0x0E] = "Reserved",
		[0x0F] = "Reserved"}

local f_fstart = ProtoField.uint8("mmdvm.fstart", "FrameStart", base.HEX)
local f_len = ProtoField.uint8("mmdvm.len", "Length", base.DEC)
local f_type = ProtoField.uint8("mmdvm.type", "Type", base.HEX, FRAMETYPE)
local f_Slot = ProtoField.uint8("mmdvm.Slot", "Slot", base.DEC, nil, 0x80)
local f_dsync = ProtoField.uint8("mmdvm.dsync", "DSync", base.DEC, nil, 0x40)
local f_async = ProtoField.uint8("mmdvm.async", "ASync", base.DEC, nil, 0x20)
local f_dtype = ProtoField.uint8("mmdvm.dtype", "DType", base.HEX, DATATYPE, 0x0F)
local f_data = ProtoField.string("mmdvm.data", "Data", FT_STRING)
  
p_mmdvm.fields = {f_fstart, f_len, f_type, f_Slot, f_dsync, f_async, f_dtype, f_dmrdata}
   
 -- myproto dissector function
function p_mmdvm.dissector (buf, pkt, root)
   -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_mmdvm.name
  subtree = root:add(p_mmdvm, buf(0))
  subtree:add(f_fstart, buf(0,1))
  subtree:add(f_len, buf(1,1))
  subtree:add(f_type, buf(2,1))
  subtree:add(f_Slot, buf(3,1))
  subtree:add(f_dsync, buf(3,1))
  subtree:add(f_async, buf(3,1))

  Dissector.get("dmr"):call(buf(4):tvb(), pkt, root)
end
                        
function p_mmdvm.init()
end
                         
print( (require 'debug').getinfo(1).source )
local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, p_mmdvm)


