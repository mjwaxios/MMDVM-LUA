-- create myproto protocol and its fields
p_mmdvm = Proto ("mmdvm","MMDVM")

local DATATYPE = {[0x18] = "DATA1", [0x19] = "LOST1", [0x1A] = "DATA2", [0x1B] = "LOST2", 
                  [0x1C] = "SHORTLC", [0x1D] = "START", [0x1E] = "ABORT"}


local f_fstart = ProtoField.uint8("mmdvm.fstart", "FrameStart", base.HEX)
local f_len = ProtoField.uint8("mmdvm.len", "Length", base.HEX)
local f_type = ProtoField.uint8("mmdvm.type", "Type", base.HEX, DATATYPE)
local f_Slot = ProtoField.uint8("mmdvm.Slot", "Slot", base.DEC, nil, 0x80)
local f_dsync = ProtoField.uint8("mmdvm.dsync", "DSync", base.DEC, nil, 0x40)
local f_async = ProtoField.uint8("mmdvm.async", "ASync", base.DEC, nil, 0x20)
local f_dtype = ProtoField.uint8("mmdvm.dtype", "DType", base.HEX, nil, 0x0F)
local f_data = ProtoField.string("mmdvm.data", "Data", FT_STRING)
  
p_mmdvm.fields = {f_fstart, f_len, f_type, f_Slot, f_dsync, f_async, f_dtype}
   
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
  subtree:add(f_dtype, buf(3,1))

--  subtree:append_text(", Data ")
end
                        
 -- Initialization routine
function p_mmdvm.init()
end
                         
      -- register a chained dissector for port 8002
print( (require 'debug').getinfo(1).source )

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, p_mmdvm)


