p_mmdvm = Proto ("mmdvm","MMDVM")

local COMMAND = {
        [0x00] = "VERSION",
        [0x01] = "STATUS",
        [0x02] = "CONFIG",
        [0x03] = "MODE",
        [0x04] = "FREQUENCY",
        [0x0A] = "CWID",
        
        [0x10] = "D-STAR HEADER",
        [0x11] = "D-STAR DATA",
        [0x12] = "D-STAR LOST",
        [0x13] = "D-STAR EOT",
        
        [0x18] = "DMR DATA1", 
		[0x19] = "DMR LOST1", 
		[0x1A] = "DMR DATA2", 
		[0x1B] = "DMR LOST2", 
        [0x1C] = "DMR SHORTLC", 
		[0x1D] = "DMR START", 
		[0x1E] = "DMR ABORT",

        [0x20] = "YSF DATA",
        [0x21] = "YSF LOST",

        [0x30] = "P25 HEADER",
        [0x31] = "P25 LDU",
        [0x32] = "P25 LOST",
        
        [0x70] = "ACK",
        [0x71] = "NAK",
        [0x80] = "SERIAL",
        
        [0xF1] = "DEBUG1",
        [0xF2] = "DEBUG2",
        [0xF3] = "DEBUG3",
        [0xF4] = "DEBUG4",
        [0xF5] = "DEBUG5"        
        }

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
local f_Command = ProtoField.uint8("mmdvm.Command", "Command", base.HEX, COMMAND)
local f_Slot = ProtoField.uint8("mmdvm.Slot", "Slot", base.DEC, nil, 0x80)
local f_dsync = ProtoField.uint8("mmdvm.dsync", "DSync", base.DEC, nil, 0x40)
local f_async = ProtoField.uint8("mmdvm.async", "ASync", base.DEC, nil, 0x20)
local f_dtype = ProtoField.uint8("mmdvm.dtype", "DType", base.HEX, DATATYPE, 0x0F)
local f_seq = ProtoField.uint8("mmdvm.seq", "Seq", base.HEX, nil, 0x0F)
local f_data = ProtoField.string("mmdvm.data", "Data", FT_STRING)
local f_rxf = ProtoField.uint32("mmdvm.rxf", "RX Freq", base.DEC)
local f_txf = ProtoField.uint32("mmdvm.txf", "TX Freq", base.DEC)

-- Generic MMDVM Commands and Responses
local f_Cmd = ProtoField.uint8("mmdvm.Cmd", "CMD", base.HEX, COMMAND)
local f_Reaspm = ProtoField.uint8("mmdvm.Reason", "Reason", base.HEX)
local f_pversion = ProtoField.uint8("mmdvm.pversion", "Protocol Version", base.HEX)
local f_verstr = ProtoField.string("mmdvm.verstr", "Hardware Version", FT_STRING)
  
p_mmdvm.fields = {f_fstart, f_len, f_Command, f_Slot, f_dsync, f_async, f_dtype, f_dmrdata, f_seq, 
  f_Cmd, f_Reason, f_pversion, f_verstr, f_rxf, f_txf
  }

local fstart_Field = Field.new("mmdvm.fstart")
local Command_Field = Field.new("mmdvm.Command")
local dsync_Field = Field.new("mmdvm.dsync")
local async_Field = Field.new("mmdvm.async")
local dtype_Field = Field.new("mmdvm.dtype")
local seq_Field = Field.new("mmdvm.seq")
local len_Field = Field.new("mmdvm.len")
   
 -- myproto dissector function
function p_mmdvm.dissector (buf, pinfo, root)
   -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
 
  -- Check N3UC addition of RX/TX Flag on Frame Start
  local RXTX = buf(0,1):uint() == 0xE1 

  subtree = root:add(p_mmdvm, buf(0))
  subtree:add(f_fstart, buf(0,1)) 
  
  pinfo.cols.protocol:append(p_mmdvm.name)
  if RXTX == true then
    pinfo.cols.protocol:append(" TX ")
  else
    pinfo.cols.protocol:append(" RX ")  
  end

  subtree:add(f_len, buf(1,1))
  local Length = len_Field().value;
  
  subtree:add(f_Command, buf(2,1)) 
  local Command = Command_Field().value
  
  -- ACK
  if Command == 0x70 then
    subtree:add(f_Cmd, buf(3,1))   
    pinfo.cols.info:append("ACK Command " .. buf(3,1) )
  elseif Command == 0x7F then
    subtree:add(f_Cmd, buf(3,1))   
    subtree:add(f_Reason, buf(4,1))   
    pinfo.cols.info:append("NAK Command " .. buf(3,1) .. " Reason " .. buf(4,1) )
  elseif Command == 0x00 then
    pinfo.cols.info:append("Version ")
    if Length >= 4 then
      subtree:add(f_pversion, buf(3,1))     
      subtree:add(f_verstr, buf(4, Length - 4))
    end
  elseif Command == 0x01 then
    pinfo.cols.info:append("Status ")
  elseif Command == 0x02 then
    pinfo.cols.info:append("Config ")
  elseif Command == 0x03 then
    pinfo.cols.info:append("Mode ")
  elseif Command == 0x04 then
    pinfo.cols.info:append("Frequency ")
    subtree:add_le(f_rxf, buf(4,4))         
    subtree:add_le(f_txf, buf(8,4))         
  end
  
  -- DMR
  if Command >= 0x18 and Command <= 0x1E then
    subtree:add(f_Slot, buf(3,1))
    subtree:add(f_dsync, buf(3,1))
    subtree:add(f_async, buf(3,1))
  
    -- Check for DataSync and Decode low nibble
    if dsync_Field().value == 1 then
      subtree:add(f_dtype, buf(3,1))
      local dt = dtype_Field().value
      pinfo.cols.info:append("Data SYNC " .. tostring( DATATYPE[dt] ))
    elseif async_Field().value == 1 then
      pinfo.cols.info:append("Voice SYNC ")
    else
      subtree:add(f_seq, buf(3,1))
      pinfo.cols.info:append("Seq " .. tostring(seq_Field().value) .. " ")  
    end

    Dissector.get("dmr"):call(buf(4):tvb(), pinfo, root)
  end
end
                        
function p_mmdvm.init()
end
                         
print( (require 'debug').getinfo(1).source )
local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, p_mmdvm)


