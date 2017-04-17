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

local MODE = {
        [00] = "IDLE",
        [01] = "IDLE",
        [02] = "IDLE",
        [03] = "IDLE",
        [04] = "IDLE",
        [98] = "CW",
        [99] = "LOCKOUT",
        [100] = "ERROR",        
}
        
p_mmdvm.fields.f_fstart = ProtoField.uint8("mmdvm.fstart", "FrameStart", base.HEX)
p_mmdvm.fields.f_len = ProtoField.uint8("mmdvm.len", "Length", base.DEC)
p_mmdvm.fields.f_Command = ProtoField.uint8("mmdvm.Command", "Command", base.HEX, COMMAND)
p_mmdvm.fields.f_Slot = ProtoField.uint8("mmdvm.Slot", "Slot", base.DEC, nil, 0x80)
p_mmdvm.fields.f_dsync = ProtoField.uint8("mmdvm.dsync", "DSync", base.DEC, nil, 0x40)
p_mmdvm.fields.f_async = ProtoField.uint8("mmdvm.async", "ASync", base.DEC, nil, 0x20)
p_mmdvm.fields.f_dtype = ProtoField.uint8("mmdvm.dtype", "DType", base.HEX, DATATYPE, 0x0F)
p_mmdvm.fields.f_seq = ProtoField.uint8("mmdvm.seq", "Seq", base.HEX, nil, 0x0F)
p_mmdvm.fields.f_data = ProtoField.string("mmdvm.data", "Data", FT_STRING)
p_mmdvm.fields.f_rxf = ProtoField.uint32("mmdvm.rxf", "RX Freq", base.DEC)
p_mmdvm.fields.f_txf = ProtoField.uint32("mmdvm.txf", "TX Freq", base.DEC)

-- Generic MMDVM Commands and Responses
p_mmdvm.fields.f_Cmd = ProtoField.uint8("mmdvm.Cmd", "CMD", base.HEX, COMMAND)
p_mmdvm.fields.f_Reaspm = ProtoField.uint8("mmdvm.Reason", "Reason", base.HEX)
p_mmdvm.fields.f_pversion = ProtoField.uint8("mmdvm.pversion", "Protocol Version", base.HEX)
p_mmdvm.fields.f_verstr = ProtoField.string("mmdvm.verstr", "Hardware Version", FT_STRING)

p_mmdvm.fields.f_flags = ProtoField.uint16("mmdvm.flags", "Config Flags", base.HEX)
p_mmdvm.fields.f_rxi = ProtoField.uint16("mmdvm.rxi", "RX Invert", base.HEX, nil, 0x0100)
p_mmdvm.fields.f_txi = ProtoField.uint16("mmdvm.txi", "TX Invert", base.HEX, nil, 0x0200)
p_mmdvm.fields.f_ptti = ProtoField.uint16("mmdvm.ptti", "PTT Invert", base.HEX, nil, 0x0400)
p_mmdvm.fields.f_ysfLoDev = ProtoField.uint16("mmdvm.ysfLoDev", "YSF Low Dev", base.HEX, nil, 0x0800)
p_mmdvm.fields.f_duplex = ProtoField.uint16("mmdvm.duplex", "Duplex", base.HEX, nil, 0x8000)

p_mmdvm.fields.f_dstaren= ProtoField.uint16("mmdvm.dstaren", "DStar Enable", base.HEX, nil, 0x0001)
p_mmdvm.fields.f_dmren= ProtoField.uint16("mmdvm.dmren", "DMR Enable", base.HEX, nil, 0x0002)
p_mmdvm.fields.f_ysfen= ProtoField.uint16("mmdvm.ysfen", "YSF Enable", base.HEX, nil, 0x0004)
p_mmdvm.fields.f_p25en= ProtoField.uint16("mmdvm.p25en", "P25 Enable", base.HEX, nil, 0x0008)
 
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
  if buf:len() < 3 then return end
 
  -- Check N3UC addition of RX/TX Flag on Frame Start
  -- a StartFrame of 0xE0 means the modem heard it and is sending it the serial port
  -- a StartFrame of 0XE1 means the serial port sent the frame to the modem to transmit
  local RXTX = buf(0,1):uint() == 0xE1 

  subtree = root:add(p_mmdvm, buf(0))
  subtree:add(p_mmdvm.fields.f_fstart, buf(0,1)) 
  
  pinfo.cols.protocol:append(p_mmdvm.name)
  if RXTX then
    pinfo.cols.protocol:append(" TX ")
  else
    pinfo.cols.protocol:append(" RX ")  
  end

  subtree:add(p_mmdvm.fields.f_len, buf(1,1))
  local Length = len_Field().value;
  
  subtree:add(p_mmdvm.fields.f_Command, buf(2,1)) 
  local Command = Command_Field().value
  
  -- ACK
  if Command == 0x70 then
    subtree:add(p_mmdvm.fields.f_Cmd, buf(3,1))   
    pinfo.cols.info:append("ACK Command " .. buf(3,1) )
  elseif Command == 0x7F then
    subtree:add(p_mmdvm.fields.f_Cmd, buf(3,1))   
    subtree:add(p_mmdvm.fields.f_Reason, buf(4,1))   
    pinfo.cols.info:append("NAK Command " .. buf(3,1) .. " Reason " .. buf(4,1) )
  elseif Command == 0x00 then
    pinfo.cols.info:append("Version ")
    if Length >= 4 then
      subtree:add(p_mmdvm.fields.f_pversion, buf(3,1))     
      subtree:add(p_mmdvm.fields.f_verstr, buf(4, Length - 4))
    end
  elseif Command == 0x01 then
    pinfo.cols.info:append("Status ")
    if not RXTX then
      flags = subtree:add("Enabled Modes")     
        flags:add(p_mmdvm.fields.f_p25en, buf(3,1))     
        flags:add(p_mmdvm.fields.f_ysfen, buf(3,1))     
        flags:add(p_mmdvm.fields.f_dmren, buf(3,1))     
        flags:add(p_mmdvm.fields.f_dstaren, buf(3,1))         
    
      subtree:add(buf(4,1), "Modem State: " .. MODE[buf(4,1):uint()])     
      if (buf(5,1):uint() == 1) then
        subtree:add(buf(5,1), "Radio Mode            : Transmitting")
      else
        subtree:add(buf(5,1), "Radio Mode            : Receiving")
      end
      
      subtree:add(buf(6,1), "DStar Buffer Size     : " .. buf(6,1):uint())
      subtree:add(buf(7,1), "DMR Slot 1 Buffer Size: " .. buf(7,1):uint())
      subtree:add(buf(8,1), "DMR Slot 2 Buffer Size: " .. buf(8,1):uint())
      subtree:add(buf(9,1), "YSF Buffer Size       : " .. buf(9,1):uint())          
    end  

  elseif Command == 0x02 then
    pinfo.cols.info:append("Config ")
    flags = subtree:add(p_mmdvm.fields.f_flags, buf(3,2))     
      flags:add(p_mmdvm.fields.f_duplex, buf(3,2))     
      flags:add(p_mmdvm.fields.f_ysfLoDev, buf(3,2))     
      flags:add(p_mmdvm.fields.f_ptti, buf(3,2))     
      flags:add(p_mmdvm.fields.f_txi, buf(3,2))     
      flags:add(p_mmdvm.fields.f_rxi, buf(3,2))        
      flags:add(p_mmdvm.fields.f_p25en, buf(3,2))     
      flags:add(p_mmdvm.fields.f_ysfen, buf(3,2))     
      flags:add(p_mmdvm.fields.f_dmren, buf(3,2))     
      flags:add(p_mmdvm.fields.f_dstaren, buf(3,2))     
    subtree:add(buf(5,1), "TX Delay: " .. buf(5,1):uint() * 10 .. " ms")     
    subtree:add(buf(6,1), "Init Mode: " .. buf(6,1))     
    subtree:add(buf(7,1), "RX Level: " .. buf(7,1):uint() * 100 / 255)     
    subtree:add(buf(8,1), "CDID Level: " .. buf(8,1):uint() * 100 / 255)     
    subtree:add(buf(9,1), "DMR Color Code: " .. buf(9,1))     
    subtree:add(buf(10,1), "DMR Delay: " .. buf(10,1))     
    subtree:add(buf(11,1), "reserved: " .. buf(11,1))     
    subtree:add(buf(12,1), "DStar TX Level: " .. buf(12,1):uint() * 100 / 255 )     
    subtree:add(buf(13,1), "DMR TX Level: " .. buf(13,1):uint() * 100 / 255 )     
    subtree:add(buf(14,1), "YSF TX Level: " .. buf(14,1):uint() * 100 / 255 )     
    subtree:add(buf(15,1), "P25 TX Level: " .. buf(15,1):uint() * 100 / 255 )     
    
  elseif Command == 0x03 then
    pinfo.cols.info:append("Mode ")
    subtree:add(buf(3,1), "Mode: " .. MODE[buf(3,1):uint()])     
    pinfo.cols.info:append(MODE[buf(3,1):uint()])    
  elseif Command == 0x04 then
    pinfo.cols.info:append("Frequency ")
    subtree:add_le(p_mmdvm.fields.f_rxf, buf(4,4))         
    subtree:add_le(p_mmdvm.fields.f_txf, buf(8,4))         
  end
  
  -- DMR
  if Command >= 0x18 and Command <= 0x1E then
    subtree:add(p_mmdvm.fields.f_Slot, buf(3,1))
    subtree:add(p_mmdvm.fields.f_dsync, buf(3,1))
    subtree:add(p_mmdvm.fields.f_async, buf(3,1))
  
    if not RXTX then
      -- Check for DataSync and Decode low nibble
      if dsync_Field().value == 1 then
        subtree:add(p_mmdvm.fields.f_dtype, buf(3,1))
        local dt = dtype_Field().value
        pinfo.cols.info:append("Data SYNC " .. tostring( DATATYPE[dt] ))
      elseif async_Field().value == 1 then
        pinfo.cols.info:append("Voice SYNC ")
      else
        subtree:add(p_mmdvm.fields.f_seq, buf(3,1))
        pinfo.cols.info:append("Seq " .. tostring(seq_Field().value) .. " ")  
      end
    end  

    Dissector.get("dmr"):call(buf(4):tvb(), pinfo, root)
  end
end
                        
function p_mmdvm.init()
end
                         
print( (require 'debug').getinfo(1).source )
local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, p_mmdvm)


