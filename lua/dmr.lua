local dmr = Proto("dmr", "DMR Protocol")

local pf_sync_bytes = ProtoField.new(
    "Sync Bytes",
    "dmr.sync_bytes",
    ftypes.BYTES
)
local pf_sync_type = ProtoField.new(
    "Sync Type",
    "dmr.sync_type",
    ftypes.STRING
)
local pf_sync_val = ProtoField.new(
    "Sync VAL",
    "dmr.sync_val",
    ftypes.UINT64,
    nil,
    base.HEX
)

dmr.fields = {
    pf_sync_bytes,
    pf_sync_type,
    pf_sync_val
}

BitArray = {}
BitArray.__index = BitArray

function BitArray.new(bytearray)
    local bitarray = {}
    for i = 1, bytearray:len() do
        local b = bytearray:get_index(i-1)
        for j = 1, 8 do 
            local x = bit.rshift(bit.band(b, 0x80), 7)
            b = bit.lshift(b, 1)
            bitarray[#bitarray+1] = x
        end
    end
    return bitarray
end
    
function bitarray_tostring(bitarray)
    s = ""
    for i = 1, #bitarray do
        s = s .. tostring(bitarray[i])
    end
    return s
end

function extract_info_bits(payload_bits)
    local info_bits = {}
    for i = 1, 98 do
        info_bits[#info_bits + 1] = payload_bits[i]
    end
    for i = 166, 264 do
        info_bits[#info_bits + 1] = payload_bits[i]
    end
    return info_bits
end

function bptc_deinterleave(info_bits)
    local deint_bits = {}
    for i = 1, 196 do
        local j = (i * 181) % 196
        deint_bits[#deint_bits + 1] = info_bits[j]
    end
    return deint_bits
end

function extract_data(deint_bits)
    local data_bits = {}
    for i = 5, 12 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 17, 27 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 32, 42 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 47, 57 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 62, 72 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 77, 87 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 92, 102 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 107, 117 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    for i = 122, 132 do
        data_bits[#data_bits+1] = deint_bits[i]
    end
    return data_bits
end
    
function dmr.dissector(tvbuf,pktinfo,root)
    pktinfo.cols.protocol:set("DMR")

    local pktlen = tvbuf:reported_length_remaining()

    local subtree = root:add(dmr, tvbuf(0,pktlen))

    if pktlen < 33 then
        return
    end
    
    local payload_bits = BitArray.new(tvbuf(0,33):bytes())
    local info_bits = extract_info_bits(payload_bits)
    local deint_bits = bptc_deinterleave(info_bits)
    -- TODO bptc correct
    local data_bits = extract_data(deint_bits)
    print(#data_bits)
    print(bitarray_tostring(data_bits))

    -- get the value of the sync as a UInt64
    local sync_value = tvbuf(13,7):bitfield(4, 48)
    subtree:add(
        pf_sync_val,
	    sync_value
    )

    -- TODO instead of equality comparison, mask the
    --      sync against all known patterns and accept
    --      them if they have TBD or fewer bit differences
    --
    -- TODO support the other sync patterns
    --
    -- TODO if we are in a voice super-frame the sync type
    --      will simply be a counter
    if sync_value == UInt64(0xf77fd757, 0x0000d5d7) then
        subtree:add(
	    pf_sync_type,
	    "MS_D"
	)
    else
        subtree:add(
	    pf_sync_type,
	    "UNK"
	)
    end 

    -- this is a really crude way to strip out the
    -- sync pattern which starts at the 13.5th byte
    -- and it 6 bytes long, yet still display it 
    -- as a BYTES field
    local sync_bytes = ByteArray.new(
        tvbuf(13,7):bytes():tohex():sub(2, -2)
    )
    subtree:add(
        pf_sync_bytes,
	ByteArray.tvb(sync_bytes, "sync_bytes")(0,6)
    )

    return 33
end

local wtap_encap_table = DissectorTable.get("wtap_encap")

wtap_encap_table:add(wtap.USER0, dmr)

print( (require 'debug').getinfo(1).source )

