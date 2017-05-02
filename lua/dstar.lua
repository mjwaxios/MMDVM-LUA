local dstar = Proto("dstar", "DStar Protocol")
   
function dstar.dissector(tvbuf,pinfo,root)
    pinfo.cols.protocol:append("DStar ")
end

print( (require 'debug').getinfo(1).source )

