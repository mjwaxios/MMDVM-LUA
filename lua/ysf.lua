local ysf = Proto("ysf", "YSF Protocol")
   
function ysf.dissector(tvbuf,pinfo,root)
    pinfo.cols.protocol:append("YSF ")
end

print( (require 'debug').getinfo(1).source )

