print("SELECTOR624_BASELINE_BEGIN_20261018")
if type(syscall) ~= "table" or type(syscall.pipe) ~= "table" then
 print("WRAPPER_UNAVAILABLE")
 return
end
local q = {}
for k,v in pairs(syscall.pipe) do q[k]=v end
q.syscall_no=624
setmetatable(q,getmetatable(syscall.pipe))
for i=1,3 do
 print("CALL_START",i)
 local ok,v=pcall(function() return q() end)
 if not ok then print("CALL_ERROR",i,tostring(v)); return end
 if type(v)=="table" and type(v.h)=="number" and type(v.l)=="number" then
  print("CALL_RETURN",i,string.format("0x%08X_%08X",v.h,v.l))
 elseif type(v)=="number" or type(v)=="string" then
  print("CALL_RETURN",i,type(v),tostring(v))
 else print("CALL_RETURN_UNDECODED",i,type(v)) end
end
print("SELECTOR624_BASELINE_END_20261018")
return
