print("SELECTOR624_WRAPPER_BEGIN_20261018")
print("RUNTIME",_VERSION)
if type(syscall)~="table" then print("NO_SYSCALL_TABLE");return end
local base=rawget(syscall,"pipe")
print("BASE_TYPE",type(base))
if type(base)~="table" then return end
local mt=getmetatable(base)
print("METATABLE_TYPE",type(mt))
if type(mt)~="table" then return end
print("CALL_FIELD_TYPE",type(rawget(mt,"__call")))
local q={}
for k,v in pairs(base) do q[k]=v end
q.syscall_no=624
setmetatable(q,mt)
for i=1,3 do
 print("CALL_START",i,"RECORDED_SELECTOR",rawget(q,"syscall_no"))
 local ok,v=pcall(function() return q() end)
 if not ok then print("CALL_ERROR",i,tostring(v));return end
 print("RETURN_TYPE",i,type(v))
 if type(v)=="table" then
  local h,l=rawget(v,"h"),rawget(v,"l")
  print("FIELD_TYPES",i,type(h),type(l))
  if type(h)=="number" and type(l)=="number" then print("CALL_RETURN",i,string.format("0x%08X_%08X",h,l)) end
 elseif type(v)=="number" or type(v)=="string" then print("CALL_RETURN",i,tostring(v)) end
end
print("SELECTOR624_WRAPPER_END_20261018")
return
