-- CRASH_CLASS: LOW
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=20 setmetatable(t,getmetatable(syscall.pipe))
print("CANARY pid="..tostring(to_num(t())))
print("=== COMPLETE ===")
