-- CRASH_CLASS: HIGH
-- PROBE 630a: does the loader's kernel.read_qword have a working backend on 14.10?
print("=== PROBE 630a: KERNEL READ API ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local ok,a=pcall(function() return kernel.addr end)
print(string.format("[A] kernel.addr=%s ok=%s",tostring(ok and a or "err"),tostring(ok)))
local ok2,s=pcall(function() return kernel_offset and kernel_offset.SIZEOF_OFILES end)
print(string.format("[B] SIZEOF_OFILES=%s",tostring(ok2 and s or "err")))
local ok3,v=pcall(function() return kernel.read_qword(uint64(0xffffffff8a9c0000)) end)
print(string.format("[C] read kernel base -> %s (ok=%s)",tostring(ok3 and v or "err"),tostring(ok3)))
local ok4,v4=pcall(function() return kernel.read_dword(uint64(0)) end)
print(string.format("[D] read 0 -> %s (ok=%s)",tostring(ok4 and v4 or "err"),tostring(ok4)))
print("[Z] alive")
