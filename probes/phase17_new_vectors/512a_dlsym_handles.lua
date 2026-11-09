-- CRASH_CLASS: MODERATE
-- PROBE 512a: 591 dynlib_dlsym with a real handle.
--
-- The 13.60 decode (docs/OFFLINE_HANDLER_DECODE_2026-10-23.md:44-64) says 591
-- is ungated: 591(handle, name_ptr, out_addr_ptr) resolves a symbol in a loaded
-- module and copyouts the address.  Every earlier 591 call used handle 0, which
-- fails the handle lookup (error 3), so this asks 592 for the real handle list
-- and tries one symbol name per handle.
--
-- A success here is a kernel-side dlsym for any loaded module: a code-address
-- oracle in libkernel and other XO modules, and potentially a syscall stub.

print("=== PROBE 512a: 591 WITH REAL HANDLES ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = nil
        local ok, v = pcall(function() return memory.read_byte(a + i) end)
        if ok then b = to_num(v) end
        if not b or b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b)
        else out = out .. "." end
    end
    return out
end
local function hexq(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", to_num(v.h), to_num(v.l))
    end
    return string.format("0x%X", to_num(v))
end

local sc592 = make_syscall(592)
local sc593 = make_syscall(593)
local sc591 = make_syscall(591)

local list = memory.alloc(0x400)
local count = memory.alloc(8)
wd(list, 0, 0)
wd(count, 0)
local okA, retA = pcall(function() return sc592(uint64(list), uint64(0x100), uint64(count)) end)
print(string.format("[A] 592 ret=%s count=%d", okA and tostring(to_num(retA)) or "pcall-fail", to_num(rd(count))))

local n = to_num(rd(count))
if n > 0x100 then n = 0x100 end
local handles = {}
for i = 0, n - 1 do handles[#handles + 1] = to_num(rd(list + i * 4)) end
local line = ""
for i = 1, #handles do
    line = line .. string.format("%08X ", handles[i])
    if i % 8 == 0 then print("    " .. line); line = "" end
end
if #line > 0 then print("    " .. line) end

print("")
print("[B] 593 names for each handle")
local info = memory.alloc(0x200)
for i = 1, #handles do
    local ok = pcall(function()
        for k = 0, 0x1FF, 4 do memory.write_dword(info + k, 0) end
        memory.write_dword(info, 0x160)
    end)
    if ok then
        local ok2, rv = pcall(function() return sc593(uint64(handles[i]), uint64(info)) end)
        if ok2 and to_num(rv) == 0 then
            print(string.format("    [%2d] h=%08X name=%s text=%s", i, handles[i],
                ascii(info + 0x20, 0x20), hexq(rq(info + 0x108))))
        else
            print(string.format("    [%2d] h=%08X ret=%s", i, handles[i], ok2 and tostring(to_num(rv)) or "pcall-fail"))
        end
    end
end

print("")
print("[C] 591 dlsym per handle, name=sceKernelGetProcessId")
local name = memory.alloc(0x40)
local nm = "sceKernelGetProcessId"
for i = 1, #nm do pcall(function() memory.write_byte(name + i - 1, string.byte(nm, i)) end) end
pcall(function() memory.write_byte(name + #nm, 0) end)
local out = memory.alloc(8)
for i = 1, #handles do
    pcall(function() memory.write_qword(out, 0xDEADBEEF) end)
    local ok, rv = pcall(function() return sc591(uint64(handles[i]), uint64(name), uint64(out)) end)
    print(string.format("    [%2d] h=%08X ret=%s out=%s", i, handles[i],
        ok and tostring(to_num(rv)) or "pcall-fail", hexq(rq(out))))
end
print("=== DONE ===")
