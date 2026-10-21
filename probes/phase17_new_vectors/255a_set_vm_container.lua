-- CRASH_CLASS: HIGH
-- PROBE 255a: 559 set_vm_container, the untested memory-container call
--
-- The 13.60 table names 559 set_vm_container and 560 debug_init, neither of
-- which has been called on 14.10. A VM container is a memory-isolation object,
-- so if this call can be pointed at a container the process does not own, the
-- next mapping could land somewhere it should not. The observable here is
-- cheap and safe first: whether the id is accepted at all, then whether a
-- mapping made afterwards differs from one made before.
--
--   A  559(id) for ids 0..8, 0xFFFFFFFF, and a few large values
--   B  mmap a page before and after an accepted id, and print both addresses
--   C  547 query_memory_protection on the pre-switch page, then a fresh mmap
--
-- A kill names its own row because every row prints the pid.

print("=== PROBE 255a: set_vm_container ===")
print("")

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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end
local function mmap(size, prot, flags)
    local rv = call(477, uint64(0), uint64(size), uint64(prot), uint64(flags), uint64(0xFFFFFFFF), uint64(0))
    return rv
end
local function query(addr)
    local b = memory.alloc(0x200)
    pcall(function() for o = 0, 0x1FC, 4 do memory.write_dword(b + o, 0) end end)
    local rv = call(547, uint64(addr), uint64(b), uint64(0x200))
    return rv, b
end

print("[0] pid=" .. tostring(pid()))
local m0 = mmap(0x1000, 3, 0x1002)
print("    mmap before any switch -> " .. q(m0) .. "  pid=" .. tostring(pid()))

print("")
print("[A] 559(id)")
local ids = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 0xF, 0x100, 0xFFFFFFFF }
for i = 1, #ids do
    local rv = call(559, uint64(ids[i]), uint64(0), uint64(0))
    print(string.format("    559(0x%08X) -> %-24s pid=%s", ids[i], q(rv), tostring(pid())))
end

print("")
print("[B] mappings after the sweep")
local m1 = mmap(0x1000, 3, 0x1002)
print("    mmap after the sweep  -> " .. q(m1) .. "  pid=" .. tostring(pid()))
print("    same region as before -> " .. tostring(to_num(m0) == to_num(m1)))
local m2 = mmap(0x4000, 3, 0x33)
print("    device-style mmap     -> " .. q(m2) .. "  pid=" .. tostring(pid()))

print("")
print("[C] 547 on the pre-switch page")
if to_num(m0) ~= 0 then
    local rv, b = query(to_num(m0))
    local s = ""
    for o = 0, 0x14, 4 do
        local ok, v = pcall(function() return memory.read_dword(b + o) end)
        s = s .. " " .. (ok and string.format("%08X", to_num(v)) or "??")
    end
    print("    547(m0) -> " .. q(rv) .. "  rec:" .. s .. "  pid=" .. tostring(pid()))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 255a COMPLETE ===")
