-- CRASH_CLASS: MODERATE
-- Isolated syscall-65 msync baseline on one anonymous user mapping.
-- No MS_INVALIDATE, device object, race, or page fault trigger.
print("=== PROBE 121e: MSYNC 65 BASELINE ===")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function failed(v)
    return type(v) == "table" and v.h == 0xFFFFFFFF and v.l == 0xFFFFFFFF
end

local getpid = sc(20)
print("pid=" .. num(getpid()))
local ok_map, base = pcall(function()
    return sc(477)(uint64(0), uint64(0x4000), uint64(0x33),
                   uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("mmap_ok=" .. tostring(ok_map) .. " base=" .. tostring(base))
if not ok_map or failed(base) or num(base) == 0 then
    print("STOP: anonymous mapping unavailable")
    return
end

local addr = num(base)
local marker = 0x1234ABCD
local ok_write = pcall(function() memory.write_dword(addr, marker) end)
local ok_before, before = pcall(function() return memory.read_dword(addr) end)
print("before_write_ok=" .. tostring(ok_write) .. " read_ok=" .. tostring(ok_before) .. " value=" .. tostring(before))
if not ok_write or not ok_before or num(before) ~= marker then
    print("STOP: mapping read/write baseline failed")
    return
end

print("[BEFORE] msync syscall 65, flags=0")
local ok, rv = pcall(function()
    return sc(65)(base, uint64(0x4000), uint64(0))
end)
print("[AFTER] ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
local ok_after, after = pcall(function() return memory.read_dword(addr) end)
print("after_read_ok=" .. tostring(ok_after) .. " value=" .. tostring(after))
print("canary_pid=" .. num(getpid()))
print("=== PROBE 121e COMPLETE ===")
