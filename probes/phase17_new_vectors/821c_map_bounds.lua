-- CRASH_CLASS: LOW
-- PROBE 821c: where does the user vm_map end, and does an unmapped range give
-- a different error from an out-of-map range?
--
-- sys 73 rejects start < map->min_offset or end > map->max_offset before it
-- does anything (cmp r14,[rbx+0x20]; jb; cmp r15,[rbx+0x28]; ja), while
-- mprotect(74) has no such check and calls vm_map_protect directly.

print("=== PROBE 821c: vm_map bounds oracle ===")
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
local function u(v)
    if type(v) == "table" then
        return uint64(to_num(v.h or 0)) * uint64(4294967296) + uint64(to_num(v.l or 0))
    end
    return uint64(v)
end

local sc73 = make_syscall(73)
local sc_mprot = make_syscall(74)
local sc_mmap = make_syscall(477)

local p = -1
pcall(function() p = to_num(sc_mmap(u(0), u(0x4000), u(3), u(0x1002), u(-1), u(0))) end)

local addrs = {
    { "mapped page",          p },
    { "0x0",                  0x0000000000000000 },
    { "0x100000",             0x0000000000100000 },
    { "0x7FFF00000000",       0x00007FFF00000000 },
    { "0x8000000000",         0x0000008000000000 },
    { "0xFE0000000",          0x0000000FE0000000 },
    { "0x1000000000",         0x0000001000000000 },
    { "0x7FFFFFFFFFFF",       0x00007FFFFFFFFFFF },
    { "0xFFFF800000000000",   0xFFFF800000000000 },
    { "kernel base",          0xFFFFFFFF8A9C0000 },
}

for _, a in ipairs(addrs) do
    local r73, r74 = -99, -99
    pcall(function() r73 = to_num(sc73(u(a[2]), u(0x4000), u(0))) end)
    pcall(function() r74 = to_num(sc_mprot(u(a[2]), u(0x4000), u(3))) end)
    print(string.format("[A] %-20s addr=%016X  73=%d  74=%d", a[1], a[2], r73, r74))
end
print("[B] survived")
