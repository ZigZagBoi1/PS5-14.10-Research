-- CRASH_CLASS: HIGH (reads a mapping of a physical shared memory object)
-- PROBE 316a: read the physhm mapping, read-only
--
-- 315a: 629(1,2,0,0) returned fd 27, and mmap(0, 0x1000, RW, MAP_SHARED, fd, 0)
-- returned 0x110F10000. The process died after that, so this run does one step
-- at a time, formats every value as hex, and never writes to the mapping.
--
-- What this settles: whether the mapping is readable at all, whether its
-- content is stable across two reads, and how much of it can be read.

print("=== PROBE 316a: physhm mapping, read only ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function U32(v) return uint64(v) end
local function hexaddr(v)
    if type(v) == "table" and v.h then return string.format("0x%X%08X", v.h, v.l) end
    return string.format("0x%X", to_num(v))
end
local function dw(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return string.format("%08X", to_num(v)) end
    return "FAULT"
end

local sc629 = make_syscall(629)
local sc_mmap = make_syscall(477)
local sc_close = make_syscall(6)

for _, arg3 in ipairs({0, 1}) do
    local fd = sgn(sc629(uint64(1), U32(2), U32(0), U32(arg3)))
    print(string.format("[arg3=%d] physhm_open -> %d", arg3, fd))
    if fd >= 0 then
        local p = sgn(sc_mmap(uint64(0), U32(0x1000), U32(3), U32(1), U32(fd), uint64(0)))
        print(string.format("  mmap(0x1000, shared) -> %s", hexaddr(p)))
        if p > 0 then
            local line = "  [0]"
            for i = 0, 7 do line = line .. " " .. dw(p + i * 4) end
            print(line)
            line = "  [32]"
            for i = 8, 15 do line = line .. " " .. dw(p + i * 4) end
            print(line)
            line = "  [0xF00]"
            for i = 0xF00, 0xF07 do line = line .. " " .. dw(p + i * 4) end
            print(line)
            print("  reread [0]: " .. dw(p) .. " " .. dw(p + 4))
        end
        sc_close(U32(fd))
    end
end

print("")
print("=== PROBE 316a COMPLETE ===")
