-- CRASH_CLASS: LOW
-- PROBE 294a: what the jail actually contains
--
-- Context: 290a found that only "/", "/app0" and "/dev" open; 291a never ran
-- because the loader died first. getdirentries is syscall 196 and returns
-- bytes, but a walk using FreeBSD's 64-bit struct dirent offsets found no
-- entry with a sane d_reclen.
--
-- This probe dumps the raw buffer for each directory it can open, and walks it
-- with three candidate layouts, so the record format can be read off the bytes
-- instead of assumed.
--
-- The shape of the jail matters: if the game process cannot see a mounted
-- volume, no filesystem driver is reachable from here at all.

print("=== PROBE 294a: jail layout ===")
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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function hexdump(addr, n)
    local out = {}
    for row = 0, math.floor((n - 1) / 16) do
        local line = string.format("%04X  ", row * 16)
        local ascii = ""
        for col = 0, 15 do
            local b = 0
            pcall(function() b = to_num(memory.read_byte(addr + row * 16 + col)) end)
            line = line .. string.format("%02X ", b)
            ascii = ascii .. (b >= 32 and b < 127 and string.char(b) or ".")
        end
        out[#out + 1] = line .. " " .. ascii
    end
    return table.concat(out, "\n")
end
local function rd(addr, n)
    local s = ""
    for i = 0, n - 1 do
        local c = 0
        pcall(function() c = to_num(memory.read_byte(addr + i)) end)
        if c > 0 and c < 128 then s = s .. string.char(c) end
    end
    return s
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local list = make_syscall(196)
local buf = memory.alloc(0x8000)
local basep = memory.alloc(8)

for _, p in ipairs({ "/", "/app0", "/dev" }) do
    local fd = sgn(sc_open(uint64(put_str(p)), uint64(0), uint64(0)))
    print(string.format("[%s] fd=%d", p, fd))
    if fd >= 0 then
        for off = 0, 0x7FFC, 4 do pcall(function() memory.write_dword(buf + off, 0xCC) end) end
        local r = sgn(list(uint64(fd), uint64(buf), uint64(0x8000), uint64(basep)))
        print(string.format("  n=%d base=%d", r, sgn(memory.read_dword(basep))))
        if r > 0 then print(hexdump(buf, math.min(r, 128))) end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== PROBE 294a COMPLETE ===")
