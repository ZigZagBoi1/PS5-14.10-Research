-- CRASH_CLASS: LOW
-- PROBE 291a: what getdirentries actually returns
--
-- Context: 290a showed syscall 196 returns data for "/", "/app0" and "/dev"
-- (n=132, 232, 1376) but a walk using the FreeBSD 64-bit struct dirent offsets
-- printed nothing, so either the layout differs or the buffer is not dirents.
-- This probe dumps the raw bytes and tries three layouts.

print("=== PROBE 291a: dirent layout ===")
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

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local buf = memory.alloc(0x4000)
local basep = memory.alloc(8)

for _, p in ipairs({ "/", "/app0" }) do
    local fd = sgn(sc_open(uint64(put_str(p)), uint64(0), uint64(0)))
    print(string.format("[%s] fd=%d", p, fd))
    if fd >= 0 then
        for _, num in ipairs({ 196, 554, 272, 344, 500, 512 }) do
            for off = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(buf + off, 0) end) end
            local sc = make_syscall(num)
            local r = sgn(sc(uint64(fd), uint64(buf), uint64(0x4000), uint64(basep)))
            if r > 0 then
                print(string.format("  syscall %d -> %d bytes, base=%d", num, r, sgn(memory.read_dword(basep))))
                print(hexdump(buf, 160))
                break
            else
                print(string.format("  syscall %d -> %d", num, r))
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== PROBE 291a COMPLETE ===")
