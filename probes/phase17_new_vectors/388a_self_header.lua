-- CRASH_CLASS: LOW
-- PROBE 388a: what kind of container eboot.bin and libc.prx are
--
-- 385a found that the game's files can be opened and read: eboot.bin and
-- sce_module/libc.prx both begin 4F 15 3D 1D, which is the SCE SELF magic, and
-- root.pfs begins "pf8cn". A SELF carries a table of segments that says whether
-- each one is encrypted. If the code segment is plaintext, the file holds the
-- same bytes we can already read from memory plus the ELF header and the import
-- tables; if it is encrypted, the file is not worth pulling.
--
-- This reads the first 0x400 bytes of each and prints them as hex, then looks for
-- an ELF magic anywhere in the first 0x10000 bytes and reports where.

print("=== PROBE 388a: SELF HEADER ===")
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
local sc_open  = make_syscall(5)
local sc_read  = make_syscall(3)
local sc_close = make_syscall(6)
local sc_lseek = make_syscall(478)

local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function open_rd(path)
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
    local ok = pcall(function()
        for i = 1, #path do memory.write_byte(buf + i - 1, path:byte(i)) end
        memory.write_byte(buf + #path, 0)
    end)
    if not ok then return -1 end
    local fd = -1
    pcall(function() fd = sgn(sc_open(uint64(buf), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    return fd
end
local function read_at(fd, off, n)
    local buf = memory.alloc(n)
    for i = 0, n - 4, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
    local got = -1
    pcall(function() got = sgn(sc_read(uint64(fd), uint64(buf), uint64(n), uint64(0), uint64(0), uint64(0))) end)
    return got, buf
end
local function seek(fd, off)
    local r = -1
    pcall(function() r = sgn(sc_lseek(uint64(fd), uint64(off), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    return r
end
local function hex(buf, n)
    local s = ""
    for i = 0, n - 1 do
        local ok, b = pcall(function() return memory.read_byte(buf + i) end)
        if ok and b then s = s .. string.format("%02X", to_num(b)) else s = s .. "??" end
    end
    return s
end

local function inspect(path)
    print("[FILE] " .. path)
    local fd = open_rd(path)
    print("  fd=" .. fd)
    if fd < 0 then return end
    local got, buf = read_at(fd, 0, 0x100)
    print("  head=" .. hex(buf, 0x40))
    -- elf magic anywhere in the first 0x10000
    local found = {}
    seek(fd, 0)
    local n = 0
    for off = 0, 0xF000, 0x1000 do
        local g, b = read_at(fd, off, 0x1000)
        if g <= 0 then break end
        n = n + g
        for i = 0, g - 4 do
            local ok, b0, b1, b2, b3 = pcall(function()
                return memory.read_byte(b + i), memory.read_byte(b + i + 1),
                       memory.read_byte(b + i + 2), memory.read_byte(b + i + 3)
            end)
            if ok and to_num(b0) == 0x7F and to_num(b1) == 0x45 and to_num(b2) == 0x4C and to_num(b3) == 0x46 then
                found[#found + 1] = off + i
                if #found >= 8 then break end
            end
        end
        if #found >= 8 then break end
    end
    print(string.format("  scanned=%d elf-magic-at=%d", n, #found))
    for _, o in ipairs(found) do
        seek(fd, o)
        local g2, b2 = read_at(fd, o, 0x40)
        print(string.format("    +0x%X %s", o, hex(b2, 0x30)))
    end
    pcall(function() sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

inspect("/app0/eboot.bin")
inspect("/app0/sce_module/libc.prx")

print("")
print("=== 388a DONE ===")
