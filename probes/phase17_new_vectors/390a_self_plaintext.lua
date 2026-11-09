-- CRASH_CLASS: LOW
-- PROBE 390a: is the code segment in eboot.bin the same bytes as memory
--
-- 389a recovered the program header table: the first LOAD segment is file offset
-- 0x4000, virtual 0, file size 0x491474, flags 5 - the same range 374a read from
-- memory at the eboot base. If the two match byte for byte, the SELF carries its
-- segments in plaintext and the file can be read for the parts memory will not
-- give us (.rodata, the import tables, the relocations). If they differ, the file
-- is encrypted and pulling it is pointless.
--
-- This reads 0x40 bytes at file offset 0x4000 and the same 0x40 bytes at the
-- eboot text base, prints both and says whether they match.

print("=== PROBE 390a: SELF PLAINTEXT CHECK ===")
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
local sc_info  = make_syscall(593)

local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end

local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -1
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
print(string.format("593 rv=%d eboot base=0x%X", rv, base))

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
local function seek(fd, off)
    local r = -1
    pcall(function() r = sgn(sc_lseek(uint64(fd), uint64(off), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    return r
end
local function read_n(fd, n)
    local buf = memory.alloc(n)
    for i = 0, n - 4, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
    local got = -1
    pcall(function() got = sgn(sc_read(uint64(fd), uint64(buf), uint64(n), uint64(0), uint64(0), uint64(0))) end)
    return got, buf
end
local function hex(buf, n)
    local s = ""
    for i = 0, n - 1 do
        local ok, b = pcall(function() return memory.read_byte(buf + i) end)
        if ok and b then s = s .. string.format("%02X", to_num(b)) else s = s .. "??" end
    end
    return s
end

local fd = open_rd("/app0/eboot.bin")
print("fd=" .. fd)
if fd < 0 or base <= 0 then print("cannot compare") print("=== 390a DONE ===") return end

local ok_seek = seek(fd, 0x4000)
print("seek -> " .. ok_seek)
local got, fbuf = read_n(fd, 0x40)
print(string.format("file[0x4000] (%d) %s", got, hex(fbuf, 0x40)))

local mbuf = memory.alloc(0x40)
pcall(function() for i = 0, 0x3C, 4 do memory.write_dword(mbuf + i, 0) end end)
local okread = pcall(function() return memory.read_buffer(base, 0x40) end)
local s = nil
local ok2, res = pcall(function() return memory.read_buffer(base, 0x40) end)
if ok2 then s = res end
if type(s) == "string" then
    local h = ""
    for i = 1, #s do h = h .. string.format("%02X", string.byte(s, i)) end
    print("mem [base  ]        " .. h)
    print("match=" .. tostring(h == hex(fbuf, 0x40)))
else
    print("memory read failed")
end

-- also 0x20 bytes at the entry point
local entry = 0x2C56C0
seek(fd, 0x4000 + entry)
local g2, b2 = read_n(fd, 0x20)
print(string.format("file[entry] (%d) %s", g2, hex(b2, 0x20)))
local ok3, s3 = pcall(function() return memory.read_buffer(base + entry, 0x20) end)
if ok3 and type(s3) == "string" then
    local h = ""
    for i = 1, #s3 do h = h .. string.format("%02X", string.byte(s3, i)) end
    print("mem [entry]        " .. h)
    print("match=" .. tostring(h == hex(b2, 0x20)))
end

pcall(function() sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print("")
print("=== 390a DONE ===")
