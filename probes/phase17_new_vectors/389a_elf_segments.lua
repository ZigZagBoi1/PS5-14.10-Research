-- CRASH_CLASS: LOW
-- PROBE 389a: the segment table inside eboot.bin
--
-- 388a found a plaintext ELF header 0x160 bytes into both eboot.bin and
-- sce_module/libc.prx (ELFCLASS64, OSABI 9, e_type 0xFE10, x86-64), so the SELF
-- wrapper carries the ELF unencrypted at that offset. If the program headers and
-- the segments are plaintext too, the file is worth pulling: it holds the import
-- tables (NID lists) that the loaded image does not expose to us, and .rodata,
-- which cannot be read once mapped.
--
-- This reads the ELF header, walks the program header table and prints one line
-- per segment: type, flags, file offset, virtual address, file size, memory size.

print("=== PROBE 389a: ELF SEGMENTS ===")
print("")

local ELF_OFF = 0x160

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
local function rd64(buf, off)
    local lo = to_num(memory.read_dword(buf + off))
    local hi = to_num(memory.read_dword(buf + off + 4))
    return hi * 4294967296 + lo
end
local function rd32(buf, off)
    return to_num(memory.read_dword(buf + off))
end
local function rd16(buf, off)
    return to_num(memory.read_byte(buf + off)) + to_num(memory.read_byte(buf + off + 1)) * 256
end

local function inspect(path)
    print("[FILE] " .. path)
    local fd = open_rd(path)
    if fd < 0 then print("  cannot open") return end
    seek(fd, ELF_OFF)
    local got, buf = read_n(fd, 0x40)
    if got < 0x40 then print("  short read " .. got) return end
    local e_entry = rd64(buf, 0x18)
    local e_phoff = rd64(buf, 0x20)
    local e_phentsize = rd16(buf, 0x36)
    local e_phnum = rd16(buf, 0x38)
    print(string.format("  entry=0x%X phoff=0x%X phentsize=%d phnum=%d",
        e_entry, e_phoff, e_phentsize, e_phnum))
    if e_phnum == 0 or e_phnum > 32 or e_phentsize == 0 then
        print("  unexpected table")
        pcall(function() sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        return
    end
    seek(fd, ELF_OFF + e_phoff)
    local total = e_phnum * 0x40
    local g2, ph = read_n(fd, total)
    print("  read=" .. g2)
    for i = 0, e_phnum - 1 do
        local o = i * 0x40
        local p_type = rd32(ph, o)
        local p_flags = rd32(ph, o + 4)
        local p_offset = rd64(ph, o + 8)
        local p_vaddr = rd64(ph, o + 0x10)
        local p_filesz = rd64(ph, o + 0x20)
        local p_memsz = rd64(ph, o + 0x28)
        print(string.format("  [%d] type=0x%X flags=%d off=0x%X vaddr=0x%X filesz=0x%X memsz=0x%X",
            i, p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    end
    pcall(function() sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

inspect("/app0/eboot.bin")
inspect("/app0/sce_module/libc.prx")

print("")
print("=== 389a DONE ===")
