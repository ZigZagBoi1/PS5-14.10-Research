-- CRASH_CLASS: LOW
-- PROBE 385a: can the game process read its own module files
--
-- 377a showed that module .text and .rodata cannot be read once mapped (p=0x1 and
-- p=0x4 both fault). But the same modules also exist as files: 295a listed
-- /app0/sce_module with libc.prx and ten more PRX, next to eboot.bin. A file read
-- would hand us the code we cannot touch in memory, which is the only way left to
-- learn the userland APIs - the graphics driver's submit path in particular.
--
-- This probe lists /app0/sce_module and then opens three of the modules plus
-- eboot.bin and reads 32 bytes from each, printing the first bytes so an ELF or
-- SELF header is visible. Read-only, nothing is written.

print("=== PROBE 385a: MODULE FILE READ ===")
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

local sc_open = make_syscall(5)
local sc_read = make_syscall(3)
local sc_close = make_syscall(6)
local sc_dir  = make_syscall(196)

local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    if (l % 2) == 1 then return h * 4294967296 + l - 4294967296 end
    return h * 4294967296 + l
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
local function read_hex(fd, n)
    local buf = memory.alloc(n)
    for i = 0, n - 4, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
    local got = -1
    pcall(function() got = sgn(sc_read(uint64(fd), uint64(buf), uint64(n), uint64(0), uint64(0), uint64(0))) end)
    if got <= 0 then return got, "" end
    local s = ""
    for i = 0, got - 1 do
        local ok, b = pcall(function() return memory.read_byte(buf + i) end)
        if ok and b then s = s .. string.format("%02X ", to_num(b)) else s = s .. "?? " end
    end
    return got, s
end

-- [A] list /app0/sce_module
print("[A] /app0/sce_module")
local dirbuf = memory.alloc(0x800)
local d = open_rd("/app0/sce_module")
print("    dirfd=" .. d)
if d >= 0 then
    for i = 0, 0x7FC, 4 do pcall(function() memory.write_dword(dirbuf + i, 0) end) end
    local n = -1
    pcall(function() n = sgn(sc_dir(uint64(d), uint64(dirbuf), uint64(0x800), uint64(0), uint64(0), uint64(0))) end)
    print("    bytes=" .. n)
    if n > 0 then
        local off = 0
        while off < n do
            local reclen = to_num(memory.read_byte(dirbuf + off + 4))
            local namlen = to_num(memory.read_byte(dirbuf + off + 7))
            if reclen <= 0 then break end
            local name = ""
            for i = 0, namlen - 1 do
                local ok, b = pcall(function() return memory.read_byte(dirbuf + off + 8 + i) end)
                if ok and b and to_num(b) ~= 0 then name = name .. string.char(to_num(b)) end
            end
            print(string.format("    %s", name))
            off = off + reclen + 4
        end
    end
    pcall(function() sc_close(uint64(d), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

-- [B] open and read a few of them
local targets = {"/app0/eboot.bin", "/app0/sce_module/libc.prx", "/app0/root.pfs"}
for _, path in ipairs(targets) do
    local fd = open_rd(path)
    print(string.format("[B] %s fd=%d", path, fd))
    if fd >= 0 then
        local got, hex = read_hex(fd, 32)
        print(string.format("    read=%d %s", got, hex))
        pcall(function() sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end

print("")
print("=== 385a DONE ===")
