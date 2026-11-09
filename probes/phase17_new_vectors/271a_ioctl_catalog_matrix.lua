-- CRASH_CLASS: MODERATE
-- PROBE 271a: 13.60-derived ioctl command-code matrix on openable device nodes
--
-- Context: PR #74 opened 34 /dev nodes from the game process and ioctl(fd, 0)
-- returned -1 on all of them without killing: the drivers refuse command 0 but
-- the ioctl path reaches them. No real command codes were ever tried.
-- The 13.60 kernel text capture (docs/dumps_13.60/kernel_text.bin, KASLR base
-- 0xffffffff8a9c0000) contains real driver ioctl dispatchers as binary-search
-- compare chains on the command register. tools/extract_ioctl_catalog.py
-- extracted 88 direction-bit command codes from 13 dispatchers (groups
-- A/B/D/f/H/O/P/S/t/U). This probe tries 57 of them on 10 openable
-- device nodes and records every return that is not -1.
--
-- Caveats: 13.60-labeled capture, acquisition authenticity unresolved; 14.10
-- codes may differ. Buffer is zeroed 0x800 bytes, larger than the largest
-- copyin/copyout size in the catalog (0x404). IN-codes read zeros, OUT-codes
-- write into the buffer, VOID codes ignore it.

print("=== PROBE 271a: ioctl catalog matrix ===")
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
local function n(v)
    local t = to_num(v)
    if t > 0x7FFFFFFFFFFFFFFF then t = t - 18446744073709551616 end
    return t
end
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function call(num, a, b, c)
    local sc = make_syscall(num)
    sc.syscall_no = num
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0)) end)
    if not ok then return nil end
    return rv
end

-- Section A: open the target nodes
print("[A] open device nodes")
local nodes = { "gc", "dce", "gic", "ajmi", "ajm", "camera", "notification0", "usbctl", "hid", "bt" }
local fds = {}
local function path(p)
    local b = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do
        pcall(function() memory.write_dword(b + i, 0) end)
    end
    for i = 0, #p - 1, 4 do
        local d = 0
        for j = 0, 3 do
            if i + j < #p then
                d = d + string.byte(p, i + j + 1) * (256 ^ j)
            end
        end
        pcall(function() memory.write_dword(b + i, d) end)
    end
    return b
end
for i = 1, #nodes do
    local rv = call(5, path("/dev/" .. nodes[i]), uint64(2))  -- O_RDWR
    local fd = n(rv)
    print(string.format("    %-14s open=%s", nodes[i], raw(rv)))
    if fd >= 0 then fds[#fds + 1] = { nodes[i], fd } end
end
print(string.format("    opened %d/%d", #fds, #nodes))
print("")

-- Section B: ioctl matrix
print("[B] ioctl matrix: every non-(-1) return printed")
local codes = {
    0x00004F00,
    0x00004F01,
    0x40047400,
    0x40047401,
    0x40047402,
    0x40047403,
    0x40047419,
    0x4004741A,
    0x40047440,
    0x40084105,
    0x40084106,
    0x40084108,
    0x4008411F,
    0x40084120,
    0x4008421F,
    0x40084220,
    0x400C4109,
    0x400C410A,
    0x4014421B,
    0x40144401,
    0x40184114,
    0x40184402,
    0x40204117,
    0x40205505,
    0x402C7413,
    0x4030440A,
    0x4030440B,
    0x40407445,
    0x40845301,
    0x40845303,
    0x80044103,
    0x8004410C,
    0x8004410E,
    0x8004410F,
    0x80044808,
    0x80045501,
    0x80045502,
    0x80045506,
    0x80047401,
    0x80047402,
    0x80047404,
    0x80047410,
    0x80084107,
    0x80084108,
    0x80084109,
    0x8008410E,
    0x802C7414,
    0x802C7416,
    0xC00C440D,
    0xC00C440E,
    0xC0104410,
    0xC0104411,
    0xC0185501,
    0xC0845301,
    0xC0845302,
    0xC0A84B00,
    0xC1785504
}
local buf = memory.alloc(0x800)
for i = 0, 0x7FC, 4 do
    pcall(function() memory.write_dword(buf + i, 0) end)
end
local sc_ioctl = make_syscall(54)
sc_ioctl.syscall_no = 54
local hits, tried = 0, 0
for fi = 1, #fds do
    local nm, fd = fds[fi][1], fds[fi][2]
    local refused = 0
    -- re-zero buffer between devices
    for zi = 0, 0x7FC, 4 do
        pcall(function() memory.write_dword(buf + zi, 0) end)
    end
    for ci = 1, #codes do
        local code = codes[ci]
        local ok, rv = pcall(function() return sc_ioctl(uint64(fd), uint64(code), uint64(buf)) end)
        tried = tried + 1
        if not ok then
            print(string.format("    PCALL-FAIL %s fd=%d code=0x%08X", nm, fd, code))
        else
            local r = n(rv)
            if r ~= -1 then
                hits = hits + 1
                local b0 = 0
                pcall(function() b0 = to_num(memory.read_dword(buf)) end)
                print(string.format("    HIT %-14s fd=%-3d code=0x%08X ret=%s buf0=0x%08X", nm, fd, code, raw(rv), b0))
                -- scan buffer for kernel pointers
                local dir = math.floor(code / 0x20000000) % 4  -- 2=OUT, 3=INOUT
                local sz = math.floor(code / 0x10000) % 0x2000
                if dir >= 2 and sz > 0 and sz <= 0x800 then
                    for off = 0, sz - 8, 4 do
                        local lo = 0; pcall(function() lo = to_num(memory.read_dword(buf + off)) end)
                        local hi = 0; pcall(function() hi = to_num(memory.read_dword(buf + off + 4)) end)
                        if lo < 0 then lo = lo + 0x100000000 end
                        if hi < 0 then hi = hi + 0x100000000 end
                        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                            print(string.format("    *** KPTR %s code=0x%08X +0x%X: 0x%08X%08X ***", nm, code, off, hi, lo))
                        end
                    end
                end
            else
                refused = refused + 1
            end
        end
    end
    print(string.format("    [%s] %d codes, %d refused, done", nm, #codes, refused))
    call(6, uint64(fd))
    fds[fi][2] = -1
end
print("")
print(string.format("[C] summary: tried=%d hits=%d", tried, hits))
print("=== END 271a ===")
