-- CRASH_CLASS: LOW
-- PROBE 1404c: deep read on /dev/usb + remaining safe nodes
--
-- 1404b found /dev/usb returns 248 bytes of structured data.
-- This probe: full hex dump of USB data, multiple reads, scan for kptrs.
-- Also tests /dev/rng with O_RDWR and skips notification nodes (blocking).

print("=== 1404c: /dev/usb deep + safe nodes ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end

local sc_open = mk(5)
local sc_read = mk(3)
local sc_close = mk(6)

local buf = memory.alloc(0x1000)
local buf_n = N(buf)

local path_buf = memory.alloc(256)
local path_n = N(path_buf)

local function write_str(addr, s)
    for i = 1, #s do wd(addr + i - 1, string.byte(s, i)) end
    wd(addr + #s, 0)
end

local function hexdump(addr, len)
    local lines = {}
    for off = 0, len - 1, 16 do
        local hex = {}
        for i = 0, 15 do
            if off + i < len then
                local b = rd(addr + off + i)
                if b then
                    table.insert(hex, string.format("%02X", b % 256))
                else
                    table.insert(hex, "??")
                end
            end
        end
        table.insert(lines, string.format("  +%03X: %s", off, table.concat(hex, " ")))
    end
    return lines
end

-- ============================================================
-- [A] /dev/usb full dump — multiple reads
-- ============================================================
print("[A] /dev/usb deep read")

write_str(path_n, "/dev/usb")
local fd = -1
pcall(function() fd = N(sc_open(uint64(path_n), uint64(0), uint64(0))) end)

if fd >= 0 then
    -- Read 1: 4096 bytes
    for i = 0, 0xFFC, 4 do wd(buf_n + i, 0xDEADDEAD) end
    local ok1, rv1 = pcall(function()
        return sc_read(uint64(fd), uint64(buf_n), uint64(4096))
    end)
    local br1 = ok1 and N(rv1) or -999
    print(string.format("  read1: %d bytes", br1))

    if br1 > 0 then
        -- Full hex dump (byte-level)
        for off = 0, br1 - 1, 16 do
            local hex = {}
            local ascii = {}
            for i = 0, 15 do
                if off + i < br1 then
                    local dw = rd(buf_n + off + i)
                    local b = dw and (dw % 256) or 0
                    table.insert(hex, string.format("%02X", b))
                    if b >= 32 and b < 127 then
                        table.insert(ascii, string.char(b))
                    else
                        table.insert(ascii, ".")
                    end
                else
                    table.insert(hex, "  ")
                    table.insert(ascii, " ")
                end
            end
            print(string.format("  %03X: %s  %s", off, table.concat(hex, " "), table.concat(ascii)))
        end

        -- Kernel pointer scan (qword-aligned)
        print("")
        print("  kptr scan:")
        local kptr_found = false
        for i = 0, br1 - 8, 8 do
            local lo = rd(buf_n + i) or 0
            local hi = rd(buf_n + i + 4) or 0
            if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                print(string.format("    +0x%02X: 0x%X%08X", i, hi, lo))
                kptr_found = true
            end
        end
        if not kptr_found then print("    none") end

        -- Read 2: see if second read returns more data or same
        for i = 0, 0xFFC, 4 do wd(buf_n + i, 0xDEADDEAD) end
        local ok2, rv2 = pcall(function()
            return sc_read(uint64(fd), uint64(buf_n), uint64(4096))
        end)
        local br2 = ok2 and N(rv2) or -999
        print(string.format("\n  read2: %d bytes", br2))
        if br2 > 0 and br2 ~= br1 then
            print(string.format("  different length! read1=%d read2=%d", br1, br2))
        end
    end

    pcall(function() sc_close(uint64(fd)) end)
else
    print("  OPEN_FAIL")
end

-- ============================================================
-- [B] /dev/rng with O_RDWR
-- ============================================================
print("")
print("[B] /dev/rng")
write_str(path_n, "/dev/rng")
for _, flags in ipairs({0, 2}) do -- O_RDONLY, O_RDWR
    fd = -1
    pcall(function() fd = N(sc_open(uint64(path_n), uint64(flags), uint64(0))) end)
    if fd >= 0 then
        for i = 0, 0x3C, 4 do wd(buf_n + i, 0xDEADDEAD) end
        local ok_r, rv_r = pcall(function()
            return sc_read(uint64(fd), uint64(buf_n), uint64(64))
        end)
        local br = ok_r and N(rv_r) or -999
        print(string.format("  flags=0x%X fd=%d read=%d", flags, fd, br))
        if br > 0 then
            local s = {}
            for i = 0, math.min(br-1, 31), 4 do
                table.insert(s, string.format("%08X", rd(buf_n + i) or 0))
            end
            print(string.format("  data: %s", table.concat(s, " ")))
        end
        pcall(function() sc_close(uint64(fd)) end)
    else
        print(string.format("  flags=0x%X OPEN_FAIL", flags))
    end
end

-- ============================================================
-- [C] Try /dev/urandom and /dev/random (might exist under different names)
-- ============================================================
print("")
print("[C] alternative random nodes")
for _, name in ipairs({"/dev/random", "/dev/urandom"}) do
    write_str(path_n, name)
    fd = -1
    pcall(function() fd = N(sc_open(uint64(path_n), uint64(0), uint64(0))) end)
    if fd >= 0 then
        for i = 0, 0x3C, 4 do wd(buf_n + i, 0xDEADDEAD) end
        local ok_r, rv_r = pcall(function()
            return sc_read(uint64(fd), uint64(buf_n), uint64(64))
        end)
        local br = ok_r and N(rv_r) or -999
        print(string.format("  %-20s fd=%d read=%d", name, fd, br))
        if br > 0 then
            local s = {}
            for i = 0, math.min(br-1, 31), 4 do
                table.insert(s, string.format("%08X", rd(buf_n + i) or 0))
            end
            print(string.format("  data: %s", table.concat(s, " ")))
        end
        pcall(function() sc_close(uint64(fd)) end)
    else
        print(string.format("  %-20s OPEN_FAIL", name))
    end
end

print("")
print("=== 1404c DONE ===")
