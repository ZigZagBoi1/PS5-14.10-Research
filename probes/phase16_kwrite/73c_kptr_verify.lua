-- CRASH_CLASS: LOW
-- PROBE 73c: Verify 73b kernel pointer candidates
--
-- 73b found 3495 values matching 0xFFFF8xxx in module data segments.
-- This probe re-reads specific offsets to check:
--   1. Value stability (same across connections = constant, not kernel addr)
--   2. Dword decomposition (are these pairs of unrelated 32-bit values?)
--   3. Module identity (which library is handle 2?)
--   4. Data segment size (are we reading past bounds?)
--
-- Expected 73b values for comparison (same boot should match if kernel):
--   h=2 data+0xA428: 0xFFFF806000040740
--   h=2 data+0xA430: 0xFFFF809000040774
--   h=2 data+0xA438: 0xFFFF80C000035CC4
--   h=38 data+0x1320: 0xFFFFC94000006C70

print("=== PROBE 73c: KPTR VERIFICATION ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt64(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local pid = N(mk(20)())
print("pid=" .. pid)

-- ============================================================
-- [A] Module identity and data segment sizes
-- ============================================================
print("[A] Module data segment info")

local info_buf = memory.alloc(0x200)
local mod_data = {}

for handle = 0, 38 do
    wd(N(info_buf), 0x160)
    pcall(function() mk(593)(uint64(handle), info_buf) end)

    local txt_lo = rd(N(info_buf) + 0x108)
    local txt_hi = rd(N(info_buf) + 0x10C)
    local txt_sz = rd(N(info_buf) + 0x110)
    local dat_lo = rd(N(info_buf) + 0x118)
    local dat_hi = rd(N(info_buf) + 0x11C)
    local dat_sz = rd(N(info_buf) + 0x120)

    if dat_lo and dat_hi and dat_sz then
        mod_data[handle] = {
            data_h = dat_hi, data_l = dat_lo,
            data_size = dat_sz,
            text_h = txt_hi, text_l = txt_lo,
            text_size = txt_sz
        }
        -- Only print interesting modules (handles 0, 1, 2, 38 and those with large data)
        if handle <= 5 or handle == 38 or dat_sz > 0x8000 then
            print(string.format("  h=%d: text=0x%X%08X(%dKB) data=0x%X%08X(%dKB)",
                handle, txt_hi or 0, txt_lo or 0, (txt_sz or 0) / 1024,
                dat_hi or 0, dat_lo or 0, dat_sz / 1024))
        end
    end
end

-- ============================================================
-- [B] Re-read specific offsets from 73b (handle 2)
-- ============================================================
print("")
print("[B] Handle 2 data verification")

local m2 = mod_data[2]
if m2 then
    print(string.format("  h=2 data segment: 0x%X%08X, size=0x%X (%d bytes)",
        m2.data_h, m2.data_l, m2.data_size, m2.data_size))

    -- Check if +0xA428 is within bounds
    if m2.data_size < 0xA428 then
        print(string.format("  *** WARNING: +0xA428 is PAST data segment end (0x%X) ***", m2.data_size))
        print("  Reading past declared bounds into adjacent memory!")
    end

    -- Read the specific offsets
    local test_offsets = {
        0xA420, 0xA424, 0xA428, 0xA42C, 0xA430, 0xA434,
        0xA438, 0xA43C, 0xA440, 0xA444, 0xA448, 0xA44C
    }

    print("  Dword-by-dword:")
    for _, off in ipairs(test_offsets) do
        local addr = uint64(string.format("0x%X%08X", m2.data_h, m2.data_l + off))
        local d = rd(addr)
        if d then
            print(string.format("    data+0x%04X: 0x%08X", off, d))
        else
            print(string.format("    data+0x%04X: UNREADABLE", off))
        end
    end

    print("  Qword (73b comparison):")
    local qword_offsets = {0xA428, 0xA430, 0xA438, 0xA440, 0xA448}
    for _, off in ipairs(qword_offsets) do
        local addr = uint64(string.format("0x%X%08X", m2.data_h, m2.data_l + off))
        local q = rq(addr)
        print(string.format("    data+0x%04X: %s", off, fmt64(q)))
    end
else
    print("  h=2 not found")
end

-- ============================================================
-- [C] Handle 38 data verification
-- ============================================================
print("")
print("[C] Handle 38 data verification")

local m38 = mod_data[38]
if m38 then
    print(string.format("  h=38 data segment: 0x%X%08X, size=0x%X (%d bytes)",
        m38.data_h, m38.data_l, m38.data_size, m38.data_size))

    if m38.data_size < 0x1320 then
        print(string.format("  *** WARNING: +0x1320 is PAST data segment end (0x%X) ***", m38.data_size))
    end

    local qoff38 = {0x1320, 0x1328, 0x1330, 0x1338, 0x1340}
    print("  Qword (73b comparison):")
    for _, off in ipairs(qoff38) do
        local addr = uint64(string.format("0x%X%08X", m38.data_h, m38.data_l + off))
        local q = rq(addr)
        print(string.format("    data+0x%04X: %s", off, fmt64(q)))
    end
end

-- ============================================================
-- [D] Check ALL modules: which have kptrs, what are their sizes
-- ============================================================
print("")
print("[D] Per-module kptr census (first 3 kptrs per module)")

local total_mod_kptrs = 0
for handle = 0, 38 do
    local m = mod_data[handle]
    if not m then break end

    local scan = math.min(m.data_size, 0x20000)
    local kptrs = {}

    for off = 0, scan - 8, 8 do
        local addr = uint64(string.format("0x%X%08X", m.data_h, m.data_l + off))
        local q = rq(addr)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                table.insert(kptrs, {off = off, h = h, l = l})
                if #kptrs >= 3 then break end
            end
        else
            break
        end
    end

    if #kptrs > 0 then
        total_mod_kptrs = total_mod_kptrs + #kptrs
        local first = kptrs[1]
        print(string.format("  h=%d: size=0x%X, first_kptr at +0x%04X = 0x%08X%08X%s",
            handle, m.data_size, first.off, first.h, first.l,
            first.off >= m.data_size and " (PAST END!)" or ""))
    end
end

-- ============================================================
-- [E] Check if values at boundary overlap into adjacent regions
-- ============================================================
print("")
print("[E] Cross-region boundary check for handle 2")

if m2 then
    local boundary = m2.data_size
    print(string.format("  data segment ends at +0x%X", boundary))

    -- Read 16 qwords before and after the boundary
    print("  Values around boundary:")
    for off = math.max(0, boundary - 64), boundary + 64, 8 do
        local addr = uint64(string.format("0x%X%08X", m2.data_h, m2.data_l + off))
        local q = rq(addr)
        local h, l = 0, 0
        if q then h, l = get_hi_lo(q) end
        local marker = ""
        if off == boundary then marker = " <-- BOUNDARY" end
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then marker = marker .. " *KPTR*" end
        print(string.format("    +0x%05X: %s%s", off, fmt64(q), marker))
    end
end

-- ============================================================
-- [F] Read first few qwords at handle 0 (eboot) data for comparison
-- ============================================================
print("")
print("[F] Handle 0 (eboot) data sample")

local m0 = mod_data[0]
if m0 then
    print(string.format("  eboot data: 0x%X%08X, size=0x%X", m0.data_h, m0.data_l, m0.data_size))
    for off = 0, 0x40, 8 do
        local addr = uint64(string.format("0x%X%08X", m0.data_h, m0.data_l + off))
        local q = rq(addr)
        print(string.format("    +0x%04X: %s", off, fmt64(q)))
    end
end

print("")
print("=== PROBE 73c COMPLETE ===")
