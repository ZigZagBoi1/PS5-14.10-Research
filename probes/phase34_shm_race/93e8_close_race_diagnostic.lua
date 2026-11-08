-- CRASH_CLASS: MODERATE
-- PROBE 93e8: socket close race with diagnostic output
--
-- 93e6/93e7 crashed with zero output. This probe prints a marker BEFORE
-- each operation so we can identify which specific syscall triggers the crash.
-- Single operation per section, flush-like output, minimal iterations.

print("=== PROBE 93e8: CLOSE RACE DIAGNOSTIC ===")
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
local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Get eboot base
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
    -- sysarch SET_FSBASE
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)
    -- actual calls
    for _, c in ipairs(calls) do
        if #c >= 2 then put(pdr_lo, pdr_hi); local l,h = split(c[2]); put(l, h) end
        if #c >= 3 then put(psr_lo, psr_hi); local l,h = split(c[3]); put(l, h) end
        if #c >= 4 then put(prdx_lo, prdx_hi); local l,h = split(c[4]); put(l, h) end
        if #c >= 5 then put(prc_lo, prc_hi); local l,h = split(c[5]); put(l, h) end
        if #c >= 6 then put(pr8_lo, pr8_hi); local l,h = split(c[6]); put(l, h) end
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end
    -- signal done
    put(par_lo, par_hi); put(0xD09E93E8, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    -- exit
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)
    -- thr_new param
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

-- Helper: create socketpair, returns fd0, fd1
local function make_pair(typ)
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(typ or 2), uint64(0), sv) end)
    return rd(N(sv)) or -1, rd(N(sv)+4) or -1
end

print("setup done")
print("")

-- ====== TEST A: setsockopt SO_SNDBUF vs close ======
-- setsockopt touches so_snd which is inside the socket struct
print("PRE_A")
for iter = 1, 3 do
    if not alive() then print("DEAD_A_" .. iter); break end
    print(string.format("A_%d_CREATE", iter))
    local fd0, fd1 = make_pair(2)
    if fd0 < 0 then print("A_NOPAIR"); break end

    print(string.format("A_%d_FD=%d,%d", iter, fd0, fd1))
    local done = memory.alloc(8); wd(N(done), 0)

    -- Child will close fd0
    print(string.format("A_%d_SPAWN", iter))
    local ok = spawn_child({{6, fd0}}, N(done))
    if not ok then print("A_NOSPAWN"); pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    -- Main: setsockopt(fd0, SOL_SOCKET, SO_SNDBUF, &val, 4)
    print(string.format("A_%d_SETSOCKOPT", iter))
    local optval = memory.alloc(8); wd(N(optval), 65536)
    local ok_s, rv_s = pcall(function()
        return mk(105)(uint64(fd0), uint64(0xFFFF), uint64(0x1001), uint64(N(optval)), uint64(4))
    end)
    local s_ret = ok_s and N(rv_s) or -999
    if s_ret >= 0x80000000 then s_ret = s_ret - 0x100000000 end

    wait_done(done, 5000)
    print(string.format("A_%d_RET=%d", iter, s_ret))

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print("POST_A")

-- ====== TEST B: getsockname vs close ======
-- getsockname copies from so_pcb
print("")
print("PRE_B")
for iter = 1, 3 do
    if not alive() then print("DEAD_B_" .. iter); break end
    print(string.format("B_%d_CREATE", iter))
    local fd0, fd1 = make_pair(2)
    if fd0 < 0 then print("B_NOPAIR"); break end

    print(string.format("B_%d_FD=%d,%d", iter, fd0, fd1))
    local done = memory.alloc(8); wd(N(done), 0)

    print(string.format("B_%d_SPAWN", iter))
    local ok = spawn_child({{6, fd0}}, N(done))
    if not ok then print("B_NOSPAWN"); pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    -- Main: getsockname(fd0, &addr, &addrlen)
    print(string.format("B_%d_GETSOCKNAME", iter))
    local addr = memory.alloc(128)
    local alen = memory.alloc(8); wd(N(alen), 128)
    local ok_g, rv_g = pcall(function()
        return mk(32)(uint64(fd0), uint64(N(addr)), uint64(N(alen)))
    end)
    local g_ret = ok_g and N(rv_g) or -999
    if g_ret >= 0x80000000 then g_ret = g_ret - 0x100000000 end

    wait_done(done, 5000)
    print(string.format("B_%d_RET=%d", iter, g_ret))

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print("POST_B")

-- ====== TEST C: recvmsg MSG_PEEK vs close ======
-- recvmsg with MSG_PEEK reads from socket buffer without consuming
print("")
print("PRE_C")
for iter = 1, 3 do
    if not alive() then print("DEAD_C_" .. iter); break end
    print(string.format("C_%d_CREATE", iter))
    local fd0, fd1 = make_pair(2)
    if fd0 < 0 then print("C_NOPAIR"); break end

    -- Send data so there's something to peek
    local wbuf = memory.alloc(32)
    for j = 0, 28, 4 do wd(N(wbuf)+j, 0xAA000000+iter) end
    pcall(function() mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(32)) end)

    print(string.format("C_%d_FD=%d,%d", iter, fd0, fd1))
    local done = memory.alloc(8); wd(N(done), 0)

    print(string.format("C_%d_SPAWN", iter))
    local ok = spawn_child({{6, fd1}}, N(done))
    if not ok then print("C_NOSPAWN"); pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    -- Main: recvmsg(fd1, &msg, MSG_PEEK=2)
    print(string.format("C_%d_RECVMSG", iter))
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
    print(string.format("C_%d_RET=%d", iter, r_ret))

    -- Scan for kernel pointers
    if r_ret > 0 then
        for j = 0, math.min(r_ret-1, 56), 4 do
            local lo = rd(N(rbuf)+j) or 0
            local hi = rd(N(rbuf)+j+4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                print(string.format("C_%d_KPTR +%02X: 0x%08X%08X", iter, j, hi, lo))
            end
        end
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print("POST_C")

-- ====== TEST D: shutdown vs close ======
-- shutdown(fd, SHUT_RDWR=2) while child closes the same fd
print("")
print("PRE_D")
for iter = 1, 3 do
    if not alive() then print("DEAD_D_" .. iter); break end
    print(string.format("D_%d_CREATE", iter))
    local fd0, fd1 = make_pair(2)
    if fd0 < 0 then print("D_NOPAIR"); break end

    print(string.format("D_%d_FD=%d,%d", iter, fd0, fd1))
    local done = memory.alloc(8); wd(N(done), 0)

    print(string.format("D_%d_SPAWN", iter))
    local ok = spawn_child({{6, fd0}}, N(done))
    if not ok then print("D_NOSPAWN"); pcall(function() mk(6)(uint64(fd0)) end); pcall(function() mk(6)(uint64(fd1)) end); break end

    -- Main: shutdown(fd0, SHUT_RDWR=2)
    print(string.format("D_%d_SHUTDOWN", iter))
    local ok_h, rv_h = pcall(function()
        return mk(134)(uint64(fd0), uint64(2))
    end)
    local h_ret = ok_h and N(rv_h) or -999
    if h_ret >= 0x80000000 then h_ret = h_ret - 0x100000000 end

    wait_done(done, 5000)
    print(string.format("D_%d_RET=%d", iter, h_ret))

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print("POST_D")

print("")
print("alive=" .. tostring(alive()))
print("=== 93e8 COMPLETE ===")
