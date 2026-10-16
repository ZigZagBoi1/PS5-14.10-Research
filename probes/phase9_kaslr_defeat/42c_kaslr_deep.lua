-- CRASH_CLASS: SAFE (read-only enumeration, no dangerous syscalls)
-- PROBE 42c: Deep KASLR defeat — full struct dumps
--
-- From 42b:
--   kinfo_proc +0x060 = FFFFFFFF_00000000 (sanitized — low bits zeroed)
--   libkernel.sprx at 0x82D4B0000
--   39 modules loaded
--   FS base at 0x881014080 (userspace TCB)
--   kldsym(337) and kldstat(306) both hard-crash
--
-- This probe:
--   A) Full kinfo_proc dump — every qword of all 1096 bytes
--   B) Full dynlib_get_info struct for libkernel — every qword
--   C) Extended TCB read — 0x200 bytes from FS base
--   D) machdep sysctl namespace
--   E) Check if any dynlib info has kernel-range addresses
--   F) Try pipe/socket fd kernel object leak via fstat

print("=== PROBE 42c: DEEP KASLR ===")
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
local sc_pipe = make_syscall(42)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local kptrs = {}

--------------------------------------------------------------------
-- A) Full kinfo_proc — every qword
--------------------------------------------------------------------
print("")
print("=== A: FULL KINFO_PROC (1096 bytes) ===")
do
    local mib = memory.alloc(16)
    safe_wd(mib, 1); safe_wd(mib+4, 14); safe_wd(mib+8, 1); safe_wd(mib+12, pid)
    local out = memory.alloc(0x1000)
    for i = 0, 0xFF, 4 do safe_wd(out+i, 0) end
    local lenp = memory.alloc(8)
    safe_wd(lenp, 0x1000)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(out), uint64(lenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local alen = safe_rd(lenp) or 0

    if rv == 0 then
        for off = 0, alen - 8, 8 do
            local q = safe_rq(out + off)
            if q then
                local h, l = get_hi_lo(q)
                if h ~= 0 or l ~= 0 then
                    local tag = ""
                    if h >= 0xFFFF8000 then tag = " KPTR!"; kptrs[#kptrs+1] = {src="kinfo", off=off, h=h, l=l} end
                    if h >= 0x80000000 and h < 0xFFFF0000 then tag = " HIGH?" end
                    if h > 0 or l > 0x10000000 then
                        print(string.format("  +%03X: %08X_%08X%s", off, h, l, tag))
                    end
                end
            end
        end
    else
        print("  sysctl failed: " .. rv)
    end
end

--------------------------------------------------------------------
-- B) Full dynlib_get_info for libkernel (handle=8193)
--------------------------------------------------------------------
print("")
print("=== B: LIBKERNEL DYNLIB INFO ===")
do
    local sc_dgi = make_syscall(593)
    local info = memory.alloc(0x200)
    for i = 0, 0x1F8, 4 do safe_wd(info+i, 0) end
    safe_wd(info, 0x160)

    local ok = pcall(function() sc_dgi(uint64(8193), info) end)
    if ok then
        for off = 0, 0x158, 8 do
            local q = safe_rq(info + off)
            if q then
                local h, l = get_hi_lo(q)
                if h ~= 0 or l ~= 0 then
                    local tag = ""
                    if h >= 0xFFFF8000 then tag = " KPTR!"; kptrs[#kptrs+1] = {src="libk_info", off=off, h=h, l=l} end
                    print(string.format("  +%03X: %08X_%08X%s", off, h, l, tag))
                end
            end
        end
    else
        print("  dynlib_get_info failed for libkernel")
    end
end

--------------------------------------------------------------------
-- C) Extended TCB — 0x200 bytes from FS base
--------------------------------------------------------------------
print("")
print("=== C: EXTENDED TCB ===")
do
    local sc_sysarch = make_syscall(165)
    local addr_buf = memory.alloc(16)
    safe_wd(addr_buf, 0); safe_wd(addr_buf+4, 0)
    local ok_fs = pcall(function() sc_sysarch(uint64(128), uint64(addr_buf)) end)
    local fs_q = safe_rq(addr_buf)
    if fs_q then
        local fsh, fsl = get_hi_lo(fs_q)
        print(string.format("  FS base: %08X_%08X", fsh, fsl))
        if fsh > 0 or fsl > 0x10000 then
            local fs_addr = uint64(fs_q)
            for off = 0, 0x1F8, 8 do
                local q = safe_rq(fs_addr + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h ~= 0 or l ~= 0 then
                        local tag = ""
                        if h >= 0xFFFF8000 then tag = " KPTR!"; kptrs[#kptrs+1] = {src="tcb", off=off, h=h, l=l} end
                        print(string.format("  +%03X: %08X_%08X%s", off, h, l, tag))
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- D) machdep sysctl namespace — try various MIBs
--------------------------------------------------------------------
print("")
print("=== D: MACHDEP SYSCTL ===")
do
    local function try_sysctl(label, mib_vals, sz)
        sz = sz or 0x100
        local mib = memory.alloc(#mib_vals * 4)
        for i, v in ipairs(mib_vals) do safe_wd(mib+(i-1)*4, v) end
        local out = memory.alloc(sz)
        for i = 0, math.min(sz-1, 0x3F), 4 do safe_wd(out+i, 0) end
        local lenp = memory.alloc(8)
        safe_wd(lenp, sz)
        local ok, ret = pcall(function()
            return sc_sysctl(uint64(mib), uint64(#mib_vals), uint64(out), uint64(lenp), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local alen = safe_rd(lenp) or 0
        if rv ~= 0 then
            print(string.format("  %s: ret=%d", label, rv))
            return
        end
        for off = 0, math.min(alen-1, sz-8), 8 do
            local q = safe_rq(out+off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("  %s +%03X: %08X_%08X KPTR!", label, off, h, l))
                    kptrs[#kptrs+1] = {src="sysctl:"..label, off=off, h=h, l=l}
                elseif h ~= 0 or l ~= 0 then
                    if alen <= 16 then
                        print(string.format("  %s: %08X_%08X", label, h, l))
                    end
                end
            end
        end
        if alen > 16 then print(string.format("  %s: len=%d (no kptrs)", label, alen)) end
    end

    -- machdep = CTL 7
    try_sysctl("machdep.tsc_freq", {7, 1}, 8)
    -- debug = CTL 5
    try_sysctl("debug.ncpus", {5, 1}, 8)
    try_sysctl("debug.witness", {5, 2}, 8)
    -- security = CTL 14
    try_sysctl("security.bsd.see_other_uids", {14, 1, 1}, 4)
    try_sysctl("security.bsd.unprivileged_read_msgbuf", {14, 1, 3}, 4)
    -- net.inet = {4, 2}
    try_sysctl("net.inet.tcp.mssdflt", {4, 2, 6, 4}, 4)
    -- kern.smp.cpus name2oid then read
    -- try direct: kern.smp = {1, 12}?
    try_sysctl("kern.smp.active", {1, 12, 1}, 4)
    try_sysctl("kern.smp.cpus", {1, 12, 2}, 4)
end

--------------------------------------------------------------------
-- E) fstat (syscall 551 or 189) — check if fd metadata leaks kptrs
--------------------------------------------------------------------
print("")
print("=== E: FSTAT KERNEL LEAK ===")
do
    local sc_fstat = make_syscall(189)
    local stat_buf = memory.alloc(0x100)
    for i = 0, 0xF8, 4 do safe_wd(stat_buf+i, 0) end

    -- fstat on stdin (fd 0)
    local ok, ret = pcall(function()
        return sc_fstat(uint64(0), uint64(stat_buf))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  fstat(0): ret=%d", rv))
    if rv == 0 then
        for off = 0, 0x70, 8 do
            local q = safe_rq(stat_buf+off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("    +%03X: %08X_%08X KPTR!", off, h, l))
                    kptrs[#kptrs+1] = {src="fstat", off=off, h=h, l=l}
                elseif h ~= 0 or l ~= 0 then
                    print(string.format("    +%03X: %08X_%08X", off, h, l))
                end
            end
        end
    end

    -- also try a pipe fd
    local pipe_buf = memory.alloc(8)
    local ok_p = pcall(function() sc_pipe(uint64(pipe_buf)) end)
    if ok_p then
        local pfd0 = safe_rd(pipe_buf)
        if pfd0 and pfd0 > 0 then
            for i = 0, 0xF8, 4 do safe_wd(stat_buf+i, 0) end
            pcall(function() sc_fstat(uint64(pfd0), uint64(stat_buf)) end)
            print(string.format("  fstat(pipe fd %d):", pfd0))
            for off = 0, 0x70, 8 do
                local q = safe_rq(stat_buf+off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 then
                        print(string.format("    +%03X: %08X_%08X KPTR!", off, h, l))
                        kptrs[#kptrs+1] = {src="fstat_pipe", off=off, h=h, l=l}
                    elseif h ~= 0 or l ~= 0 then
                        print(string.format("    +%03X: %08X_%08X", off, h, l))
                    end
                end
            end
            local sc_close = make_syscall(6)
            pcall(function() sc_close(uint64(pfd0)) end)
            local pfd1 = safe_rd(pipe_buf+4)
            if pfd1 then pcall(function() sc_close(uint64(pfd1)) end) end
        end
    end
end

--------------------------------------------------------------------
-- F) Try getdirentries (syscall 272) on /dev
--------------------------------------------------------------------
print("")
print("=== F: PROC SELF FD SCAN ===")
do
    -- Try reading /proc/self or /dev/deci — unlikely but worth a shot
    local sc_open = make_syscall(5)
    local path_buf = memory.alloc(64)

    local paths = {"/dev/deci", "/dev/dmem0", "/dev/hid"}
    for _, path in ipairs(paths) do
        for i = 1, #path do memory.write_byte(path_buf+(i-1), string.byte(path, i)) end
        memory.write_byte(path_buf + #path, 0)

        local ok_o, fd = pcall(function()
            return sc_open(uint64(path_buf), uint64(0), uint64(0))  -- O_RDONLY
        end)
        local fdv = ok_o and to_num(fd) or -1
        print(string.format("  open(%s): fd=%d", path, fdv))
        if fdv >= 0 then
            local sc_close = make_syscall(6)
            pcall(function() sc_close(uint64(fdv)) end)
        end
    end
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== SUMMARY ===")
print("kernel pointers found: " .. #kptrs)
for _, kp in ipairs(kptrs) do
    print(string.format("  [%s +%03X] %08X_%08X", kp.src, kp.off, kp.h, kp.l))
end

if #kptrs == 0 then
    print("  still no unsanitized kernel pointers")
    print("  next: use ropchain to call libkernel internal funcs")
end

print("")
print("=== PROBE 42c COMPLETE ===")
