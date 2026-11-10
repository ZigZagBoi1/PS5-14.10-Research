-- CRASH_CLASS: LOW
-- PROBE p803: /proc auxv file test (Arm 2 — cobrajet302gt, PR #240)
--
-- Context: RVA is a link-time fact, not derivable from source alone.
-- If /proc/<pid>/auxv is readable, AT_PHDR - e_phoff = binary base.
-- sysctl KERN_PROC_AUXV already measured negative (probe 56g3).
-- This probe tests the genuinely unmeasured /proc FILE leg.
--
-- Null-class prenote: ENOENT on /proc is ambiguous between "procfs not
-- mounted" and "auxv not exposed." We distinguish by opening a bare
-- /proc/<pid>/ path first — directory-list failure vs auxv-specific
-- failure are different verdicts.
--
-- prior art: 56g3 (sysctl auxv → "not available"), 392f (stat /proc → -1)

print("=== PROBE p803: /proc auxv file test ===")
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
local function hex64(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

-- Syscall numbers (FreeBSD)
local SYS_READ    = 3
local SYS_WRITE   = 4
local SYS_OPEN    = 5
local SYS_CLOSE   = 6
local SYS_GETPID  = 20
local SYS_STAT    = 188
local SYS_SYSCTL  = 202

local sc_open   = make_syscall(SYS_OPEN)
local sc_read   = make_syscall(SYS_READ)
local sc_close  = make_syscall(SYS_CLOSE)
local sc_getpid = make_syscall(SYS_GETPID)
local sc_stat   = make_syscall(SYS_STAT)
local sc_sysctl = make_syscall(SYS_SYSCTL)

-- Get our PID
local pid = 0
do
    local ok, rv = pcall(function() return sc_getpid() end)
    if ok then pid = to_num(rv) end
end
print(string.format("PID: %d (0x%X)", pid, pid))

-- Helper: write a string into a buffer and return (buf, len)
local function make_path(str)
    local buf = memory.alloc(#str + 16)
    for i = 1, #str do
        safe_wd(buf + (i - 1), string.byte(str, i))
    end
    safe_wd(buf + #str, 0)
    return buf
end

-- Helper: try open(path, O_RDONLY) and return fd or -1
local O_RDONLY = 0
local function try_open(path_str)
    local pbuf = make_path(path_str)
    local ok, rv = pcall(function()
        return sc_open(uint64(pbuf), uint64(O_RDONLY), uint64(0))
    end)
    if not ok then return -1 end
    local ret = to_num(rv)
    if ret >= 0x80000000 then return -1 end
    return ret
end

-- Helper: try stat(path) and return 0 or -1
local function try_stat(path_str)
    local pbuf = make_path(path_str)
    local sbuf = memory.alloc(256)
    local ok, rv = pcall(function()
        return sc_stat(uint64(pbuf), uint64(sbuf))
    end)
    if not ok then return -1 end
    return to_num(rv)
end

-- Helper: read from fd into buffer, return bytes read or -1
local function try_read(fd, buf, size)
    local ok, rv = pcall(function()
        return sc_read(uint64(fd), uint64(buf), uint64(size))
    end)
    if not ok then return -1 end
    local ret = to_num(rv)
    if ret >= 0x80000000 then return -1 end
    return ret
end

print("")
print("=== SECTION A: procfs existence test ===")
print("")

local paths_exist = {
    "/proc",
    "/proc/self",
    "/proc/curproc",
    string.format("/proc/%d", pid),
}

local procfs_exists = false
for _, p in ipairs(paths_exist) do
    local rv = try_stat(p)
    print(string.format("  stat('%s') = %d", p, rv))
    if rv == 0 then procfs_exists = true end
end

if not procfs_exists then
    print("")
    print("VERDICT: procfs not mounted or not accessible.")
    print("This is ENOENT-no-procfs, not ENOENT-no-auxv.")
    print("The /proc leg is closed for this jail context.")
end

print("")
print("=== SECTION B: /proc auxv file read ===")
print("")

local auxv_paths = {
    "/proc/self/auxv",
    "/proc/curproc/auxv",
    string.format("/proc/%d/auxv", pid),
}

-- Also try some other /proc paths to see what's accessible
local other_proc_paths = {
    "/proc/self/status",
    "/proc/self/map",
    "/proc/self/exe",
    string.format("/proc/%d/status", pid),
    string.format("/proc/%d/map", pid),
}

local auxv_fd = -1
local auxv_path_used = ""

for _, p in ipairs(auxv_paths) do
    local fd = try_open(p)
    print(string.format("  open('%s') = %d", p, fd))
    if fd >= 0 then
        auxv_fd = fd
        auxv_path_used = p
        break
    end
end

if auxv_fd < 0 then
    print("")
    print("No auxv file readable. Trying other /proc paths...")
    print("")
    for _, p in ipairs(other_proc_paths) do
        local fd = try_open(p)
        print(string.format("  open('%s') = %d", p, fd))
        if fd >= 0 then
            local tmpbuf = memory.alloc(256)
            local nr = try_read(fd, tmpbuf, 256)
            print(string.format("    read = %d bytes", nr))
            pcall(function() sc_close(uint64(fd)) end)
        end
    end
end

if auxv_fd >= 0 then
    print(string.format("\nSUCCESS: auxv open at '%s', fd=%d", auxv_path_used, auxv_fd))
    print("")

    -- Read auxv entries: each is { uint64 type, uint64 value } = 16 bytes
    local auxbuf = memory.alloc(4096)
    local nr = try_read(auxv_fd, auxbuf, 4096)
    print(string.format("  read = %d bytes", nr))
    pcall(function() sc_close(uint64(auxv_fd)) end)

    if nr > 0 then
        print("")
        print("  Auxv entries (type, value):")
        -- FreeBSD auxv types we care about:
        -- AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_ENTRY = 9, AT_BASE = 7
        -- AT_NULL = 0 (terminator)
        local AT_NAMES = {
            [0] = "AT_NULL", [1] = "AT_IGNORE", [2] = "AT_EXECFD",
            [3] = "AT_PHDR", [4] = "AT_PHENT", [5] = "AT_PHNUM",
            [6] = "AT_PAGESZ", [7] = "AT_BASE", [8] = "AT_FLAGS",
            [9] = "AT_ENTRY", [15] = "AT_EXECPATH", [16] = "AT_CANARY",
            [17] = "AT_CANARYLEN", [18] = "AT_OSRELDATE", [19] = "AT_NCPUS",
            [20] = "AT_PAGESIZES", [21] = "AT_PAGESIZESLEN",
            [22] = "AT_TIMEKEEP", [23] = "AT_STACKPROT",
            [24] = "AT_EHDRFLAGS", [25] = "AT_HWCAP", [26] = "AT_HWCAP2",
        }

        local at_phdr = nil
        local at_entry = nil
        local at_base = nil

        local off = 0
        while off + 16 <= nr do
            local type_val = safe_rq(auxbuf + off)
            local value    = safe_rq(auxbuf + off + 8)
            local type_num = to_num(type_val)
            local name = AT_NAMES[type_num] or string.format("AT_%d", type_num)

            print(string.format("    [%s] type=%d value=%s", name, type_num, hex64(value)))

            if type_num == 3 then at_phdr = value end
            if type_num == 9 then at_entry = value end
            if type_num == 7 then at_base = value end
            if type_num == 0 then break end

            off = off + 16
        end

        print("")
        if at_phdr then
            print(string.format("  AT_PHDR = %s", hex64(at_phdr)))
            -- e_phoff for a typical ELF is 0x40 (64-byte ELF header)
            -- base = AT_PHDR - e_phoff
            -- We assume standard e_phoff = 0x40
            local h, l = get_hi_lo(at_phdr)
            local base_l = l - 0x40
            local base_h = h
            if base_l < 0 then base_h = base_h - 1; base_l = base_l + 0x100000000 end
            print(string.format("  Estimated base (AT_PHDR - 0x40) = 0x%X%08X", base_h, base_l))
            print("  NOTE: this is the GAME PROCESS base, not WebProcess.")
            print("  WebProcess base requires reading WebProcess auxv (different PID).")
        else
            print("  AT_PHDR not found in auxv.")
        end
        if at_entry then print(string.format("  AT_ENTRY = %s", hex64(at_entry))) end
        if at_base then print(string.format("  AT_BASE  = %s", hex64(at_base))) end
    end
else
    print("")
    print("VERDICT: /proc auxv not readable from game process.")
end

print("")
print("=== SECTION C: sysctl KERN_PROC_AUXV (confirming line) ===")
print("")

-- MIB: { CTL_KERN=1, KERN_PROC=14, KERN_PROC_AUXV=16, pid }
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 16)  -- KERN_PROC_AUXV
safe_wd(mib + 12, pid)

local outbuf = memory.alloc(4096)
local oldlenp = memory.alloc(8)
safe_wq(oldlenp, uint64(4096))

local ok_sc, rv_sc = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
local ret_sc = -999
if ok_sc then ret_sc = to_num(rv_sc) end
local outlen = to_num(safe_rq(oldlenp))

print(string.format("  sysctl(KERN_PROC_AUXV, pid=%d) = %d, outlen=%d", pid, ret_sc, outlen))

if ret_sc == 0 and outlen > 0 then
    print(string.format("  SUCCESS: %d bytes of auxv from sysctl", outlen))
    local off = 0
    while off + 16 <= outlen do
        local type_val = safe_rq(outbuf + off)
        local value    = safe_rq(outbuf + off + 8)
        local type_num = to_num(type_val)
        if type_num == 0 then break end
        print(string.format("    type=%d value=%s", type_num, hex64(value)))
        off = off + 16
    end
else
    print("  Confirming: sysctl KERN_PROC_AUXV not available (matches probe 56g3).")
end

print("")
print("=== SECTION D: cross-process auxv (WebProcess PID discovery) ===")
print("")

-- Try PIDs near ours — WebProcess may be a nearby PID
-- Also try common patterns: pid+1, pid-1, sequential scan of a few PIDs
local test_pids = {}
for delta = -5, 10 do
    local tp = pid + delta
    if tp > 0 and tp ~= pid then
        table.insert(test_pids, tp)
    end
end

-- Try opening /proc/<pid>/auxv for nearby PIDs
local found_any = false
for _, tp in ipairs(test_pids) do
    local path = string.format("/proc/%d/auxv", tp)
    local fd = try_open(path)
    if fd >= 0 then
        found_any = true
        print(string.format("  open('/proc/%d/auxv') = %d (SUCCESS!)", tp, fd))
        local tmpbuf = memory.alloc(4096)
        local nr = try_read(fd, tmpbuf, 4096)
        print(string.format("    read = %d bytes", nr))
        if nr > 0 then
            local off = 0
            while off + 16 <= nr do
                local type_val = safe_rq(tmpbuf + off)
                local value    = safe_rq(tmpbuf + off + 8)
                local type_num = to_num(type_val)
                if type_num == 0 then break end
                if type_num == 3 or type_num == 9 then
                    print(string.format("    type=%d value=%s", type_num, hex64(value)))
                end
                off = off + 16
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

if not found_any then
    if procfs_exists then
        print("  No cross-process auxv readable (permission denied or no procfs entries).")
    else
        print("  Skipped (procfs not mounted).")
    end
end

print("")
print("=== COMPLETE ===")
