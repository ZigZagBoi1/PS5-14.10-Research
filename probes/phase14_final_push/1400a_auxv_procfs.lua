-- CRASH_CLASS: LOW
-- PROBE 1400a: /proc/self/auxv and /proc/<webprocess>/auxv
--
-- Context: cobrajet302gt identified that AT_PHDR from the ELF
-- auxiliary vector gives the program header address, and
-- base = AT_PHDR - e_phoff. If procfs is accessible even partially,
-- this is the cheapest route to any process's text base.
--
-- stat("/proc") returns -1 from the game loader on 14.10, but:
-- 1. The file might exist without stat permission
-- 2. open() might succeed where stat() fails
-- 3. sysctl KERN_PROC_AUXV (MIB 1,14,16,pid) might work
--
-- prior art: 02_webprocess_dump.lua (process enum),
-- docs/VP_SLOT_DELTAS_CORRECTED.md (cobrajet review)

print("=== PROBE 1400a: AUXV / PROCFS TEST ===")
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

local sc_open = make_syscall(5)
local sc_read = make_syscall(3)
local sc_close = make_syscall(6)
local sc_sysctl = make_syscall(202)
local sc_getpid = make_syscall(20)

local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- Helper: try to open and read a path
local function try_read_path(path)
    local pb = memory.alloc(256)
    for i = 1, #path do safe_wd(pb + (i-1), string.byte(path, i)) end
    safe_wd(pb + #path, 0)

    local fd = sc_open(uint64(pb), uint64(0), uint64(0)) -- O_RDONLY
    local fv = to_num(fd)
    if fv < 0 then
        print(string.format("OPEN %s: FAILED (fd=%d)", path, fv))
        return nil
    end

    print(string.format("OPEN %s: fd=%d", path, fv))
    local buf = memory.alloc(0x1000)
    local ret = sc_read(uint64(fv), uint64(buf), uint64(0x1000))
    local bytes = to_num(ret)
    print(string.format("READ %s: %d bytes", path, bytes))

    if bytes > 0 then
        -- Parse auxv entries (16 bytes each: uint64 type, uint64 value)
        local AT_NAMES = {
            [0] = "AT_NULL", [3] = "AT_PHDR", [4] = "AT_PHENT",
            [5] = "AT_PHNUM", [6] = "AT_PAGESZ", [7] = "AT_BASE",
            [9] = "AT_ENTRY", [15] = "AT_EXECPATH"
        }
        for off = 0, bytes - 16, 16 do
            local type_lo = safe_rd(buf + off)
            local type_hi = safe_rd(buf + off + 4)
            local val_q = safe_rq(buf + off + 8)
            if type_lo then
                local name = AT_NAMES[type_lo] or ("AT_" .. type_lo)
                if val_q then
                    local vh, vl = get_hi_lo(val_q)
                    print(string.format("  %s = 0x%08X%08X", name, vh, vl))
                    if type_lo == 3 then
                        print("  *** AT_PHDR FOUND ***")
                        print(string.format("  base (approx) = 0x%08X%08X - 0x40", vh, vl))
                    end
                end
                if type_lo == 0 then break end
            end
        end
    end

    sc_close(uint64(fv))
    return bytes
end

-- === Test 1: /proc/self/auxv ===
print("")
print("=== TEST 1: /proc/self/auxv ===")
local self_paths = {
    "/proc/self/auxv",
    "/proc/curproc/auxv",
    "/proc/" .. pid .. "/auxv",
    "/proc/self/status",
    "/proc/curproc/status",
    "/proc/" .. pid .. "/status",
    "/proc/self/map",
    "/proc/" .. pid .. "/map",
    "/proc/self/exe",
}
for _, p in ipairs(self_paths) do
    try_read_path(p)
end

-- === Test 2: sysctl KERN_PROC_AUXV ===
print("")
print("=== TEST 2: sysctl KERN_PROC_AUXV ===")
-- MIB: CTL_KERN(1), KERN_PROC(14), KERN_PROC_AUXV(16), pid
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 16)  -- KERN_PROC_AUXV
safe_wd(mib + 12, pid)

local outbuf = memory.alloc(0x1000)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x1000)
safe_wd(oldlenp + 4, 0)

local ret = sc_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
local rv = to_num(ret)
print("KERN_PROC_AUXV ret=" .. rv)

if rv == 0 then
    local actual = safe_rd(oldlenp) or 0
    print("AUXV_SIZE: " .. actual)
    local AT_NAMES = {
        [0] = "AT_NULL", [3] = "AT_PHDR", [4] = "AT_PHENT",
        [5] = "AT_PHNUM", [6] = "AT_PAGESZ", [7] = "AT_BASE",
        [9] = "AT_ENTRY", [15] = "AT_EXECPATH"
    }
    for off = 0, actual - 16, 16 do
        local type_lo = safe_rd(outbuf + off)
        local val_q = safe_rq(outbuf + off + 8)
        if type_lo then
            local name = AT_NAMES[type_lo] or ("AT_" .. type_lo)
            if val_q then
                local vh, vl = get_hi_lo(val_q)
                print(string.format("  %s = 0x%08X%08X", name, vh, vl))
                if type_lo == 3 then
                    print("  *** AT_PHDR FOUND ***")
                    -- base = AT_PHDR - e_phoff (typically 0x40)
                    local base_lo = vl - 0x40
                    local base_hi = vh
                    if base_lo < 0 then base_lo = base_lo + 0x100000000; base_hi = base_hi - 1 end
                    print(string.format("  LOADER_BASE = 0x%08X%08X", base_hi, base_lo))
                end
                if type_lo == 9 then
                    print(string.format("  ENTRY_POINT = 0x%08X%08X", vh, vl))
                end
            end
            if type_lo == 0 then break end
        end
    end
else
    print("KERN_PROC_AUXV: BLOCKED (ret=-1)")
end

-- === Test 3: sysctl KERN_PROC_PATHNAME ===
print("")
print("=== TEST 3: sysctl KERN_PROC_PATHNAME ===")
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 12)  -- KERN_PROC_PATHNAME
safe_wd(mib + 12, -1) -- -1 = self
safe_wd(oldlenp, 0x400)
safe_wd(oldlenp + 4, 0)
local path_buf = memory.alloc(0x400)
ret = sc_sysctl(uint64(mib), uint64(4), uint64(path_buf), uint64(oldlenp), uint64(0), uint64(0))
rv = to_num(ret)
print("KERN_PROC_PATHNAME ret=" .. rv)
if rv == 0 then
    local s = ""
    for i = 0, 255 do
        local c = safe_rd(path_buf + i)
        if not c or c == 0 then break end
        if c >= 32 and c < 127 then s = s .. string.char(c) end
    end
    print("PATHNAME: " .. s)
end

-- === Test 4: Try to read WebProcess auxv (need its PID first) ===
print("")
print("=== TEST 4: ENUMERATE FOR WEBPROCESS ===")
-- Get process list to find WebProcess PID
safe_wd(mib, 1); safe_wd(mib + 4, 14); safe_wd(mib + 8, 0) -- KERN_PROC_ALL
safe_wd(oldlenp, 0); safe_wd(oldlenp + 4, 0)
ret = sc_sysctl(uint64(mib), uint64(3), uint64(0), uint64(oldlenp), uint64(0), uint64(0))
local needed = safe_rd(oldlenp) or 0
local web_pids = {}

if needed > 0 and needed < 0x200000 then
    local proc_buf = memory.alloc(needed + 0x2000)
    safe_wd(oldlenp, needed + 0x2000)
    safe_wd(oldlenp + 4, 0)
    ret = sc_sysctl(uint64(mib), uint64(3), uint64(proc_buf), uint64(oldlenp), uint64(0), uint64(0))
    if to_num(ret) == 0 then
        local actual = safe_rd(oldlenp) or 0
        local count = math.floor(actual / 1096)
        for i = 0, count - 1 do
            local base = proc_buf + i * 1096
            local pid_val = safe_rd(base + 0x44) or 0
            local name = ""
            for j = 0, 19 do
                local c = safe_rd(base + 0x1BF + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then name = name .. string.char(c) end
            end
            local nl = name:lower()
            if nl:find("web") or nl:find("browser") then
                print(string.format("WEBPROCESS: pid=%d name=%s", pid_val, name))
                table.insert(web_pids, pid_val)
            end
        end
    end
end

-- Try KERN_PROC_AUXV for each WebProcess PID
for _, wpid in ipairs(web_pids) do
    print("")
    print("=== AUXV for WebProcess pid=" .. wpid .. " ===")
    safe_wd(mib, 1); safe_wd(mib + 4, 14); safe_wd(mib + 8, 16); safe_wd(mib + 12, wpid)
    safe_wd(oldlenp, 0x1000); safe_wd(oldlenp + 4, 0)
    ret = sc_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
    rv = to_num(ret)
    print("AUXV ret=" .. rv)
    if rv == 0 then
        local actual = safe_rd(oldlenp) or 0
        print("AUXV_SIZE: " .. actual)
        for off = 0, actual - 16, 16 do
            local type_lo = safe_rd(outbuf + off)
            local val_q = safe_rq(outbuf + off + 8)
            if type_lo and val_q then
                local vh, vl = get_hi_lo(val_q)
                local AT_NAMES = {[0]="AT_NULL",[3]="AT_PHDR",[9]="AT_ENTRY",[7]="AT_BASE"}
                local name = AT_NAMES[type_lo] or ("AT_" .. type_lo)
                print(string.format("  %s = 0x%08X%08X", name, vh, vl))
                if type_lo == 3 then
                    print("  *** WEBPROCESS AT_PHDR ***")
                    local base_lo = vl - 0x40
                    local base_hi = vh
                    if base_lo < 0 then base_lo = base_lo + 0x100000000; base_hi = base_hi - 1 end
                    print(string.format("  WEBPROCESS_BASE = 0x%08X%08X", base_hi, base_lo))
                end
                if type_lo == 0 then break end
            end
        end
    end
end

print("")
print("=== PROBE 1400a COMPLETE ===")
