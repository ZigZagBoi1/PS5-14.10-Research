-- CRASH_CLASS: LOW
-- PROBE: Overnight Test Harness (self-contained)
--
-- Runs a comprehensive battery of tests in a single connection.
-- Designed to be the last payload sent before sleeping --
-- it tests everything we need and sends results line by line.
--
-- Tests included:
-- 1. System identification (FW version, PID, process name)
-- 2. Full process VM map via sys 674
-- 3. All 39 modules via dynlib_get_info (593)
-- 4. Credential structure (587)
-- 5. Sony syscall survey (accessible range)
-- 6. Device node inventory (/dev/*)
-- 7. Kernel pointer scan across all outputs
-- 8. Network interface enumeration
-- 9. File system enumeration (stat on key paths)

print("=== OVERNIGHT HARNESS v1 ===")
print("TIMESTAMP: " .. os.date("%Y-%m-%d %H:%M:%S"))
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

local total_kptrs = 0
local function check_kptr(source, off, val)
    if not val then return end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
        print(string.format("!KPTR[%s+0x%X] = 0x%08X%08X", source, off, h, l))
        total_kptrs = total_kptrs + 1
    elseif h == 0xFFFFFFFF and l ~= 0 and l ~= 0xFFFFFFFF and l > 0x1000 then
        print(string.format("!KPTR[%s+0x%X] = 0x%08X%08X", source, off, h, l))
        total_kptrs = total_kptrs + 1
    end
end

-- === TEST 1: System Identification ===
print("=== TEST 1: SYSTEM ID ===")
local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1); safe_wd(mib+4, 2)  -- KERN_OSRELEASE
local outbuf = memory.alloc(256)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 256)
local ret = sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
if to_num(ret) == 0 then
    local s = ""
    for i = 0, 63 do
        local c = safe_rd(outbuf + i)
        if not c or c == 0 then break end
        s = s .. string.char(c % 256)
    end
    print("OSRELEASE: " .. s)
end

-- hw.model
safe_wd(mib, 6); safe_wd(mib+4, 2)  -- HW_MODEL
safe_wd(oldlenp, 256)
ret = sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
if to_num(ret) == 0 then
    local s = ""
    for i = 0, 47 do
        local c = safe_rd(outbuf + i)
        if not c or c == 0 then break end
        s = s .. string.char(c % 256)
    end
    print("HW_MODEL: " .. s)
end

-- === TEST 2: Eboot base + module map ===
print("")
print("=== TEST 2: MODULE MAP ===")
local sc_info = make_syscall(593)
local mod_count = 0
for handle = 0, 255 do
    local ibuf = memory.alloc(0x200)
    safe_wd(ibuf, 0x160)
    local ok = pcall(function() sc_info(uint64(handle), ibuf) end)
    if ok then
        local tlo = safe_rd(ibuf + 0x108)
        local thi = safe_rd(ibuf + 0x10C)
        local tslo = safe_rd(ibuf + 0x110)
        local tshi = safe_rd(ibuf + 0x114)
        if thi and thi > 0 then
            -- Read name
            local nm = ""
            for j = 0, 31 do
                local c = safe_rd(ibuf + 8 + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then nm = nm .. string.char(c) end
            end
            print(string.format("MOD[%03d] base=%08X%08X size=%08X%08X %s",
                handle, thi, tlo, tshi or 0, tslo or 0, nm))
            mod_count = mod_count + 1

            -- Scan module info for kernel pointers
            for off = 0, 0x158, 8 do
                check_kptr("mod" .. handle, off, safe_rq(ibuf + off))
            end
        end
    end
end
print("MODULE_COUNT: " .. mod_count)

-- === TEST 3: VM Map ===
print("")
print("=== TEST 3: VM MAP (sys 674) ===")
local sc_vm = make_syscall(674)
local vm_buf = memory.alloc(0x10000)
local count_ptr = memory.alloc(8)
safe_wd(count_ptr, 1024)
local vm_ret = sc_vm(uint64(0), uint64(vm_buf), uint64(count_ptr))
if to_num(vm_ret) == 0 then
    local n = safe_rd(count_ptr) or 0
    print("VM_ENTRIES: " .. n)
    for i = 0, math.min(n-1, 511) do
        local base = vm_buf + i * 72
        local sq = safe_rq(base)
        local eq = safe_rq(base + 8)
        local p = safe_rd(base + 0x18)
        if sq and eq then
            local sh, sl = get_hi_lo(sq)
            local eh, el = get_hi_lo(eq)
            local nm = ""
            for j = 0, 31 do
                local c = safe_rd(base + 0x20 + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then nm = nm .. string.char(c) end
            end
            print(string.format("VM[%03d] %08X%08X-%08X%08X p=0x%X %s",
                i, sh, sl, eh, el, p or 0, nm))
        end
    end
end

-- === TEST 4: Sony syscall survey ===
print("")
print("=== TEST 4: SONY SYSCALL SURVEY ===")
-- Install SIGSYS handler first
local sc_sigaction = make_syscall(416)
local sa = memory.alloc(0x20)
safe_wq(sa, uint64(1))  -- SIG_IGN
local old_sa = memory.alloc(0x20)
pcall(function() sc_sigaction(uint64(12), uint64(sa), uint64(old_sa)) end)

-- Test key Sony syscalls
local sony_calls = {
    530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540,
    547, 548, 549, 557, 558, 559, 560, 563, 564, 565, 566,
    567, 572, 585, 587, 588, 593, 596, 598, 601, 606, 608,
    612, 615, 620, 622, 624, 626, 628, 629, 630, 631, 637,
    638, 639, 640, 641, 642, 643, 646, 647, 649, 656, 657,
    659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669,
    670, 671, 672, 673, 674, 675, 676,
}

for _, num in ipairs(sony_calls) do
    local sc = make_syscall(num)
    local ok, r = pcall(function() return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        print(string.format("SYS[%d] ret=%d", num, to_num(r)))
    else
        print(string.format("SYS[%d] PCALL_FAIL", num))
    end
end

-- === TEST 5: Credential check ===
print("")
print("=== TEST 5: CREDENTIALS (sys 587) ===")
local sc_587 = make_syscall(587)
local cred = memory.alloc(0x200)
safe_wd(cred, 0x200)
local cr = sc_587(uint64(0), uint64(cred))
if to_num(cr) == 0 then
    local cap = safe_rd(cred + 0x0C)
    print("CRED_CAP: " .. string.format("0x%08X", cap or 0))
    for off = 0, 0x88, 8 do
        check_kptr("cred", off, safe_rq(cred + off))
    end
end

-- === TEST 6: Device inventory ===
print("")
print("=== TEST 6: DEVICE INVENTORY ===")
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local devices = {
    "/dev/gc", "/dev/dce", "/dev/ajm", "/dev/dmem0", "/dev/dmem1",
    "/dev/dmem2", "/dev/camera", "/dev/usb", "/dev/hid", "/dev/bt",
    "/dev/rng", "/dev/gic", "/dev/zero", "/dev/null", "/dev/random",
    "/dev/urandom",
}
for _, dev in ipairs(devices) do
    local path_buf = memory.alloc(64)
    for i = 1, #dev do
        safe_wd(path_buf + (i-1), string.byte(dev, i))
    end
    safe_wd(path_buf + #dev, 0)
    local fd = sc_open(uint64(path_buf), uint64(2), uint64(0))  -- O_RDWR
    local fv = to_num(fd)
    if fv < 0 then
        fd = sc_open(uint64(path_buf), uint64(0), uint64(0))  -- O_RDONLY
        fv = to_num(fd)
    end
    print(string.format("DEV[%s] fd=%d", dev, fv))
    if fv >= 0 then sc_close(uint64(fv)) end
end

-- === TEST 7: File system paths ===
print("")
print("=== TEST 7: FILESYSTEM ===")
local sc_stat = make_syscall(188)
local paths = {
    "/", "/dev", "/app0", "/app0/eboot.bin", "/system_tmp",
    "/system", "/data", "/proc", "/tmp", "/mnt",
    "/dev/kmem", "/dev/mem",
}
for _, p in ipairs(paths) do
    local pb = memory.alloc(256)
    for i = 1, #p do safe_wd(pb + (i-1), string.byte(p, i)) end
    safe_wd(pb + #p, 0)
    local sb = memory.alloc(256)
    local sr = sc_stat(uint64(pb), uint64(sb))
    print(string.format("STAT[%s] ret=%d", p, to_num(sr)))
end

-- === SUMMARY ===
print("")
print("=== OVERNIGHT HARNESS SUMMARY ===")
print("MODULES: " .. mod_count)
print("KERNEL_PTRS_FOUND: " .. total_kptrs)
print("TESTS_COMPLETE: 7")
print("")
print("=== OVERNIGHT HARNESS v1 COMPLETE ===")
