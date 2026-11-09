-- CRASH_CLASS: MODERATE
-- PROBE 139a: Survey native sysent 677-734 (58 untested entries)
--
-- Context: These syscalls have never been tested on 14.10.
-- Notable entries from 13.60 sysent:
--   725 = mmap2 (alternative mmap, may bypass W^X checks)
--   728 = virtual_query_by_pid (may leak kernel VM info for other PIDs)
--   734 = cpuset_getaffinity (may leak kernel topology data)
--   727 = posix_fadvise (VM hint, may corrupt page state)
--
-- Strategy: Test each with zero args first (reachability), then
-- targeted arg patterns for promising ones.

print("=== PROBE 139a: SYSENT 677-734 SURVEY ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 139a COMPLETE ===")
    return
end

-- ============================================================
-- PHASE 1: Zero-arg reachability scan 677-734
-- ============================================================
print("")
print("--- PHASE 1: REACHABILITY SCAN ---")

local reachable = {}
local killed = {}

for num = 677, 734 do
    local ok, ret = pcall(function()
        return to_num(native.fcall_with_rax(stub, num, 0, 0, 0, 0, 0, 0))
    end)
    if ok then
        print(string.format("  sys %d: ret=%d", num, ret))
        if ret ~= -1 then
            reachable[num] = ret
        end
    else
        print(string.format("  sys %d: KILLED", num))
        killed[num] = true
        -- Check if still alive
        local alive = pcall(function() return to_num(syscall.getpid()) end)
        if not alive then
            print("*** PROCESS DEAD at sys " .. num .. " ***")
            return
        end
    end
end

print("")
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Deep test promising syscalls
-- ============================================================
print("")
print("--- PHASE 2: DEEP TESTS ---")

-- Test sys 725 (mmap2) — may be alternate mmap with different permission model
print("")
print("[725] mmap2 test:")
local buf725 = memory.alloc(0x100)
safe_wq(buf725, uint64(0))

-- Try mmap2 with various arg layouts
-- Standard mmap2: (addr, len, prot, flags, fd, pgoffset)
-- Try RWX
local m1 = to_num(native.fcall_with_rax(stub, 725, 0, 0x4000, 7, 0x1002, 0xFFFFFFFF, 0))
print("  mmap2(RWX,ANON) ret=" .. string.format("0x%X", m1))

-- Try with prot=5 (RX)
local m2 = to_num(native.fcall_with_rax(stub, 725, 0, 0x4000, 5, 0x1002, 0xFFFFFFFF, 0))
print("  mmap2(RX,ANON) ret=" .. string.format("0x%X", m2))

-- Try standard RW
local m3 = to_num(native.fcall_with_rax(stub, 725, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0))
print("  mmap2(RW,ANON) ret=" .. string.format("0x%X", m3))

-- If any succeeded, check if we can mprotect to RWX
if m3 > 0 and m3 < 0xFFFFFFFF00000000 then
    -- Try mprotect(RWX) on the mmap2 region
    local mp = to_num(native.fcall_with_rax(stub, 74, m3, 0x4000, 7))
    print("  mprotect(RWX) on mmap2 region: ret=" .. mp)
    if mp == 0 then
        print("  *** W^X BYPASS VIA MMAP2 ***")
    end
    -- Cleanup
    native.fcall_with_rax(stub, 73, m3, 0x4000)
end

-- Test sys 728 (virtual_query_by_pid) — may return kernel VM info
print("")
print("[728] virtual_query_by_pid test:")
local outbuf = memory.alloc(0x1000)
safe_wq(outbuf, uint64(0))

-- Try (pid, addr, outbuf, outlen)
local v1 = to_num(native.fcall_with_rax(stub, 728, pid, 0, to_num(outbuf), 0x1000, 0, 0))
print("  (pid,0,buf,4096) ret=" .. v1)

-- Try (outbuf, pid, addr, len)
safe_wq(outbuf, uint64(0))
local v2 = to_num(native.fcall_with_rax(stub, 728, to_num(outbuf), pid, 0, 0x1000, 0, 0))
print("  (buf,pid,0,4096) ret=" .. v2)

-- Try querying pid=0 (kernel) or pid=1 (init)
safe_wq(outbuf, uint64(0))
local v3 = to_num(native.fcall_with_rax(stub, 728, 0, 0, to_num(outbuf), 0x1000, 0, 0))
print("  (0,0,buf,4096) ret=" .. v3)

safe_wq(outbuf, uint64(0))
local v4 = to_num(native.fcall_with_rax(stub, 728, 1, 0, to_num(outbuf), 0x1000, 0, 0))
print("  (1,0,buf,4096) ret=" .. v4)

-- Scan output for kernel pointers
local found_kptr = false
for off = 0, 0xFF0, 8 do
    local v = safe_rq(outbuf + off)
    if is_kptr(v) then
        print(string.format("  *** KPTR at +0x%X: %s ***", off, fmt_addr(v)))
        found_kptr = true
    end
end
if not found_kptr then
    -- Dump first 128 bytes if non-zero
    local has_data = false
    for off = 0, 120, 8 do
        local v = safe_rq(outbuf + off)
        if v then
            local h, l = get_hi_lo(v)
            if h ~= 0 or l ~= 0 then
                has_data = true
                print(string.format("  +0x%02X: %s", off, fmt_addr(v)))
            end
        end
    end
    if not has_data then print("  (output all zeros)") end
end

-- Test sys 734 (cpuset_getaffinity)
print("")
print("[734] cpuset_getaffinity test:")
local cpuset_buf = memory.alloc(128)
safe_wq(cpuset_buf, uint64(0))

-- cpuset_getaffinity(level, which, id, setsize, mask)
-- level: CPU_LEVEL_ROOT=1, CPU_LEVEL_CPUSET=2, CPU_LEVEL_WHICH=3
-- which: CPU_WHICH_TID=1, CPU_WHICH_PID=2, CPU_WHICH_CPUSET=3
local ca1 = to_num(native.fcall_with_rax(stub, 734,
    1, 2, pid, 128, to_num(cpuset_buf), 0))
print("  (ROOT,PID,self,128) ret=" .. ca1)

if ca1 == 0 then
    local mask_lo = safe_rq(cpuset_buf)
    print("  CPU mask: " .. fmt_addr(mask_lo))
end

-- Try CPU_LEVEL_WHICH
safe_wq(cpuset_buf, uint64(0))
local ca2 = to_num(native.fcall_with_rax(stub, 734,
    3, 2, pid, 128, to_num(cpuset_buf), 0))
print("  (WHICH,PID,self,128) ret=" .. ca2)

-- Test sys 727 (posix_fadvise)
print("")
print("[727] posix_fadvise test:")
-- posix_fadvise(fd, offset, len, advice)
-- If we can fadvise on a socket fd, it may hit different kernel path
local test_sock = to_num(native.fcall_with_rax(stub, 97, 2, 2, 17))
if test_sock >= 0 then
    for advice = 0, 5 do
        local fa = to_num(native.fcall_with_rax(stub, 727,
            test_sock, 0, 0x10000, advice, 0, 0))
        print(string.format("  fd=%d advice=%d ret=%d", test_sock, advice, fa))
    end
    native.fcall_with_rax(stub, 6, test_sock)
end

print("")
print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Test remaining interesting entries
-- ============================================================
print("")
print("--- PHASE 3: ADDITIONAL TESTS ---")

-- Any syscall that returned ret=0 in Phase 1 gets a deeper test
for num, ret in pairs(reachable) do
    if num ~= 725 and num ~= 728 and num ~= 734 and num ~= 727 then
        print(string.format("[%d] ret=%d — testing with output buffer", num, ret))
        local tb = memory.alloc(0x200)
        safe_wq(tb, uint64(0))

        -- Try (buf, size) pattern
        local r1 = to_num(native.fcall_with_rax(stub, num,
            to_num(tb), 0x200, 0, 0, 0, 0))
        print(string.format("  (buf,0x200) ret=%d", r1))

        -- Check for kernel pointers
        for off = 0, 0x1F0, 8 do
            local v = safe_rq(tb + off)
            if is_kptr(v) then
                print(string.format("  *** KPTR at +0x%X: %s ***", off, fmt_addr(v)))
            end
        end

        -- Try (pid, buf, size)
        safe_wq(tb, uint64(0))
        local r2 = to_num(native.fcall_with_rax(stub, num,
            pid, to_num(tb), 0x200, 0, 0, 0))
        if r2 ~= r1 then
            print(string.format("  (pid,buf,0x200) ret=%d", r2))
        end
    end
end

-- VM counter
local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 139a COMPLETE ===")
