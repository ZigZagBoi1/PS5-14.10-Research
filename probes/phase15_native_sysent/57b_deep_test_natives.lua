-- CRASH_CLASS: MODERATE
-- PROBE 57b: Deep test interesting native-only syscalls
--
-- Context: Follow-up to 57a survey. Deep tests the most promising syscalls
-- from the native sysent 677-734 range with varied arg patterns, looking
-- for kernel pointer leaks, new primitives, or W^X bypass paths.
-- Focus: virtual_query_by_pid(728), mmap2(725), procctl(689), pipe2(687),
--        openintr(716), dl_get_info_2(717), workspace_ctrl(722)

print("=== PROBE 57b: DEEP TEST NATIVE SYSCALLS ===")
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

local function hex_dump(base, len)
    for row = 0, len - 1, 0x10 do
        local vals = {}
        for col = 0, 0xC, 4 do
            if row + col < len then
                vals[#vals+1] = string.format("%08X", safe_rd(base + row + col) or 0)
            end
        end
        print(string.format("    +%03X: %s", row, table.concat(vals, " ")))
    end
end

local function scan_kptrs(base, len)
    local count = 0
    for off = 0, len - 8, 8 do
        local q = safe_rq(base + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    *** KPTR +0x%04X: %08X_%08X ***", off, h, l))
                count = count + 1
                if count >= 30 then
                    print("    (capped at 30)")
                    return count
                end
            end
        end
    end
    if count == 0 then print("    No kernel pointers found") end
    return count
end

local function clear_buf(buf, dwords)
    for i = 0, dwords - 1 do safe_wd(buf + i*4, 0) end
end

local sc_getpid = make_syscall(20)
local pid_ok, pid_val = pcall(function() return sc_getpid() end)
local pid = pid_ok and to_num(pid_val) or 0
print("PID: " .. pid)

-- Get eboot base for reference
local eboot_info = memory.alloc(0x200)
safe_wd(eboot_info, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), eboot_info) end)
local eboot_lo = safe_rd(eboot_info + 0x108) or 0
local eboot_hi = safe_rd(eboot_info + 0x10C) or 0
print(string.format("Eboot text base: %08X_%08X", eboot_hi, eboot_lo))
print("")

local outbuf = memory.alloc(0x4000)

-- =====================================================
print("=== SECTION A: virtual_query_by_pid (728) DEEP ===")
print("")
-- =====================================================
local sc728 = make_syscall(728)

-- Try different arg layouts
local layouts = {
    {name="(pid,buf,size,0,0,0)", args=function(b) return uint64(pid), uint64(b), uint64(0x4000), uint64(0), uint64(0), uint64(0) end},
    {name="(pid,0,buf,size,0,0)", args=function(b) return uint64(pid), uint64(0), uint64(b), uint64(0x4000), uint64(0), uint64(0) end},
    {name="(0,pid,buf,size,0,0)", args=function(b) return uint64(0), uint64(pid), uint64(b), uint64(0x4000), uint64(0), uint64(0) end},
    {name="(buf,size,pid,0,0,0)", args=function(b) return uint64(b), uint64(0x4000), uint64(pid), uint64(0), uint64(0), uint64(0) end},
    -- Like sys 674 virtual_query_all: (pid, addr, buf, nrecs, ?, ?)
    {name="(pid,0,buf,64,0,0)", args=function(b) return uint64(pid), uint64(0), uint64(b), uint64(64), uint64(0), uint64(0) end},
}

for _, layout in ipairs(layouts) do
    clear_buf(outbuf, 0x1000)
    local ok, ret = pcall(function()
        return sc728(layout.args(outbuf))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        print(string.format("  %s: ret=%d  buf[0..4]=%08X %08X", layout.name, rv, d0, d4))
        if rv >= 0 and (d0 ~= 0 or d4 ~= 0) then
            print("  Output detected! Full dump:")
            hex_dump(outbuf, 0x100)
            print("  Kernel pointer scan (4KB):")
            scan_kptrs(outbuf, 0x4000)
        end
    else
        print(string.format("  %s: PCALL-FAIL", layout.name))
    end
end

-- Try querying pid 0 (kernel/swapper)
print("")
print("  Cross-process attempts:")
for _, target_pid in ipairs({0, 1, 2}) do
    clear_buf(outbuf, 0x1000)
    local ok, ret = pcall(function()
        return sc728(uint64(target_pid), uint64(0), uint64(outbuf), uint64(64), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        print(string.format("    pid=%d: ret=%d  buf[0]=%08X", target_pid, rv, d0))
        if rv >= 0 and d0 ~= 0 then
            print("    Kernel pointer scan:")
            scan_kptrs(outbuf, 0x1000)
        end
    else
        print(string.format("    pid=%d: PCALL-FAIL", target_pid))
    end
end
print("")

-- =====================================================
print("=== SECTION B: mmap2 (725) DEEP ===")
print("")
-- =====================================================
local sc725 = make_syscall(725)

-- Try different protection combinations
local prot_tests = {
    {name="RW_ANON", prot=3, flags=0x1002},
    {name="RWX_ANON", prot=7, flags=0x1002},
    {name="RX_ANON", prot=5, flags=0x1002},
    {name="RW_SHARED", prot=3, flags=0x1001},
    -- Try with extra flags that might bypass W^X
    {name="RWX_STACK", prot=7, flags=0x1402},  -- MAP_STACK=0x400
    {name="RW_GUARD", prot=3, flags=0x5002},    -- MAP_GUARD=0x4000
}

for _, test in ipairs(prot_tests) do
    local ok, ret = pcall(function()
        return sc725(uint64(0), uint64(0x4000), uint64(test.prot), uint64(test.flags), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local addr_str = string.format("%08X_%08X", h, l)
        print(string.format("  %s: ret=%s", test.name, addr_str))

        if h ~= 0xFFFFFFFF and l ~= 0 then
            -- Verify actual protections via sys 547 query_memory_protection
            local sc547 = make_syscall(547)
            clear_buf(outbuf, 64)
            local qok, qret = pcall(function()
                return sc547(uint64(ret), uint64(0x4000), uint64(outbuf), uint64(0x100), uint64(0), uint64(0))
            end)
            if qok then
                local qrv = to_num(qret)
                local prot_actual = safe_rd(outbuf) or 0
                local prot2 = safe_rd(outbuf+4) or 0
                print(string.format("    query_mem_prot: ret=%d prot=%08X %08X", qrv, prot_actual, prot2))
            end

            -- Test write
            local wok = safe_wd(ret, 0xDEADBEEF)
            local rval = safe_rd(ret)
            print(string.format("    Write test: ok=%s readback=%08X", tostring(wok), rval or 0))

            -- If RWX was requested, check if we got EXEC
            if test.prot == 7 then
                -- Read back to see if it's actually executable
                -- Check via CClosure redirect: write known bytes, redirect to them
                print("    (RWX requested - check query_memory_protection for actual perms)")
            end
        end
    else
        print(string.format("  %s: PCALL-FAIL", test.name))
    end
end
print("")

-- =====================================================
print("=== SECTION C: procctl (689) DEEP ===")
print("")
-- =====================================================
local sc689 = make_syscall(689)

-- Extended command scan
print("  Full command scan (0-30):")
for cmd = 0, 30 do
    clear_buf(outbuf, 64)
    local ok, ret = pcall(function()
        return sc689(uint64(0), uint64(pid), uint64(cmd), uint64(outbuf), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        if rv >= 0 or d0 ~= 0 then
            print(string.format("    cmd=%d: ret=%d  data=%08X %08X", cmd, rv, d0, d4))
        end
    else
        print(string.format("    cmd=%d: PCALL-FAIL", cmd))
    end
end

-- PROC_REAP_STATUS deep (cmd=2): returns child process info, might leak kptrs
print("")
print("  PROC_REAP_STATUS (cmd=2) deep dump:")
clear_buf(outbuf, 256)
local rok, rret = pcall(function()
    return sc689(uint64(0), uint64(pid), uint64(2), uint64(outbuf), uint64(0), uint64(0))
end)
if rok then
    local rv = to_num(rret)
    print(string.format("    ret=%d", rv))
    if rv >= 0 then
        hex_dump(outbuf, 0x80)
        scan_kptrs(outbuf, 0x100)
    end
end

-- PROC_ASLR_STATUS (cmd=14): what's our ASLR config?
print("")
print("  PROC_ASLR_STATUS (cmd=14):")
clear_buf(outbuf, 16)
safe_wd(outbuf, 0)
local aok, aret = pcall(function()
    return sc689(uint64(0), uint64(pid), uint64(14), uint64(outbuf), uint64(0), uint64(0))
end)
if aok then
    local rv = to_num(aret)
    local d0 = safe_rd(outbuf) or 0
    print(string.format("    ret=%d  status=%d (1=active,2=disabled)", rv, d0))
end

-- Try PROC_ASLR_CTL (cmd=13) to disable ASLR
print("")
print("  PROC_ASLR_CTL (cmd=13) disable attempt:")
clear_buf(outbuf, 16)
safe_wd(outbuf, 2)  -- PROC_ASLR_FORCE_DISABLE=2
local adok, adret = pcall(function()
    return sc689(uint64(0), uint64(pid), uint64(13), uint64(outbuf), uint64(0), uint64(0))
end)
if adok then
    print(string.format("    ret=%d", to_num(adret)))
else
    print("    PCALL-FAIL")
end
print("")

-- =====================================================
print("=== SECTION D: pipe2 (687) DEEP ===")
print("")
-- =====================================================
local sc687 = make_syscall(687)
local pipebuf = memory.alloc(16)

-- Standard pipe2
safe_wd(pipebuf, 0)
safe_wd(pipebuf+4, 0)
local pok, pret = pcall(function()
    return sc687(uint64(pipebuf), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if pok then
    local rv = to_num(pret)
    local fd0 = safe_rd(pipebuf) or -1
    local fd1 = safe_rd(pipebuf+4) or -1
    print(string.format("  pipe2(0): ret=%d  fds=[%d, %d]", rv, fd0, fd1))

    if rv == 0 and fd0 > 0 then
        print("  Got pipe fds! Testing write/read...")
        -- Write to fd1, read from fd0
        local wbuf = memory.alloc(64)
        safe_wd(wbuf, 0x41424344)  -- "ABCD"
        safe_wd(wbuf+4, 0x45464748)

        local sc_write = make_syscall(4)
        local sc_read = make_syscall(3)

        local wok2, wret = pcall(function()
            return sc_write(uint64(fd1), uint64(wbuf), uint64(8), uint64(0), uint64(0), uint64(0))
        end)
        if wok2 then
            print(string.format("    write(fd=%d, 8 bytes): ret=%d", fd1, to_num(wret)))
        end

        local rbuf = memory.alloc(64)
        clear_buf(rbuf, 16)
        local rok2, rret2 = pcall(function()
            return sc_read(uint64(fd0), uint64(rbuf), uint64(8), uint64(0), uint64(0), uint64(0))
        end)
        if rok2 then
            local d0 = safe_rd(rbuf) or 0
            print(string.format("    read(fd=%d, 8 bytes): ret=%d  data=%08X", fd0, to_num(rret2), d0))
        end
    end
else
    print("  pipe2(0): PCALL-FAIL")
end
print("")

-- =====================================================
print("=== SECTION E: openintr (716) ===")
print("")
-- =====================================================
local sc716 = make_syscall(716)
for arg = 0, 5 do
    clear_buf(outbuf, 64)
    local ok, ret = pcall(function()
        return sc716(uint64(arg), uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        print(string.format("  arg=%d: ret=%d  buf[0]=%08X", arg, rv, d0))
        if rv >= 0 and d0 ~= 0 then
            hex_dump(outbuf, 0x40)
            scan_kptrs(outbuf, 0x100)
        end
    else
        print(string.format("  arg=%d: PCALL-FAIL", arg))
    end
end
print("")

-- =====================================================
print("=== SECTION F: dl_get_info_2 (717) ===")
print("")
-- =====================================================
local sc717 = make_syscall(717)
-- Try like dl_get_info (536): (handle, outbuf)
for handle = 0, 5 do
    clear_buf(outbuf, 256)
    local ok, ret = pcall(function()
        return sc717(uint64(handle), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        print(string.format("  handle=%d: ret=%d  buf[0..4]=%08X %08X", handle, rv, d0, d4))
        if rv >= 0 and (d0 ~= 0 or d4 ~= 0) then
            hex_dump(outbuf, 0x80)
            scan_kptrs(outbuf, 0x200)
        end
    else
        print(string.format("  handle=%d: PCALL-FAIL", handle))
    end
end
print("")

-- =====================================================
print("=== SECTION G: workspace_ctrl (722) ===")
print("")
-- =====================================================
local sc722 = make_syscall(722)
for cmd = 0, 10 do
    clear_buf(outbuf, 64)
    local ok, ret = pcall(function()
        return sc722(uint64(cmd), uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        print(string.format("  cmd=%d: ret=%d  buf[0]=%08X", cmd, rv, d0))
    else
        print(string.format("  cmd=%d: PCALL-FAIL", cmd))
    end
end
print("")

-- =====================================================
print("=== SECTION H: get_ppr_sdk_compiled_version (713) ===")
print("")
-- =====================================================
local sc713 = make_syscall(713)
clear_buf(outbuf, 64)
local ok713, ret713 = pcall(function()
    return sc713(uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok713 then
    local rv = to_num(ret713)
    local d0 = safe_rd(outbuf) or 0
    local d4 = safe_rd(outbuf+4) or 0
    print(string.format("  ret=%d  val=%08X %08X", rv, d0, d4))
else
    print("  PCALL-FAIL")
end
-- Also try bare call
local ok713b, ret713b = pcall(function()
    return sc713(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok713b then
    print(string.format("  bare: ret=%d", to_num(ret713b)))
end
print("")

-- =====================================================
print("=== SECTION I: dynlib_get_lid_mid_info (724) ===")
print("")
-- =====================================================
local sc724 = make_syscall(724)
-- Try for each loaded module 0-39
print("  Testing handles 0-10:")
for handle = 0, 10 do
    clear_buf(outbuf, 256)
    local ok, ret = pcall(function()
        return sc724(uint64(handle), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        if rv >= 0 and (d0 ~= 0 or d4 ~= 0) then
            print(string.format("    handle=%d: ret=%d  buf=%08X %08X", handle, rv, d0, d4))
            hex_dump(outbuf, 0x40)
            scan_kptrs(outbuf, 0x200)
        else
            print(string.format("    handle=%d: ret=%d", handle, rv))
        end
    else
        print(string.format("    handle=%d: PCALL-FAIL", handle))
    end
end
print("")

-- Final liveness check
local final_ok, final_val = pcall(function() return sc_getpid() end)
if final_ok then
    print("=== PROCESS SURVIVED (pid=" .. to_num(final_val) .. ") ===")
else
    print("=== PROCESS DEAD ===")
end

print("")
print("=== PROBE 57b COMPLETE ===")
