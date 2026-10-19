-- CRASH_CLASS: MODERATE
-- PROBE 57a: Survey native-only syscalls 677-734
--
-- Context: PR#9 revealed the native ELF64 sysent has 735 entries (0-734)
-- while we only surveyed up to 676. Syscalls 677-734 include pipe2, procctl,
-- apr_*, mmap2, virtual_query_by_pid, cffmgr_call, trace_ctrl and more.
-- This probe does a basic accessibility scan of all 58 new syscalls.

print("=== PROBE 57a: NATIVE SYSENT SURVEY 677-734 ===")
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

-- 13.60 native sysent names for reference
local names = {
    [677]="wait6", [678]="cap_rights_limit", [679]="cap_ioctls_limit",
    [680]="cap_ioctls_get", [681]="cap_fcntls_limit", [682]="cap_fcntls_get",
    [683]="bindat", [684]="connectat", [685]="chflagsat", [686]="accept4",
    [687]="pipe2", [688]="aio_mlock", [689]="procctl", [690]="ppoll",
    [691]="futimens", [692]="utimensat", [693]="numa_getaffinity",
    [694]="numa_setaffinity",
    [700]="apr_submit", [701]="apr_resolve", [702]="apr_stat",
    [703]="apr_wait", [704]="apr_ctrl", [705]="get_phys_page_size",
    [706]="begin_app_mount", [707]="end_app_mount", [708]="fsc2h_ctrl",
    [709]="streamwrite", [710]="app_save", [711]="app_restore",
    [712]="saved_app_delete", [713]="get_ppr_sdk_compiled_version",
    [714]="notify_app_event", [715]="ioreq", [716]="openintr",
    [717]="dl_get_info_2", [718]="acinfo_add", [719]="acinfo_delete",
    [720]="acinfo_get_all_for_coredump", [721]="ampr_ctrl_debug",
    [722]="workspace_ctrl", [723]="notify_a53_bind_progress",
    [724]="dynlib_get_lid_mid_info", [725]="mmap2",
    [726]="get_aio_debug_submit_info", [727]="get_aio_debug_request_info",
    [728]="virtual_query_by_pid", [729]="fgcinfo_add", [730]="fgcinfo_delete",
    [731]="fgcinfo_get_all_for_coredump", [732]="cffmgr_call",
    [733]="get_resident_fmem_count2", [734]="trace_ctrl"
}

-- Get our PID for reference
local sc_getpid = make_syscall(20)
local pid_ok, pid_val = pcall(function() return sc_getpid() end)
local pid = pid_ok and to_num(pid_val) or 0
print("PID: " .. pid)
print("")

-- Allocate shared buffers
local outbuf = memory.alloc(0x1000)
local argbuf = memory.alloc(0x100)

print("=== SECTION A: ZERO-ARG SURVEY ===")
print("Testing each syscall with no arguments (all zeros)")
print("")

local accessible = {}
local lethal = {}

for num = 677, 734 do
    local name = names[num] or ("#" .. num)

    -- Clear output area
    for i = 0, 0x3F do safe_wd(outbuf + i*4, 0) end

    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = to_num(ret)
        local tag = ""
        if rv == 0 then tag = " [SUCCESS]" end
        print(string.format("  sys %d %-35s ret=%d%s", num, name, rv, tag))
        if rv >= 0 then
            accessible[#accessible+1] = {num=num, name=name, ret=rv}
        end
    else
        print(string.format("  sys %d %-35s PCALL-FAIL", num, name))
    end
end

print("")
print("Accessible (ret >= 0): " .. #accessible)
print("")

-- Check we're still alive
local alive_ok, alive_val = pcall(function() return sc_getpid() end)
if alive_ok then
    print("Process alive after zero-arg survey: YES (pid=" .. to_num(alive_val) .. ")")
else
    print("Process alive after zero-arg survey: NO")
end
print("")

print("=== SECTION B: OUTPUT-BUFFER SURVEY ===")
print("Testing accessible syscalls with output buffer arg patterns")
print("")

for _, entry in ipairs(accessible) do
    local num = entry.num
    local name = entry.name
    print("--- sys " .. num .. " " .. name .. " (zero-arg ret=" .. entry.ret .. ") ---")

    local sc = make_syscall(num)

    -- Clear buffer
    for i = 0, 0xFF do safe_wd(outbuf + i*4, 0) end

    -- Pattern 1: (outbuf, size)
    local ok1, ret1 = pcall(function()
        return sc(uint64(outbuf), uint64(0x1000), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok1 then
        local rv = to_num(ret1)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        local d8 = safe_rd(outbuf+8) or 0
        print(string.format("  (buf,size): ret=%d  buf[0..8]=%08X %08X %08X", rv, d0, d4, d8))

        -- Check for kernel pointers
        for off = 0, 0x3F0, 8 do
            local q = safe_rq(outbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  *** KERNEL PTR at +0x%03X: %08X_%08X ***", off, h, l))
                end
            end
        end
    else
        print("  (buf,size): PCALL-FAIL")
    end

    -- Pattern 2: (arg1, outbuf, size) with arg1=pid
    for i = 0, 0xFF do safe_wd(outbuf + i*4, 0) end
    local ok2, ret2 = pcall(function()
        return sc(uint64(pid), uint64(outbuf), uint64(0x1000), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv = to_num(ret2)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        local d8 = safe_rd(outbuf+8) or 0
        print(string.format("  (pid,buf,size): ret=%d  buf[0..8]=%08X %08X %08X", rv, d0, d4, d8))

        for off = 0, 0x3F0, 8 do
            local q = safe_rq(outbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  *** KERNEL PTR at +0x%03X: %08X_%08X ***", off, h, l))
                end
            end
        end
    else
        print("  (pid,buf,size): PCALL-FAIL")
    end

    -- Pattern 3: (cmd, outbuf, size) with small cmd values
    for cmd = 0, 3 do
        for i = 0, 0xFF do safe_wd(outbuf + i*4, 0) end
        local ok3, ret3 = pcall(function()
            return sc(uint64(cmd), uint64(outbuf), uint64(0x1000), uint64(0), uint64(0), uint64(0))
        end)
        if ok3 then
            local rv = to_num(ret3)
            local d0 = safe_rd(outbuf) or 0
            if rv >= 0 and d0 ~= 0 then
                local d4 = safe_rd(outbuf+4) or 0
                local d8 = safe_rd(outbuf+8) or 0
                print(string.format("  (cmd=%d,buf,size): ret=%d  buf[0..8]=%08X %08X %08X", cmd, rv, d0, d4, d8))
            end
        end
    end

    print("")
end

print("=== SECTION C: SPECIFIC TESTS ===")
print("")

-- Test pipe2(687) specifically: pipe2(fds, flags)
print("--- pipe2 (687) ---")
local pipebuf = memory.alloc(16)
safe_wd(pipebuf, 0)
safe_wd(pipebuf+4, 0)
local sc_pipe2 = make_syscall(687)
-- flags: 0 = normal, 0x100000 = O_CLOEXEC, 0x4 = O_NONBLOCK
for _, flags in ipairs({0, 4, 0x100000}) do
    safe_wd(pipebuf, 0)
    safe_wd(pipebuf+4, 0)
    local ok, ret = pcall(function()
        return sc_pipe2(uint64(pipebuf), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local fd0 = safe_rd(pipebuf) or -1
        local fd1 = safe_rd(pipebuf+4) or -1
        print(string.format("  pipe2(flags=0x%X): ret=%d  fds=[%d, %d]", flags, rv, fd0, fd1))
    else
        print(string.format("  pipe2(flags=0x%X): PCALL-FAIL", flags))
    end
end
print("")

-- Test procctl(689): procctl(idtype, id, cmd, data)
print("--- procctl (689) ---")
local sc_procctl = make_syscall(689)
-- PROC_REAP_STATUS=2, PROC_TRACE_CTL=7, PROC_TRACE_STATUS=8
-- PROC_ASLR_CTL=13, PROC_ASLR_STATUS=14, PROC_STACKGAP_CTL=17, PROC_STACKGAP_STATUS=18
local procctl_cmds = {
    {name="REAP_STATUS", cmd=2},
    {name="TRACE_CTL", cmd=7},
    {name="TRACE_STATUS", cmd=8},
    {name="ASLR_CTL", cmd=13},
    {name="ASLR_STATUS", cmd=14},
    {name="STACKGAP_CTL", cmd=17},
    {name="STACKGAP_STATUS", cmd=18},
}
for _, c in ipairs(procctl_cmds) do
    for i = 0, 0x3F do safe_wd(outbuf + i*4, 0) end
    -- idtype=0 (P_PID), id=pid
    local ok, ret = pcall(function()
        return sc_procctl(uint64(0), uint64(pid), uint64(c.cmd), uint64(outbuf), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        local d4 = safe_rd(outbuf+4) or 0
        print(string.format("  procctl(%s=%d): ret=%d  data[0..4]=%08X %08X", c.name, c.cmd, rv, d0, d4))
    else
        print(string.format("  procctl(%s=%d): PCALL-FAIL", c.name, c.cmd))
    end
end
print("")

-- Test get_phys_page_size(705)
print("--- get_phys_page_size (705) ---")
local sc705 = make_syscall(705)
local ok705, ret705 = pcall(function() return sc705(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
if ok705 then
    print("  ret=" .. to_num(ret705))
else
    print("  PCALL-FAIL")
end
-- With outbuf
safe_wd(outbuf, 0)
safe_wd(outbuf+4, 0)
local ok705b, ret705b = pcall(function() return sc705(uint64(outbuf), uint64(8), uint64(0), uint64(0), uint64(0), uint64(0)) end)
if ok705b then
    local rv = to_num(ret705b)
    local d0 = safe_rd(outbuf) or 0
    print(string.format("  (buf,8): ret=%d  buf[0]=%08X (%d)", rv, d0, d0))
else
    print("  (buf,8): PCALL-FAIL")
end
print("")

-- Test virtual_query_by_pid(728) — the big one
print("--- virtual_query_by_pid (728) ---")
local sc728 = make_syscall(728)
-- Try querying our own process
local vqbuf = memory.alloc(0x2000)
for i = 0, 0x1FF do safe_wd(vqbuf + i*4, 0) end

-- Pattern: (pid, outbuf, size, ???)
local ok728, ret728 = pcall(function()
    return sc728(uint64(pid), uint64(vqbuf), uint64(0x2000), uint64(0), uint64(0), uint64(0))
end)
if ok728 then
    local rv = to_num(ret728)
    print(string.format("  (pid,buf,size): ret=%d", rv))
    if rv >= 0 then
        -- Dump first 128 bytes
        print("  First 128 bytes:")
        for row = 0, 0x70, 0x10 do
            local vals = {}
            for col = 0, 0xC, 4 do
                vals[#vals+1] = string.format("%08X", safe_rd(vqbuf + row + col) or 0)
            end
            print(string.format("    +%03X: %s", row, table.concat(vals, " ")))
        end
        -- Kernel pointer scan
        print("  Kernel pointer scan:")
        local kptr_count = 0
        for off = 0, 0x1FF0, 8 do
            local q = safe_rq(vqbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("    *** KPTR +0x%04X: %08X_%08X ***", off, h, l))
                    kptr_count = kptr_count + 1
                    if kptr_count >= 20 then
                        print("    (capped at 20)")
                        break
                    end
                end
            end
        end
        if kptr_count == 0 then print("    None found") end
    end
else
    print("  (pid,buf,size): PCALL-FAIL")
end

-- Try with pid=1 (init) to see if cross-process works
for i = 0, 0x1FF do safe_wd(vqbuf + i*4, 0) end
local ok728b, ret728b = pcall(function()
    return sc728(uint64(1), uint64(vqbuf), uint64(0x2000), uint64(0), uint64(0), uint64(0))
end)
if ok728b then
    local rv = to_num(ret728b)
    print(string.format("  (pid=1,buf,size): ret=%d", rv))
    if rv >= 0 then
        local d0 = safe_rd(vqbuf) or 0
        local d4 = safe_rd(vqbuf+4) or 0
        print(string.format("    buf[0..4]=%08X %08X", d0, d4))
        -- Kernel pointer scan
        for off = 0, 0x1FF0, 8 do
            local q = safe_rq(vqbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("    *** KPTR +0x%04X: %08X_%08X ***", off, h, l))
                end
            end
        end
    end
else
    print("  (pid=1,buf,size): PCALL-FAIL")
end
print("")

-- Test mmap2(725)
print("--- mmap2 (725) ---")
local sc725 = make_syscall(725)
-- Try like regular mmap: (addr, len, prot, flags, fd, offset)
-- MAP_ANON|MAP_PRIVATE = 0x1002, PROT_RW = 0x3
local ok725, ret725 = pcall(function()
    return sc725(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok725 then
    local h, l = get_hi_lo(ret725)
    print(string.format("  mmap2(RW,ANON): ret=%08X_%08X", h, l))
    if h ~= 0xFFFFFFFF then
        print("  Got mapping! Testing R/W...")
        local wok = safe_wd(ret725, 0xDEADBEEF)
        local rval = safe_rd(ret725)
        print(string.format("  Write: %s  Read: %08X", tostring(wok), rval or 0))
    end
else
    print("  mmap2(RW,ANON): PCALL-FAIL")
end

-- Try RWX
local ok725x, ret725x = pcall(function()
    return sc725(uint64(0), uint64(0x4000), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok725x then
    local h, l = get_hi_lo(ret725x)
    print(string.format("  mmap2(RWX,ANON): ret=%08X_%08X", h, l))
else
    print("  mmap2(RWX,ANON): PCALL-FAIL")
end
print("")

-- Test cffmgr_call(732)
print("--- cffmgr_call (732) ---")
local sc732 = make_syscall(732)
for cmd = 0, 8 do
    for i = 0, 0x3F do safe_wd(outbuf + i*4, 0) end
    local ok, ret = pcall(function()
        return sc732(uint64(cmd), uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        if rv >= 0 or d0 ~= 0 then
            print(string.format("  cmd=%d: ret=%d  buf[0]=%08X", cmd, rv, d0))
        else
            print(string.format("  cmd=%d: ret=%d", cmd, rv))
        end
    else
        print(string.format("  cmd=%d: PCALL-FAIL", cmd))
    end
end
print("")

-- Test trace_ctrl(734)
print("--- trace_ctrl (734) ---")
local sc734 = make_syscall(734)
for cmd = 0, 5 do
    for i = 0, 0x3F do safe_wd(outbuf + i*4, 0) end
    local ok, ret = pcall(function()
        return sc734(uint64(cmd), uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0))
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

-- Test apr_* (700-704) — async procedure requests
print("--- apr_* (700-704) ---")
local apr_names = {[700]="apr_submit", [701]="apr_resolve", [702]="apr_stat", [703]="apr_wait", [704]="apr_ctrl"}
for num = 700, 704 do
    for i = 0, 0x3F do safe_wd(outbuf + i*4, 0) end
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local d0 = safe_rd(outbuf) or 0
        print(string.format("  sys %d %s: ret=%d  buf[0]=%08X", num, apr_names[num], rv, d0))
    else
        print(string.format("  sys %d %s: PCALL-FAIL", num, apr_names[num]))
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
print("=== PROBE 57a COMPLETE ===")
