-- CRASH_CLASS: LOW
-- PROBE 56i2: KASLR hunt — auxv, stack, timekeep, targeted heap scan
--
-- Context: 56i crashed during module data section scan (binary garbage).
-- This probe reorders: high-value targets first, safer scans.

print("=== PROBE 56i2: KASLR — AUXV / STACK / TIMEKEEP ===")
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
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] sysctl kern.proc.auxv — kernel writes this during execve
-- ============================================================
print("")
print("[B] kern.proc.auxv")

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
local auxv_ret = ok and to_num(ret) or -999
print("  ret=" .. auxv_ret)

local timekeep_addr = nil

if auxv_ret == 0 then
    local auxlen = safe_rd(oldlenp) or 0
    print("  len=" .. auxlen .. " bytes")

    local i = 0
    while i < auxlen and i < 0x800 do
        local atype_val = safe_rq(auxbuf + i)
        local aval = safe_rq(auxbuf + i + 8)
        if atype_val == nil then break end
        local at = to_num(atype_val)
        if at == 0 then break end

        local tag = ""
        if at == 3 then tag = "AT_PHDR"
        elseif at == 6 then tag = "AT_PAGESZ"
        elseif at == 7 then tag = "AT_BASE"
        elseif at == 9 then tag = "AT_ENTRY"
        elseif at == 15 then tag = "AT_EXECPATH"
        elseif at == 16 then tag = "AT_CANARY"
        elseif at == 18 then tag = "AT_OSRELDATE"
        elseif at == 19 then tag = "AT_NCPUS"
        elseif at == 22 then tag = "AT_TIMEKEEP"
        elseif at == 23 then tag = "AT_STACKPROT"
        elseif at == 25 then tag = "AT_HWCAP"
        end

        local marker = ""
        if is_kptr(aval) then marker = " *** KERNEL PTR! ***" end

        if tag ~= "" or marker ~= "" then
            print(string.format("  [%d] %s = %s%s", at, tag, hexval(aval), marker))
        else
            print(string.format("  [%d] = %s%s", at, hexval(aval), marker))
        end

        if at == 22 then timekeep_addr = aval end
        i = i + 16
    end
else
    print("  auxv not available")
end

-- ============================================================
-- [C] AT_TIMEKEEP shared page scan
-- Kernel maps a shared page with vdso_timehands. Updated by kernel.
-- May contain kernel pointers in the timehands struct.
-- ============================================================
print("")
print("[C] AT_TIMEKEEP shared page")

if timekeep_addr then
    local th, tl = get_hi_lo(timekeep_addr)
    print("  addr: " .. hexval(timekeep_addr))

    -- Dump first 256 bytes as hex
    print("  First 0x100 bytes:")
    local tk_kptrs = 0
    for off = 0, 0xFF, 8 do
        local scan_l = tl + off
        local scan_h = th
        if scan_l >= 0x100000000 then
            scan_h = scan_h + 1
            scan_l = scan_l - 0x100000000
        end
        local addr = uint64(string.format("0x%X%08X", scan_h, scan_l))
        local val = safe_rq(addr)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                local marker = ""
                if is_kptr(val) then
                    marker = " KPTR!"
                    tk_kptrs = tk_kptrs + 1
                end
                print(string.format("    +0x%02X: %s%s", off, hexval(val), marker))
            end
        end
    end

    -- Scan full 16KB page
    for off = 0x100, 0x3FF8, 8 do
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
            if tk_kptrs <= 10 then
                print(string.format("    +0x%04X: %s KPTR!", off, hexval(val)))
            end
        end
    end
    print("  Total kernel pointers in timekeep page: " .. tk_kptrs)
else
    print("  No timekeep address (auxv failed)")
end

-- ============================================================
-- [D] Stack scan — find stack via VM map, scan top for kernel ptrs
-- ============================================================
print("")
print("[D] Stack scan via sys 674 VM map")

local sc_vmmap = make_syscall(674)
local vm_buf = memory.alloc(0x8000)
local vm_len_buf = memory.alloc(8)
safe_wd(vm_len_buf, 0x8000)
safe_wd(vm_len_buf + 4, 0)

local ok2, ret2 = pcall(function()
    return sc_vmmap(uint64(vm_buf), uint64(vm_len_buf))
end)
local vr = ok2 and to_num(ret2) or -999

if vr == 0 then
    local vm_len = safe_rd(vm_len_buf) or 0
    local entries = math.floor(vm_len / 72)
    print("  " .. entries .. " VM regions")

    local stack_start, stack_end = nil, nil
    for e = 0, entries - 1 do
        local base = vm_buf + e * 72
        local start_val = safe_rq(base)
        local end_val = safe_rq(base + 8)
        -- Read name bytes individually
        local name = ""
        for ci = 0, 15 do
            local b = safe_rd(base + 0x20 + ci)
            if b and b > 31 and b < 127 then
                name = name .. string.char(b)
            elseif b == 0 then
                break
            end
        end
        if name:find("stack") then
            stack_start = start_val
            stack_end = end_val
            print("  Stack: " .. hexval(start_val) .. " - " .. hexval(end_val))
        end
    end

    if stack_end then
        local eh, el = get_hi_lo(stack_end)
        -- Scan top 8KB of stack (most recent frames)
        local scan_bytes = 0x2000
        local stack_kptrs = 0
        print("  Scanning top " .. scan_bytes .. " bytes...")

        for off = scan_bytes, 8, -8 do
            local sl = el - off
            local sh = eh
            if sl < 0 then
                sh = sh - 1
                sl = sl + 0x100000000
            end
            local addr = uint64(string.format("0x%X%08X", sh, sl))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                stack_kptrs = stack_kptrs + 1
                if stack_kptrs <= 10 then
                    print(string.format("    end-0x%04X: %s KPTR!", off, hexval(val)))
                end
            end
        end
        print("  Stack kernel pointers: " .. stack_kptrs)
    end
else
    print("  VM map ret=" .. vr)
end

-- ============================================================
-- [E] Heap near loader internals — smaller, safer scan
-- Scan 0x1000 bytes around fn_addr and ropchain
-- ============================================================
print("")
print("[E] Heap near loader internals")

local pipe_str = tostring(syscall.pipe)
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if rop_addr_str then
    local rop_addr = uint64(rop_addr_str)
    local rh, rl = get_hi_lo(rop_addr)
    print("  ropchain: " .. hexval(rop_addr))

    local heap_kptrs = 0
    for off = -0x2000, 0x4000, 8 do
        local sl = rl + off
        local sh = rh
        if sl < 0 then
            sh = sh - 1
            sl = sl + 0x100000000
        end
        if sh >= 0 then
            local addr = uint64(string.format("0x%X%08X", sh, sl))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                heap_kptrs = heap_kptrs + 1
                if heap_kptrs <= 10 then
                    print(string.format("    rop%+05X: %s KPTR!", off, hexval(val)))
                end
            end
        end
    end
    print("  Heap kernel pointers: " .. heap_kptrs)
end

-- ============================================================
-- [F] UMTX mutex trylock — check output buffers for kernel addrs
-- ============================================================
print("")
print("[F] UMTX probe")

local sc_umtx = make_syscall(454)
local umtx_obj = memory.alloc(0x100)
local umtx_out = memory.alloc(0x100)

-- Zero
for i = 0, 0xFF, 4 do
    safe_wd(umtx_obj + i, 0)
    safe_wd(umtx_out + i, 0)
end

-- UMTX_OP_MUTEX_TRYLOCK(5)
safe_wd(umtx_obj, 0)
local ok3, ret3 = pcall(function()
    return sc_umtx(uint64(umtx_obj), uint64(5), uint64(0), uint64(0), uint64(0))
end)
print("  MUTEX_TRYLOCK ret=" .. (ok3 and to_num(ret3) or -999))

-- Check if kernel wrote owner TID or wait channel to the mutex obj
local umtx_kptrs = 0
for off = 0, 0x3F, 8 do
    local val = safe_rq(umtx_obj + off)
    if val and is_kptr(val) then
        umtx_kptrs = umtx_kptrs + 1
        print(string.format("    obj+0x%02X: %s KPTR!", off, hexval(val)))
    end
end
-- Dump first 32 bytes of mutex obj to see what kernel wrote
print("  Mutex obj after trylock:")
for off = 0, 0x1F, 8 do
    local val = safe_rq(umtx_obj + off)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then
            print(string.format("    +0x%02X: %s", off, hexval(val)))
        end
    end
end

-- UMTX_OP_NWAKE_PRIVATE(21) — batch wake, different code path
for i = 0, 0x3F, 4 do safe_wd(umtx_out + i, 0) end
local ok4, ret4 = pcall(function()
    return sc_umtx(uint64(umtx_obj), uint64(21), uint64(1), uint64(0), uint64(0))
end)
print("  NWAKE_PRIVATE ret=" .. (ok4 and to_num(ret4) or -999))

collectgarbage("restart")

print("")
print("=== PROBE 56i2 COMPLETE ===")
