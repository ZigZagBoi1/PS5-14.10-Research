-- CRASH_CLASS: LOW
-- PROBE 400e: KASLR existence test — collect kernel-derived values
--
-- If PS5 has no KASLR, kernel-derived addresses are IDENTICAL across
-- connections. Collect all values that come from kernel layout:
-- 1. sysctl sub=36 (sigtramp addr? — 4 bytes)
-- 2. sysctl sub=43 (8 bytes)
-- 3. sys 624 initial VM counter value
-- 4. Eboot base (userland ASLR — expect different each time)
-- 5. libkernel base (compare to eboot — same slide or different?)
-- 6. sys 587 credential offsets
-- 7. Module info addresses from sys 593
--
-- Run this TWICE to compare values across connections.
-- If kernel-derived values match but eboot differs → no KASLR confirmed.

print("=== PROBE 400e: KASLR stability test ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local sc202 = mk(202)
local sc593 = mk(593)
local sc624 = mk(624)

-- ============================================
-- 1. Eboot base (userland ASLR reference)
-- ============================================
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("EBOOT_BASE=%X_%08X", eb_hi, eb_lo))

-- ============================================
-- 2. Module bases (first 10 handles)
-- ============================================
print("")
print("-- module bases --")
for h = 0, 9 do
    for i = 0, 0x1FC, 4 do wd(N(info) + i, 0) end
    wd(N(info), 0x160)
    local ok_m, rv_m = pcall(function() return sc593(uint64(h), info) end)
    local ret_m = ok_m and N(rv_m) or -1
    if ret_m > 0x7FFFFFFF then ret_m = -1 end
    if ret_m == 0 then
        local m_lo = rd(N(info) + 0x108) or 0
        local m_hi = rd(N(info) + 0x10C) or 0
        local msz_lo = rd(N(info) + 0x110) or 0
        -- Module name at offset 0 + 8
        local name = ""
        for c = 8, 40 do
            local dw = rd(N(info) + c) or 0
            for b = 0, 3 do
                local byte = math.floor(dw / (256 ^ b)) % 256
                if byte >= 32 and byte < 127 then name = name .. string.char(byte)
                elseif byte == 0 then break end
            end
            if #name > 30 then break end
        end
        if m_lo ~= 0 or m_hi ~= 0 then
            print(string.format("  h=%d base=%X_%08X sz=0x%X %s",
                h, m_hi, m_lo, msz_lo, name))
        end
    end
end

-- ============================================
-- 3. sys 624 initial VM counter
-- ============================================
print("")
local ok_624, rv_624 = pcall(function() return sc624(uint64(0), uint64(0)) end)
local vm_cnt = ok_624 and N(rv_624) or -1
print(string.format("SYS624_VMCOUNT=%d", vm_cnt))

-- ============================================
-- 4. sysctl sub=36 (sigtramp?)
-- ============================================
print("")
local mib = memory.alloc(16)
wd(N(mib), 1)       -- CTL_KERN
wd(N(mib) + 4, 14)  -- KERN_PROC
wd(N(mib) + 8, 36)
wd(N(mib) + 12, pid_val)

local sbuf = memory.alloc(16)
for i = 0, 12, 4 do wd(N(sbuf) + i, 0) end
local solen = memory.alloc(8)
wq(solen, uint64(16))

local ok_36, rv_36 = pcall(function()
    return sc202(uint64(N(mib)), uint64(4), uint64(N(sbuf)),
        uint64(N(solen)), uint64(0), uint64(0))
end)
local got_36 = rd(N(solen)) or 0
local v36_0 = rd(N(sbuf)) or 0
local v36_1 = rd(N(sbuf) + 4) or 0
print(string.format("SUB36=%08X_%08X (got=%d)", v36_1, v36_0, got_36))

-- ============================================
-- 5. sysctl sub=43
-- ============================================
wd(N(mib) + 8, 43)
for i = 0, 12, 4 do wd(N(sbuf) + i, 0) end
wq(solen, uint64(16))

local ok_43, rv_43 = pcall(function()
    return sc202(uint64(N(mib)), uint64(3), uint64(N(sbuf)),
        uint64(N(solen)), uint64(0), uint64(0))
end)
local got_43 = rd(N(solen)) or 0
local v43_0 = rd(N(sbuf)) or 0
local v43_1 = rd(N(sbuf) + 4) or 0
print(string.format("SUB43=%08X_%08X (got=%d)", v43_1, v43_0, got_43))

-- ============================================
-- 6. kinfo_proc specific fields
-- Compare offsets +0x00 (structsize), +0x48 (pid), +0x0C (layout)
-- and any field that might encode kernel layout info
-- ============================================
print("")
print("-- kinfo_proc fingerprint --")

wd(N(mib) + 8, 1)    -- KERN_PROC_PID
wd(N(mib) + 12, pid_val)
local kbuf = memory.alloc(0x500)
for i = 0, 0x4FC, 4 do wd(N(kbuf) + i, 0) end
wq(solen, uint64(0x500))

local ok_ki, rv_ki = pcall(function()
    return sc202(uint64(N(mib)), uint64(4), uint64(N(kbuf)),
        uint64(N(solen)), uint64(0), uint64(0))
end)
local ki_ret = ok_ki and N(rv_ki) or -1
if ki_ret > 0x7FFFFFFF then ki_ret = -1 end

if ki_ret == 0 then
    -- Print fields that might be kernel-derived
    -- On FreeBSD 11, kinfo_proc has ki_paddr (process kernel VA)
    -- which Sony might have zeroed or might have left
    local offsets = {
        {0x00, "structsize"},
        {0x04, "layout"},
        {0x08, "paddr_lo"},
        {0x0C, "paddr_hi"},
        {0x10, "addr_lo"},
        {0x14, "addr_hi"},
        {0x18, "vmspace_lo"},
        {0x1C, "vmspace_hi"},
        {0x48, "pid"},
        {0x4C, "ppid"},
        {0x60, "cr_uid"},
        {0x64, "cr_ngroups"},
        {0xB0, "flag"},
        {0xB4, "flag2"},
        {0xB8, "runtime_lo"},
        {0xBC, "runtime_hi"},
    }
    for _, o in ipairs(offsets) do
        local v = rd(N(kbuf) + o[1]) or 0
        if v ~= 0 then
            print(string.format("  +%03X %-14s = %08X", o[1], o[2], v))
        end
    end
end

-- ============================================
-- 7. vmmap first record fingerprint
-- ============================================
print("")
print("-- vmmap first record --")

wd(N(mib) + 8, 32)   -- vmmap
wd(N(mib) + 12, pid_val)
local vbuf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(vbuf) + i, 0) end
wq(solen, uint64(0x100))

local ok_vm, rv_vm = pcall(function()
    return sc202(uint64(N(mib)), uint64(4), uint64(N(vbuf)),
        uint64(N(solen)), uint64(0), uint64(0))
end)
local vm_ret = ok_vm and N(rv_vm) or -1
if vm_ret > 0x7FFFFFFF then vm_ret = -1 end

if vm_ret == 0 then
    -- Print first record (144 bytes)
    print("  (first 144B of first vmmap entry)")
    for off = 0, 0x8C, 4 do
        local v = rd(N(vbuf) + off) or 0
        if v ~= 0 then
            print(string.format("  +%03X: %08X", off, v))
        end
    end
end

-- ============================================
-- 8. Stack pointer area (from pipe tostring)
-- ============================================
print("")
local pipe_str = tostring(syscall.pipe)
local fn_match = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
local rop_match = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("FN_ADDR=" .. (fn_match or "nil"))
print("ROP_CHAIN=" .. (rop_match or "nil"))

-- ============================================
-- 9. libkernel base specifically
-- ============================================
print("")
print("-- libkernel base --")
-- libkernel is typically handle 1
for i = 0, 0x1FC, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
pcall(function() sc593(uint64(1), info) end)
local lk_lo = rd(N(info) + 0x108) or 0
local lk_hi = rd(N(info) + 0x10C) or 0
print(string.format("LIBKERNEL_BASE=%X_%08X", lk_hi, lk_lo))

-- Also get the data segment base (+0x128)
local lkd_lo = rd(N(info) + 0x128) or 0
local lkd_hi = rd(N(info) + 0x12C) or 0
print(string.format("LIBKERNEL_DATA=%X_%08X", lkd_hi, lkd_lo))

print("")
print("=== 400e COMPLETE ===")
print("")
print("TO CHECK KASLR: run this probe TWICE and compare:")
print("  - EBOOT_BASE should DIFFER (userland ASLR confirmed)")
print("  - SUB36 and SUB43: if SAME → kernel-derived, no KASLR")
print("  - SYS624_VMCOUNT: if SAME → fixed kernel init sequence")
print("  - Module bases should DIFFER (userland ASLR)")
