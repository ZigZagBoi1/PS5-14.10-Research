-- CRASH_CLASS: LOW
-- PROBE 75c: sys 572 virtual_query deep dump
--
-- 75b found the working layout: 572(addr, size, outbuf, outsz, flags)
-- Returns 72 bytes (18 dwords) for heap addresses. This probe:
-- 1. Dumps full output for heap, GPU, eboot, stack addresses
-- 2. Tests with kernel VA inputs (0xFFFF800000000000+)
-- 3. Tests flags 0-10
-- 4. Scans all output for kernel pointers
-- 5. Compares against sys 674 format

print("=== PROBE 75c: SYS 572 DEEP DUMP ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc572 = mk(572)
local out = memory.alloc(0x200)
local total_kptrs = 0

-- Get reference addresses
local heap_buf = memory.alloc(0x4000)
local gpu_addr = nil
pcall(function()
    gpu_addr = mk(477)(uint64(0), uint64(16*0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local info_buf = memory.alloc(0x200)
for off = 0, 0x1FF, 4 do wd(N(info_buf) + off, 0) end
wq(N(info_buf), uint64(0x160))
pcall(function() mk(593)(uint64(0), info_buf) end)
local eboot_lo = rd(N(info_buf) + 0x108) or 0
local eboot_hi = rd(N(info_buf) + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt(eboot))

local function query_572(addr, label)
    for off = 0, 0x1FC, 4 do wd(N(out) + off, 0xDEAD) end
    local ret = -999
    pcall(function()
        ret = N(sc572(addr, uint64(0x4000), uint64(N(out)), uint64(0x100), uint64(0)))
    end)

    local modified = 0
    for off = 0, 0xFC, 4 do
        if rd(N(out) + off) ~= 0xDEAD then modified = modified + 1 end
    end

    print(string.format("  %s: ret=%d modified=%d", label, ret, modified))

    if modified > 0 then
        local kptrs = 0
        for off = 0, math.min(modified * 4 + 8, 0xF8), 8 do
            local q = rq(uint64(N(out) + off))
            local h, l = get_hi_lo(q)
            if h ~= 0xDEADDEAD then
                local tag = ""
                if is_kptr(q) then tag = " ***KPTR***"; kptrs = kptrs + 1 end
                print(string.format("    +0x%02X: %s%s", off, fmt(q), tag))
            end
        end
        total_kptrs = total_kptrs + kptrs
        return modified, kptrs
    end
    return 0, 0
end

-- ============================================================
-- [A] Full dump for userland addresses
-- ============================================================
print("")
print("[A] Full dump for userland addresses")
query_572(uint64(N(heap_buf)), "heap")
if gpu_addr then query_572(gpu_addr, "gpu") end
query_572(eboot, "eboot")
query_572(uint64(0x200000), "low_va_0x200000")
query_572(uint64(0x800000000), "mid_va_0x800000000")

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Kernel VA inputs
-- ============================================================
print("")
print("[B] Kernel VA inputs")
local kernel_addrs = {
    {uint64("0xFFFF800000000000"), "DMAP_base"},
    {uint64("0xFFFF800100000000"), "DMAP+4GB"},
    {uint64("0xFFFF800200000000"), "DMAP+8GB"},
    {uint64("0xFFFF810000000000"), "kern_candidate_1"},
    {uint64("0xFFFF820000000000"), "kern_candidate_2"},
    {uint64("0xFFFFFFFF80000000"), "high_kern_1"},
    {uint64("0xFFFFFFFF82000000"), "high_kern_2"},
    {uint64("0xFFFFFFFF84000000"), "high_kern_3"},
    {uint64("0xFFFFFFFFC0000000"), "kern_text_common"},
}

for _, kv in ipairs(kernel_addrs) do
    query_572(kv[1], kv[2])
    if not alive() then print("DEAD at " .. kv[2]); return end
end

-- ============================================================
-- [C] Flags sweep with heap address
-- ============================================================
print("")
print("[C] Flags sweep (addr=heap)")
for flags = 0, 8 do
    for off = 0, 0x1FC, 4 do wd(N(out) + off, 0xDEAD) end
    local ret = -999
    pcall(function()
        ret = N(sc572(uint64(N(heap_buf)), uint64(0x4000),
            uint64(N(out)), uint64(0x100), uint64(flags)))
    end)
    local modified = 0
    for off = 0, 0xFC, 4 do
        if rd(N(out) + off) ~= 0xDEAD then modified = modified + 1 end
    end
    if modified ~= 18 or ret ~= 0 then
        print(string.format("  flags=%d ret=%d modified=%d", flags, ret, modified))
    end
end
-- Also try flag 0x33, 0x100, 0xFFFFFFFF
for _, flags in ipairs({0x33, 0x100, 0x1000, 0xFFFFFFFF}) do
    for off = 0, 0x1FC, 4 do wd(N(out) + off, 0xDEAD) end
    local ret = -999
    pcall(function()
        ret = N(sc572(uint64(N(heap_buf)), uint64(0x4000),
            uint64(N(out)), uint64(0x100), uint64(flags)))
    end)
    local modified = 0
    for off = 0, 0xFC, 4 do
        if rd(N(out) + off) ~= 0xDEAD then modified = modified + 1 end
    end
    print(string.format("  flags=0x%X ret=%d modified=%d", flags, ret, modified))
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Output size test — does 572 write more than 72 bytes?
-- ============================================================
print("")
print("[D] Output size test (oversized buffer)")
for off = 0, 0x1FC, 4 do wd(N(out) + off, 0xDEAD) end
local ret = -999
pcall(function()
    ret = N(sc572(uint64(N(heap_buf)), uint64(0x4000),
        uint64(N(out)), uint64(0x200), uint64(0)))
end)
local last_modified = -1
for off = 0, 0x1FC, 4 do
    if rd(N(out) + off) ~= 0xDEAD then last_modified = off end
end
print(string.format("  ret=%d last_modified_offset=0x%X (%d bytes)", ret, last_modified, last_modified + 4))

-- ============================================================
-- [E] Output with outsz=0 — does it return the required size?
-- ============================================================
print("")
print("[E] Output size query (outsz=0)")
local sz_out = memory.alloc(16)
wd(N(sz_out), 0xDEAD)
wd(N(sz_out) + 4, 0xDEAD)
pcall(function()
    ret = N(sc572(uint64(N(heap_buf)), uint64(0x4000),
        uint64(0), uint64(0), uint64(0)))
end)
print(string.format("  572(addr,sz,NULL,0,0): ret=%d", ret))

-- ============================================================
-- [F] SUMMARY
-- ============================================================
print("")
print("[F] SUMMARY")
print("  total kernel pointers: " .. total_kptrs)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 75c COMPLETE ===")
