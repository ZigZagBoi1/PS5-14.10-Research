-- CRASH_CLASS: MODERATE
-- PROBE 531e: Raw syscall map + mmap dmem0 for allocated phys
--
-- 531d confirmed: fcall to libkernel+0x15020 (MapNamedDirectMemory)
-- crashes because the 7th arg (name) is stack garbage.
-- fcall_with_rax only delivers 6 regs, so the 7th is uncontrolled.
--
-- This probe SKIPS MapDirectMemory entirely and tries:
-- 1. mmap(477) on /dev/dmem0 at the allocated physical offset
-- 2. Raw syscall 548 (sceKernelMapDirectMemory)
-- 3. Raw syscall 547 (maybe the non-named variant?)
-- 4. Check what syscall numbers the library wrappers actually use

print("=== PROBE 531e: RAW MAP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("lk=0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk_base + uint64(0x17EF0)

-- ============================================================
-- [A] AllocateDirectMemory
-- ============================================================
print("[A] Alloc")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print(string.format("  phys=%s", hexq(phys)))
if not phys or N(phys) == 0 then print("FAIL") return end

local ph, pl = get_hi_lo(phys)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end
local phys_str = string.format("0x%X%08X", ph, pl)

-- ============================================================
-- [B] mmap(477) on /dev/dmem0 at phys offset
-- ============================================================
print("")
print("[B] mmap /dev/dmem0")
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local dm_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("  fd=%d", dm_fd))

if dm_fd >= 0 then
    local sc_477 = mk(477)
    -- Try MAP_SHARED(1) at allocated phys offset
    local ok_mm, rv_mm = pcall(function()
        return sc_477(uint64(0), uint64(0x4000), uint64(3), uint64(1),
            uint64(dm_fd), uint64(phys_str))
    end)
    print(string.format("  mmap ok=%s", tostring(ok_mm)))
    if ok_mm and rv_mm then
        local mmh, mml = get_hi_lo(rv_mm)
        if mmh < 0 then mmh = mmh + 0x100000000 end
        if mmh == 0xFFFFFFFF then
            print("  result=MAP_FAILED")
            -- Try with flags=MAP_SHARED|MAP_PREFAULT_READ(0x40001)
            ok_mm, rv_mm = pcall(function()
                return sc_477(uint64(0), uint64(0x4000), uint64(3), uint64(0x40001),
                    uint64(dm_fd), uint64(phys_str))
            end)
            print(string.format("  retry prefault: ok=%s", tostring(ok_mm)))
            if ok_mm and rv_mm then
                mmh = get_hi_lo(rv_mm)
                if mmh < 0 then mmh = mmh + 0x100000000 end
                if mmh ~= 0xFFFFFFFF then
                    print(string.format("  prefault VA=%s", hexq(rv_mm)))
                else
                    print("  prefault=FAIL")
                end
            end
        else
            local mva = N(rv_mm)
            print(string.format("  VA=0x%X", mva))
            for off = 0, 0x1C, 4 do
                local d = rd(mva + off)
                if d then
                    if d < 0 then d = d + 0x100000000 end
                    print(string.format("  [+0x%02X] 0x%08X", off, d))
                else
                    print(string.format("  [+0x%02X] FAULT", off))
                    break
                end
            end
            wd(mva, 0xCAFEBABE)
            local rb = rd(mva)
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print(string.format("  rw=0x%08X ok=%s", rb, rb == 0xCAFEBABE and "YES" or "NO"))
            end
        end
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)
end

-- ============================================================
-- [C] Raw syscalls 547-550 for mapping
-- 13.60 CSV: 547=budget_set, 548=budget_get, 549=?
-- Actually from ps5 SDK:
--   547 = sceKernelMapNamedDirectMemory
--   548 = sceKernelMapDirectMemory
-- Both are 6-arg raw syscalls (no name in raw version)
-- ============================================================
print("")
print("[C] Raw syscalls 547-550")

for sc_num = 547, 550 do
    local sc = mk(sc_num)
    local va_buf = memory.alloc(8)
    wq(N(va_buf), uint64(0))
    local ok_sc, rv_sc = pcall(function()
        return sc(uint64(N(va_buf)), uint64(0x4000), uint64(3),
            uint64(0), uint64(phys_str), uint64(0x4000))
    end)
    local rv_val = "FAIL"
    if ok_sc and rv_sc then rv_val = hexq(rv_sc) end
    local va_val = rq(N(va_buf))
    print(string.format("  %d: rv=%s out=%s", sc_num, rv_val, hexq(va_val)))

    if va_val and N(va_val) ~= 0 and N(va_val) ~= 0xDEAD then
        local d = rd(N(va_val))
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  %d: VA[0]=0x%08X", sc_num, d))
        end
    end
end

-- ============================================================
-- [D] Try syscalls around 628 (mmap_dmem)
-- 628 refused everything before but maybe with allocated phys?
-- ============================================================
print("")
print("[D] Syscall 628 mmap_dmem")
local sc_628 = mk(628)
local va628 = memory.alloc(8)
wq(N(va628), uint64(0))

-- Try: (va_out, len, prot, flags, phys_off, align)
local ok_628, rv_628 = pcall(function()
    return sc_628(uint64(N(va628)), uint64(0x4000), uint64(3),
        uint64(0), uint64(phys_str), uint64(0x4000))
end)
print(string.format("  628: rv=%s out=%s", ok_628 and hexq(rv_628) or "FAIL", hexq(rq(N(va628)))))

-- Try with descriptor=-1
wq(N(va628), uint64(0))
local ok_628b, rv_628b = pcall(function()
    return sc_628(uint64(N(va628)), uint64(0x4000), uint64(3),
        uint64(0xFFFFFFFF), uint64(phys_str), uint64(0x4000))
end)
print(string.format("  628(-1): rv=%s out=%s", ok_628b and hexq(rv_628b) or "FAIL", hexq(rq(N(va628)))))

-- Try with dmem0 fd as 4th arg
if dm_fd and dm_fd >= 0 then
    wq(N(va628), uint64(0))
    local ok_628c, rv_628c = pcall(function()
        return sc_628(uint64(N(va628)), uint64(0x4000), uint64(3),
            uint64(dm_fd), uint64(phys_str), uint64(0x4000))
    end)
    print(string.format("  628(dm%d): rv=%s out=%s", dm_fd, ok_628c and hexq(rv_628c) or "FAIL", hexq(rq(N(va628)))))
end

-- ============================================================
-- [E] Scan libkernel GOT for MapDirectMemory wrapper
-- The 529a survey found wrappers. Look for a 6-arg one.
-- Use dynlib_get_info to find data section, scan for text ptrs
-- ============================================================
print("")
print("[E] libkernel GOT scan near 0x15000")
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local data_lo = rd(N(ib) + 0x128) or 0
local data_hi = rd(N(ib) + 0x12C) or 0
local data_sz = rd(N(ib) + 0x130) or 0
if data_lo < 0 then data_lo = data_lo + 0x100000000 end
if data_hi < 0 then data_hi = data_hi + 0x100000000 end
if data_sz < 0 then data_sz = data_sz + 0x100000000 end
print(string.format("  data=0x%X%08X+0x%X", data_hi, data_lo, data_sz))

local datan = data_hi * 0x100000000 + data_lo
local scan_end = math.min(data_sz, 0x2000)
local near_map = {}
for off = 0, scan_end - 8, 8 do
    local v = rq(datan + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == lk_hi then
            local text_off = vl - lk_lo
            if text_off >= 0x14000 and text_off <= 0x18000 then
                table.insert(near_map, {off = off, text_off = text_off})
                print(string.format("  GOT+0x%04X -> lk+0x%05X", off, text_off))
            end
        end
    end
end
print(string.format("  near-map entries: %d", #near_map))

print("")
print("=== 531e DONE ===")
