-- CRASH_CLASS: HIGH
-- PROBE 531c: MapDirectMemory with hint address
--
-- 531a/531b: rv=0 (SUCCESS) but reading out_ptr crashes.
-- Hypothesis: MapDirectMemory with garbage 7th arg (name) might
-- succeed but corrupt the output pointer, or the VA is unmappable.
--
-- Alternative approach:
-- 1. Use MAP_FIXED flag with a known hint address
-- 2. Or: read out_ptr more carefully (pcall each byte)
-- 3. Or: check if the function signature differs from what we think
--
-- Actually, the real issue might be simpler:
-- sceKernelMapDirectMemory prototype:
--   int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
--                                int flags, off_t offset, size_t align)
-- vs sceKernelMapNamedDirectMemory:
--   int sceKernelMapNamedDirectMemory(void **addr, size_t len, int prot,
--                                     int flags, off_t offset, size_t align,
--                                     const char *name)
--
-- If +0x15020 is the NAMED variant, the 6-arg call puts:
--   rdi=addr, rsi=len, rdx=prot, rcx=flags, r8=offset, r9=align
-- But fcall only has 6 regs, so r8/r9 get whatever was in the regs!
-- Wait - fcall_with_rax takes (fn, rax, arg1..arg6):
--   arg1→rdi, arg2→rsi, arg3→rdx, arg4→rcx, arg5→r8, arg6→r9
-- So 6 args ARE delivered. The 7th (name) is on the stack = garbage.
-- rv=0 means the function succeeded despite garbage name pointer?
-- Or... maybe it crashes AFTER returning 0, in cleanup?
--
-- Let's test: print immediately after fcall, before reading out_ptr.

print("=== PROBE 531c: MAPDM HINT ===")
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
print("")
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

if not phys or N(phys) == 0 then
    print("ALLOC FAILED")
    return
end

local ph, pl = get_hi_lo(phys)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end

-- ============================================================
-- [B] Test: does fcall crash reading out_ptr?
-- Use a large heap buffer, write sentinel, call map, check sentinel
-- ============================================================
print("")
print("[B] Map with sentinel check")

local big = memory.alloc(0x100)
-- Write sentinels around the output pointer location
for i = 0, 0xFC, 4 do wd(N(big) + i, 0xAAAAAAAA) end
-- Put a zero qword at offset 0 for out_ptr
wq(N(big), uint64(0))
-- Sentinel at +8, +16
wd(N(big) + 8, 0xBBBBBBBB)
wd(N(big) + 12, 0xCCCCCCCC)
print("  sentinels set")

-- Call MapDirectMemory: addr=big, len=0x4000, prot=3, flags=0, off=phys, align=0x4000
print("  calling map...")
local ok_m, rv_m = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(N(big)), uint64(0x4000), uint64(3),
        uint64(0), uint64(string.format("0x%X%08X", ph, pl)), uint64(0x4000))
end)
print(string.format("  map: ok=%s", tostring(ok_m)))

if ok_m and rv_m then
    print(string.format("  rv=%s", hexq(rv_m)))
end

-- Check if we survived
print("  survived map call")

-- Read the output area carefully
print("  reading output area...")
for off = 0, 24, 4 do
    local ok_r, d = pcall(function() return memory.read_dword(N(big) + off) end)
    if ok_r and d then
        local dn = N(d)
        if dn < 0 then dn = dn + 0x100000000 end
        print(string.format("  big[+%d]=0x%08X", off, dn))
    else
        print(string.format("  big[+%d]=FAULT", off))
    end
end

-- Try reading out_ptr as qword
print("  reading out_ptr qword...")
local ok_q, va = pcall(function() return memory.read_qword(N(big)) end)
print(string.format("  ok=%s", tostring(ok_q)))
if ok_q and va then
    print(string.format("  VA=%s", hexq(va)))
    local van = N(va)
    if van ~= 0 then
        -- Try reading the mapped memory!
        print("  reading mapped page...")
        local ok_rd, d0 = pcall(function() return memory.read_dword(van) end)
        if ok_rd and d0 then
            local d0n = N(d0)
            if d0n < 0 then d0n = d0n + 0x100000000 end
            print(string.format("  VA[0]=0x%08X", d0n))
            -- Write test
            pcall(function() memory.write_dword(van, 0xCAFEBABE) end)
            local ok_rb, rb = pcall(function() return memory.read_dword(van) end)
            if ok_rb and rb then
                local rbn = N(rb)
                if rbn < 0 then rbn = rbn + 0x100000000 end
                print(string.format("  write_test=0x%08X", rbn))
            end
        else
            print("  VA[0]=FAULT")
        end
    end
end

-- ============================================================
-- [C] Alternative: use mmap(477) on /dev/dmem0 with phys offset
-- This is known to work from DEM9N101
-- ============================================================
print("")
print("[C] Fallback: mmap dmem0")
local devpath = memory.alloc(0x20)
local name = "/dev/dmem0"
for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
wd(N(devpath) + #name, 0)
local dm_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("  dmem0_fd=%d", dm_fd))

if dm_fd >= 0 then
    local sc_477 = mk(477)
    local ok_d, rv_d = pcall(function()
        return sc_477(uint64(0), uint64(0x4000), uint64(3), uint64(1),
            uint64(dm_fd), uint64(string.format("0x%X%08X", ph, pl)))
    end)
    if ok_d and rv_d then
        local drh, drl = get_hi_lo(rv_d)
        if drh < 0 then drh = drh + 0x100000000 end
        if drh ~= 0xFFFFFFFF then
            local dva = N(rv_d)
            print(string.format("  dmem0_mmap=0x%X", dva))
            local dd = rd(dva)
            if dd then
                if dd < 0 then dd = dd + 0x100000000 end
                print(string.format("  dmem0[0]=0x%08X", dd))
            end
            wd(dva, 0xDEAD1234)
            local rb2 = rd(dva)
            if rb2 then
                if rb2 < 0 then rb2 = rb2 + 0x100000000 end
                print(string.format("  dmem0_rw=0x%08X match=%s", rb2, rb2 == 0xDEAD1234 and "YES" or "NO"))
            end
        else
            print("  dmem0_mmap=FAIL (MAP_FAILED)")
        end
    else
        print("  dmem0_mmap=FAIL")
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)
end

print("")
print("=== 531c DONE ===")
