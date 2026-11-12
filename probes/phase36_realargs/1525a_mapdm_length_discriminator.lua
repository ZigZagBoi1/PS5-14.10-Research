-- CRASH_CLASS: MODERATE
-- PROBE 1525a: which MapDirectMemory argument breaks the fcall chain -- the length, or the map?
--
-- -- prior art:
--   probes/phase36_realargs/1522b_mapdm_fcall_offsets.lua
--     results/phase36_realargs/1522b_mapdm_fcall_offsets_20261109_234027.txt
--     -> libkernel+0x15020 is sceKernelMapDirectMemory by behaviour (returns Sony status
--        0x80020016 for a zero-length request); +0x17EF0 AllocateDirectMemory succeeds.
--   probes/phase36_realargs/1523a_mapdm_prot_matrix.lua
--     results/phase36_realargs/1523a_mapdm_prot_matrix_20261109_234855.txt
--     -> the payload's own prot/flags pair crashes exactly like prot 3/flags 0; fault RIP is
--        eboot+0x1BA4C0 = 45 0F B6 44 17 FF = movzx r8d,[r15+rdx-1], a Lua string-hash loop.
--   probes/phase36_realargs/1523b_mapdm_fault_attribution.lua
--     results/phase36_realargs/1523b_mapdm_fault_attribution_20261109_235053.txt
--     -> map_fn(out, 0x4000, prot 0, flags 0, phys 0, align 0x4000) also crashes, so the
--        physical address and the protections are not the trigger.
--   probes/phase36_realargs/1523c_mapdm_fixed_addr.lua
--     results/phase36_realargs/1523c_mapdm_fixed_addr_20261109_235204.txt
--     -> a pre-filled *out page we already own does not help either.
--   So: len = 0 returns a clean Sony status, and EVERY len > 0 crashes -- but nothing has yet
--   separated "the chain cannot carry a nonzero length" from "the map runs and damages the
--   process". Arm [B] is the discriminator: a length that the handler must refuse early
--   (0xFFFFFFFFFFFFF000) exercises the chain identically while performing no mapping at all.
--
-- Method: one call per arm, print before each. A arm that kills the process truncates the
-- capture exactly at its own print, which is the datum.

print("=== PROBE 1525a: MAPDM -- LENGTH OR MAP? ===")
print("")

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
local function guarded(n)
    if n < 0 then return 0 end
    return uint64(n)
end

local PID0 = self_pid()
print("pid=" .. tostring(PID0))

-- ============================================================
-- [A] resolve libkernel and prove the identity call still works
-- ============================================================
print("")
print("[A] resolve libkernel via 593")
local KTEXT = nil
local info = memory.alloc(0x200)
local ia = addr_of(info)
if not ia then print("  FAIL: no info buffer"); return end
pcall(function() memory.write_dword(ia, 0x160) end)
local function module_text(handle)
    for off = 0, 0x160, 4 do pcall(function() memory.write_dword(ia + off, 0) end) end
    pcall(function() memory.write_dword(ia, 0x160) end)
    local ok, rv = pcall(function() return mk(593)(uint64(handle), uint64(ia)) end)
    if not ok then return nil, "raised" end
    local n = N(rv)
    if n ~= 0 then return nil, string.format("rv=0x%X", sid(rv)) end
    local lo = rd(ia + 0x108) or 0
    local hi = rd(ia + 0x10C) or 0
    if lo == 0 and hi == 0 then return nil, "zero rv=0" end
    return hi * 4294967296 + lo, "ok"
end
KTEXT = select(1, module_text(0x2001))
if not KTEXT then print("  FAIL: libkernel (handle 0x2001) did not resolve"); return end
print("  KTEXT=" .. string.format("0x%X", KTEXT))
local MK_ALLOC = KTEXT + 0x17EF0
local MK_MAP = KTEXT + 0x15020
print("  alloc_fn=" .. string.format("0x%X", MK_ALLOC) .. "  map_fn=" .. string.format("0x%X", MK_MAP))

local out = memory.alloc(0x10)
local outa = addr_of(out)
local phys = memory.alloc(0x10)
local pha = addr_of(phys)
if not outa or not pha then print("  FAIL: buffers"); return end
pcall(function() memory.write_qword(outa, 0) end)
pcall(function() memory.write_qword(pha, 0) end)

print("  [A1] AllocateDirectMemory(0, 0x150000000, 0x4000, 0x4000, 0, &phys)")
local okA, rvA = pcall(function()
    return native.fcall(MK_ALLOC, uint64(0), uint64(0x150000000), uint64(0x4000), uint64(0x4000), uint64(0), uint64(pha))
end)
print("       rv=" .. tostring(okA and N(rvA) or "EXC"))
local PHYS = N(memory.read_qword(pha))
print("       phys=" .. string.format("0x%X", PHYS))
if PHYS == 0 then print("  FAIL: no direct memory block"); return end

print("  [A2] identity: map_fn(out, 0, 3, 0, 0, 0) must return 0x80020016 if the chain is healthy")
local okI, rvI = pcall(function()
    return native.fcall(MK_MAP, uint64(outa), uint64(0), uint64(3), uint64(0), uint64(0), uint64(0))
end)
if not okI then print("       EXC"); return end
print("       rv=" .. string.format("0x%X", sid(rvI)))
if sid(rvI) ~= 0x80020016 then
    print("  FAIL: identity call no longer returns 0x80020016 -- chain already unhealthy")
end

-- ============================================================
-- [B] all arguments real EXCEPT the length -- does the chain survive?
-- ============================================================
print("")
print("[B] len = 0, everything else real (prot 0x33, flags 0x400000, own phys, align 0x4000)")
print("    calling")
local okB, rvB = pcall(function()
    return native.fcall(MK_MAP, uint64(outa), uint64(0), uint64(0x33), uint64(0x400000), uint64(PHYS), uint64(0x4000))
end)
if not okB then
    print("    EXC")
else
    print("    rv=" .. string.format("0x%X", sid(rvB)) .. "  out=" .. string.format("0x%X", N(memory.read_qword(outa))))
end

-- ============================================================
-- [C] a nonzero length the handler must refuse, so no mapping can happen
-- ============================================================
print("")
print("[C] len = 0xFFFFFFFFFFFFF000 (must be refused), prot 0, flags 0, phys 0, align 0")
print("    calling")
local okC, rvC = pcall(function()
    return native.fcall(MK_MAP, uint64(outa), uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFF000)), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not okC then
    print("    EXC")
else
    print("    rv=" .. string.format("0x%X", sid(rvC)))
end

print("")
print("pid_after_C=" .. tostring(self_pid()))
print("VERDICT: if [B] and [C] both survive, the chain carries a nonzero length and only a real")
print("         mapping kills -- the map itself damages the process. If [C] dies, every nonzero")
print("         length breaks the chain before the handler ever runs.")
print("")

-- ============================================================
-- [D] the known-killer control, last
-- ============================================================
print("[D] len = 0x4000, prot 0, flags 0, phys 0, align 0x4000  (known to kill)")
print("    calling")
local okD, rvD = pcall(function()
    return native.fcall(MK_MAP, uint64(outa), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0x4000))
end)
print("    rv=" .. tostring(okD and string.format("0x%X", sid(rvD)) or "EXC"))

print("")
print("pid_final=" .. tostring(self_pid()))
print("")
print("=== PROBE 1525a COMPLETE ===")
