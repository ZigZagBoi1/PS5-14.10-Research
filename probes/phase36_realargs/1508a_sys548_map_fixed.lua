-- CRASH_CLASS: MODERATE -- [A]-[C] touch only memory the process owns. [E] replaces a device
--   window entry and can panic the console, so it runs last and only if [C] proved replacement.
-- PROBE 1508a: does 548 op 3 honour MAP_FIXED, replacing a live vm_map entry?
--
-- mmap(477) refuses MAP_FIXED over the middle of a live mapping (1469a: -1, entry intact), which
-- is a kern_mmap wrapper check. 548 op 3 does not go through that wrapper: case 0xabc11e checks
-- only that start and length are 16 KiB aligned and that the protection lacks bit 3, then calls
-- the internal mapper 0x8b47d540 with fd=-1, offset=0 and `uap[1] | 0x1000` as the map flags.
-- So the caller's flag word IS the mmap flag word, with MAP_ANON added.
--
-- The batch flag mask is 0xe0bffb6f: 1479a measured arg2 = 0x1, 0x1000, 0x20000000 and
-- 0xFFFFFFFF refused (EINVAL) while 0x0 and 0x10000000 are accepted. 0x10 (MAP_FIXED) has no bit
-- in that mask - it was never tested. If it passes, FreeBSD's MAP_FIXED-without-MAP_EXCL path is
-- vm_map_delete(range) followed by vm_map_insert(), i.e. 548 can destroy an existing entry and
-- install a fresh anonymous one on top of it.
--
-- [A] baseline: mmap 0x4000 anon, marker 0x11223344 at +0x100, 547 reports prot 3
-- [B] 548(0, 0x0,  {V,0,0x4000,3,op=3}, 1, &proc, 0)   no flags - must NOT disturb the marker
-- [C] 548(0, 0x10, {V,0,0x4000,3,op=3}, 1, &proc, 0)   MAP_FIXED - replacement if the marker dies
-- [D] 548(0, 0x10, {V2,0,0x4000,3,op=3}, ...) on an untouched 16 KiB hole - must land exactly at V2
-- [E] only if [C] replaced: the same call with V = 0xF00000000 (SceGnmTrapCode, a device window)
--
-- -- prior art:
--   results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt (flag mask: 0x1 /
--     0x1000 / 0x20000000 / 0xFFFFFFFF -> EINVAL, 0x0 / 0x10000000 -> 0)
--   results/phase36_realargs/1488b_sys548_map_desc_20261109_215258.txt (op 3 = anonymous map)
--   results/phase36_realargs/1492a_sys548_map_ceiling_20261109_220048.txt (op 3 without
--     MAP_FIXED abandons an occupied start and returns a different address)
--   results/phase36_realargs/1469a_*.txt (mmap 477 refuses MAP_FIXED over a live mapping)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (device windows movable)

print("=== PROBE 1508a: 548 op 3 WITH MAP_FIXED ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)

local function batch(flags, start, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent, uint64(start)) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return mk(548)(uint64(0), uint64(flags), uint64(ent), uint64(1), uint64(done), uint64(0))
    end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(done))
end

local rec = memory.alloc(0x30)
local function prot547(addr)
    for i = 0, 0x2C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A]
print("")
print("--- [A] baseline anon mapping ---")
local V = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  V=0x%X %s", V, V < 0 and es() or ""))
if V < 0 then print("=== PROBE 1508a VOID ===") return end
wr(V + 0x100, 0x11223344)
local rv5, p5 = prot547(V)
local marker = rd(V + 0x100)
print(string.format("  marker at V+0x100 = %s   547 rv=%d prot=%d", marker and string.format("%08X", marker) or "FAULT", rv5, p5))

-- ---------------------------------------------------------------- [B]
print("")
print("--- [B] op3 with flags 0x0 (control: must NOT disturb V) ---")
local rvB, cntB = batch(0x0, V, 0x4000, 3, 3)
print(string.format("  rv=%d processed=%d %s", rvB, cntB, rvB < 0 and es() or ""))
print(string.format("  marker after control = %s %s", marker and string.format("%08X", rd(V + 0x100) or 0) or "?",
      (rd(V + 0x100) == 0x11223344) and "(intact, expected)" or "*** CHANGED (unexpected) ***"))

-- ---------------------------------------------------------------- [C]
print("")
print("--- [C] op3 with flags 0x10 (MAP_FIXED) over the live entry ---")
print(string.format("  a replacement destroys V+0x100; a refusal leaves 11223344"))
local rvC, cntC = batch(0x10, V, 0x4000, 3, 3)
print(string.format("  rv=%d processed=%d %s", rvC, cntC, rvC < 0 and es() or ""))
local after = rd(V + 0x100)
local rv5b, p5b = prot547(V)
print(string.format("  marker now = %s   547 rv=%d prot=%d", after and string.format("%08X", after) or "FAULT", rv5b, p5b))
local REPLACED = (after == 0) or (after == nil)
print(string.format("  VERDICT: MAP_FIXED %s", REPLACED and "REPLACED THE ENTRY" or "was refused or ignored"))

-- ---------------------------------------------------------------- [D]
print("")
print("--- [D] op3 flags 0x10 onto an untouched 16 KiB-aligned hole ---")
local V2 = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  V2=0x%X (now free, we munmap it)", V2))
if V2 >= 0 then
    print(string.format("  munmap V2 -> %d", sgn(mk(73)(uint64(V2), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)))))
    print(string.format("  547(V2) rv=%d (want -1 = free)", prot547(V2)))
    local rvD, cntD = batch(0x10, V2, 0x4000, 3, 3)
    print(string.format("  rv=%d processed=%d %s", rvD, cntD, rvD < 0 and es() or ""))
    local rv5c, p5c = prot547(V2)
    print(string.format("  547(V2) rv=%d prot=%d  -> %s", rv5c, p5c,
          (rv5c == 0) and "mapped exactly at V2 (MAP_FIXED honoured)" or "not at V2"))
    wr(V2 + 0x100, 0x55667788)
    print(string.format("  write/read V2+0x100 = %s", rd(V2 + 0x100) and string.format("%08X", rd(V2 + 0x100)) or "FAULT"))
end

-- ---------------------------------------------------------------- [E]
print("")
print("--- [E] device window ---")
if not REPLACED then
    print("  skipped: [C] did not replace, so the device arm would only repeat a refusal")
else
    print("  [C] replaced an entry, so try the same on SceGnmTrapCode at 0xF00000000")
    print("  this destroys a device pager entry; a panic here is the expected failure mode")
    local rvE, cntE = batch(0x10, 0xF00000000, 0x4000, 3, 3)
    print(string.format("  rv=%d processed=%d %s", rvE, cntE, rvE < 0 and es() or ""))
    local rv5d, p5d = prot547(0xF00000000)
    print(string.format("  547(0xF00000000) rv=%d prot=%d", rv5d, p5d))
    print(string.format("  read 0xF00000000 = %s", rd(0xF00000000) and string.format("%08X", rd(0xF00000000)) or "FAULT"))
end

print("")
print(string.format("final canary pid %d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1508a COMPLETE ===")
