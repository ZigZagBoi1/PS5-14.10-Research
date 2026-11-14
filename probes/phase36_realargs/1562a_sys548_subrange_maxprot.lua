-- CRASH_CLASS: MODERATE
-- PROBE 1562a: does 548 op 2 on a 16 KiB SUB-RANGE of a device entry, or on a
--              range spanning two different entries, inherit the wrong
--              max_prot and grant EXEC?
--
-- Context: 1535a measured that 548 op 2 cannot add PROT_EXEC to the whole
-- `SceGnmTrapData` window: 0x37 / 0x7 / 0x5 all answer EACCES(13) while 0x33
-- (its own value) is accepted. 1533a measured the same refusal on anonymous
-- pages (prot 7 -> EACCES) and 424a-424c on plain 477. So every entry a game
-- process can map has a max_prot without bit 4.
--
-- What has never been tried is a PARTIAL range. vm_map_protect splits an entry
-- when the range covers only part of it, and the batch applier re-looks-up per
-- entry after dropping the lock (docs/VM_LAYER_14_10.md sections 12 and 19). If
-- a split entry inherits its max_prot from the wrong neighbour, or if the
-- applier validates only the first entry of a multi-entry range, a 16 KiB
-- request could come back rv=0 with EXEC where the whole-window request said
-- EACCES. That would reopen W^X from userland, so it is worth one run.
--
-- prior art:
--   results/phase36_realargs/1535a_gpu_window_exec_via_548_20261110_143418.txt
--     -- whole-window op 2 on SceGnmTrapData: 0x37/0x7/0x5 -> EACCES(13),
--        0x33 -> rv=0 processed=1, 547 unchanged.
--   results/phase36_realargs/1548a_map_fixed_over_device_entry_20261110_173458.txt
--     -- op 3 MAP_FIXED carves a device entry correctly: 8/8 accepted, boundary
--        intact, carved page reads 0 while the neighbour still reads C0012800.
--   results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt
--     -- op 2 requires 16 KiB alignment on start and length.
--   docs/VM_LAYER_14_10.md section 15 -- op 2 is vm_map_protect, refuses EXEC.
--
-- Method: find the window by name through 674 (fallback 0xF00004000), then:
--   [A] baseline 547 of the whole window.
--   [B] op 2 over ONE 16 KiB page inside the window, prot 0x33 (its own value).
--       A rv=0 here proves sub-ranges are accepted at all.
--   [C] op 2 over the same page, prot 0x37  -- the whole-window answer was
--       EACCES; if this returns 0, the sub-range path lost the max_prot check.
--   [D] op 3 MAP_FIXED a fresh anon page over the NEXT 16 KiB page of the
--       window (1548a's measured shape), giving an anon entry directly adjacent
--       to a device entry.
--   [E] op 2 over a 16 KiB range spanning the carved anon page and the device
--       page after it, prot 0x7 (RWX). Anon max_prot is 3 and the device's has
--       no X either, so anything but EACCES means the applier used one entry's
--       max_prot for both.
--   [F] 547 the carved page and its device neighbour, then restore the device
--       page's original protection.
-- Nothing here executes from the window; a positive result is followed by a
-- separate exec test modelled on 1535a.

print("=== PROBE 1562a: 548 op2 on a sub-range of a device entry ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function wq(a, v) pcall(function() memory.write_qword(uint64(a), uint64(v)) end) end

local sc_mmap  = mk(477)
local sc_getpid = mk(20)
local sc_547   = mk(547)
local sc_548   = mk(548)
local sc_sleep = mk(240)

local PAGE = 0x4000

local ent  = memory.alloc(0x100)
local done = memory.alloc(8)

local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local function prep(start, len, prot, op)
    zero(ent, 0x40)
    wd(ent + 0x00, start % 4294967296)
    wd(ent + 0x04, math.floor(start / 4294967296))
    wd(ent + 0x10, len % 4294967296)
    wd(ent + 0x14, math.floor(len / 4294967296))
    wd(ent + 0x18, prot)
    pcall(function() memory.write_byte(uint64(ent + 0x1C), op) end)
    wd(done, 0xEEEEEEEE)
end

local function fire()
    local ok, rv = pcall(function()
        return sc_548(uint64(0), uint64(0), uint64(ent), uint64(1),
                      uint64(done), uint64(0))
    end)
    return ok and to_num(rv) or -999, rd(done)
end

-- 547 record: {start qword, end qword, prot dword @0x10, flags dword @0x14}
local rec = memory.alloc(0x20)
local function prot_of(addr)
    local ok, rv = pcall(function() return sc_547(uint64(addr), uint64(rec)) end)
    if not ok or to_num(rv) ~= 0 then return nil end
    return rd(rec + 0x10), rq(rec), rq(rec + 8), rd(rec + 0x14)
end

local function mmap_anon(len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

local function mmap_fixed(at, len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(at), uint64(len), uint64(3), uint64(0x1012),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

print(string.format("[0] pid=%d", to_num(sc_getpid())))

-- ---- [A] find the window ----
-- 674 is the map enumerator; use the measured shape.
do
    local out = memory.alloc(0x48)
    local cur = memory.alloc(8)
    wq(cur, 0)
    local i = 0
    while i < 400 do
        wq(out, 0)
        local ok, rv = pcall(function()
            return mk(674)(uint64(out), uint64(0x48), uint64(cur))
        end)
        if not ok or to_num(rv) ~= 0 then break end
        local start = rq(out)
        local enda  = rq(out + 8)
        local name  = ""
        for o = 0x21, 0x30 do
            local c = rd(out + o)
            if c == nil or c == 0 then break end
            name = name .. string.char(c % 256)
        end
        if name:find("SceGnmTrapData") then found = start break end
        i = i + 1
    end
    W = found
end
if not W then
    W = 0xF00004000
    print(string.format("[A] 674 did not name the window; using the documented 0x%X", W))
else
    print(string.format("[A] 674 named SceGnmTrapData at 0x%X", W))
end
local p0, s0, e0, f0 = prot_of(W)
print(string.format("[A] W=0x%X 547: prot=%s rec=[0x%X,0x%X) flags=0x%X",
    W, tostring(p0), to_num(s0 or 0), to_num(e0 or 0), to_num(f0 or 0)))
if p0 == nil then
    print("=== VOID: 547 cannot describe the window; nothing below is interpretable ===")
    return
end
local DEVPROT = p0

-- ---- [B] op 2 on one page inside the window, its own protection ----
local MID = W + PAGE
print("")
print(string.format("[B] op2(MID=0x%X, 0x4000, prot=0x%X)", MID, DEVPROT))
prep(MID, PAGE, DEVPROT, 2)
local rvB, prB = fire()
print(string.format("[B] rv=%d processed=%s", rvB, tostring(prB)))
local pB = prot_of(MID)
print(string.format("[B] 547(MID) after=%s", tostring(pB)))
if rvB ~= 0 then
    print("[B] sub-ranges are refused even at the window's own protection;")
    print("[B] the rest of this probe cannot distinguish a max_prot leak.")
end

-- ---- [C] the same page with EXEC added ----
print("")
print(string.format("[C] op2(MID, 0x4000, prot=0x37)  -- whole-window answer was EACCES"))
prep(MID, PAGE, 0x37, 2)
local rvC, prC = fire()
print(string.format("[C] rv=%d processed=%s", rvC, tostring(prC)))
local pC = prot_of(MID)
print(string.format("[C] 547(MID) after=%s", tostring(pC)))
if rvC == 0 and pC ~= nil and pC - pC % 0x10 >= 4 then
    print("[C] *** SUB-RANGE ACCEPTED EXEC where the whole window refused it ***")
elseif rvC == 0 then
    print("[C] rv=0 but 547 does not show bit 4; the call was accepted and inert")
else
    print("[C] refused, same as the whole-window call: the check is per entry")
end

-- ---- [D] carve an anon page next to a device page ----
print("")
local CARVE = W + 2 * PAGE
print(string.format("[D] op3 MAP_FIXED anon at CARVE=0x%X", CARVE))
local got = mmap_fixed(CARVE, PAGE)
print(string.format("[D] mmap returned %s", tostring(got)))
local pD, sD, eD = prot_of(CARVE)
print(string.format("[D] 547(CARVE) prot=%s rec=[0x%X,0x%X)",
    tostring(pD), to_num(sD or 0), to_num(eD or 0)))
if got ~= CARVE then
    print("[D] the carve did not land at CARVE; [E] would describe an unrelated range")
end

-- ---- [E] a range spanning the carved anon page and the device page after it ----
print("")
print("[E] op2(CARVE, 0x4000, prot=0x7) -- the carved anon page, RWX")
prep(CARVE, PAGE, 0x7, 2)
local rvE, prE = fire()
print(string.format("[E] rv=%d processed=%s", rvE, tostring(prE)))
local pE = prot_of(CARVE)
print(string.format("[E] 547(CARVE) after=%s", tostring(pE)))
if rvE == 0 and pE == 7 then
    print("[E] *** ANON PAGE BECAME RWX -- investigate immediately ***")
else
    print("[E] anon page did not become RWX; the max_prot check held")
end

-- ---- [F] neighbour and restore ----
print("")
local pF, sF, eF = prot_of(W + 3 * PAGE)
print(string.format("[F] 547(W+3*PAGE) prot=%s", tostring(pF)))
print(string.format("[F] restoring MID to 0x%X", DEVPROT))
prep(MID, PAGE, DEVPROT, 2)
local rvG, prG = fire()
print(string.format("[F] restore rv=%d processed=%s", rvG, tostring(prG)))
local pG = prot_of(MID)
print(string.format("[F] 547(MID) after restore=%s (want %s)",
    tostring(pG), tostring(DEVPROT)))

print("")
print("=== PROBE 1562a COMPLETE ===")
