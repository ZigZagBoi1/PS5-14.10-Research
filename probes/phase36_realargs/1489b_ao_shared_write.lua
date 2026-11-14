-- CRASH_CLASS: MODERATE -- stores 8 bytes at +0x100 of the 32 KiB ./AOSharedState region, well
-- past the four header dwords other probes have read, then reads them back and restores the
-- protection. If another process consumes this region the store could disturb it; the offset is
-- chosen so the header the other side reads is untouched.
-- PROBE 1489b: is ./AOSharedState durable memory outside this process?
--
-- 1489a measured that 548 op 2 raises ./AOSharedState (0x310D80000, 0x8000 bytes, prot 1, flags 0xC)
-- to prot 3 and puts it back to 1, so the region is READ-only by policy and not by max_prot. The
-- only other thing in the map with flag 0xC is a mapping this process creates itself, so this one
-- belongs to the launcher.
--
-- [A] 674, locate ./AOSharedState and print its four header dwords at prot 1
-- [B] 548 op 2 prot 3, read the same header again
-- [C] store two distinct qwords at +0x100 and +0x108, read them back
-- [D] restore prot 1, read +0x100 again - a surviving value proves the store reached real memory,
--     not a copy-on-write shadow
-- [E] 674 again: did the entry survive the protection round trip
--
-- -- prior art:
--   results/phase36_realargs/1489a_ao_shared_prot_20261109_215505.txt (prot 1 -> 3 -> 1)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the /AO records, flags 0xC)
--   results/phase36_realargs/1481b_gpu_windows_write_20261109_201732.txt (the store oracle)

print("=== PROBE 1489b: AO SHARED STATE WRITE ===")

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
local function qw(a) return N(memory.read_dword(a + 4)) * 4294967296 + N(memory.read_dword(a)) end
local function nm(a, maxlen)
    local o = {}
    for i = 0, maxlen - 1 do
        local c = N(memory.read_byte(a + i))
        if c == 0 then break end
        if c >= 32 and c < 127 then o[#o + 1] = string.char(c) else o[#o + 1] = "." end
    end
    return table.concat(o)
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

local function protect(addr, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] locate it
print("")
print("--- [A] 674: find ./AOSharedState ---")
local AO = nil
do
    local MAX = 400
    local buf = memory.alloc(MAX * 72 + 0x40)
    local cnt = memory.alloc(0x10)
    for i = 0, MAX * 72 + 0x30, 8 do pcall(function() memory.write_qword(buf + i, uint64(0)) end) end
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local ok = pcall(function()
        return N(mk(674)(uint64(buf), uint64(72), uint64(MAX), uint64(cnt), uint64(0x40000000), uint64(0)))
    end)
    if ok then
        local n = N(memory.read_dword(cnt))
        if n <= 0 or n > MAX then n = 0 end
        for i = 0, n - 1 do
            local r = buf + i * 72
            local name = nm(r + 0x20, 40)
            if name:find("SharedState") then
                AO = {start = qw(r + 0x00), len = qw(r + 0x08) - qw(r + 0x00), prot = N(memory.read_dword(r + 0x18)), name = name}
                print(string.format("  %s 0x%X len 0x%X prot=%d", name, AO.start, AO.len, AO.prot))
            end
        end
    else
        print("  674 raised")
    end
end
if not AO then
    print("  ./AOSharedState is not in the map this boot")
    print("=== PROBE 1489b INCOMPLETE ===")
    return
end

local function dump16(tag)
    local o = {}
    for i = 0, 0x3C, 4 do
        local v = nil
        local ok = pcall(function() v = N(memory.read_dword(AO.start + i)) end)
        if not ok or v == nil then o[#o + 1] = "--------" break end
        o[#o + 1] = string.format("%08X", v)
    end
    print(string.format("  %s: %s", tag, table.concat(o, " ")))
end

-- ---------------------------------------------------------------- [A] read at prot 1
dump16("[A] prot " .. AO.prot .. " header")
-- capture the target words at the ORIGINAL protection, so "reverted" is distinguishable from
-- "the prot-3 view and the prot-1 view are different pages"
print(string.format("  [A] +0x100 at prot %d = %08X %08X %08X %08X",
    AO.prot, N(memory.read_dword(AO.start + 0x100)), N(memory.read_dword(AO.start + 0x104)),
    N(memory.read_dword(AO.start + 0x108)), N(memory.read_dword(AO.start + 0x10C))))

-- ---------------------------------------------------------------- [B] raise
print("")
print("--- [B] 548 op 2 prot 3 ---")
local rv, pr = protect(AO.start, AO.len, 3)
print(string.format("  rv=%s processed=%s %s -> 547 prot %d", tostring(rv), tostring(pr), rv == -1 and es() or "", map547(AO.start)))
if rv ~= 0 then
    print("  could not raise the region; nothing to write")
    print("=== PROBE 1489b INCOMPLETE ===")
    return
end
dump16("[B] header after raise")

-- ---------------------------------------------------------------- [C] store
print("")
print("--- [C] store at +0x100 ---")
pcall(function() memory.write_dword(AO.start + 0x100, uint64(0xDEAD1234)) end)
pcall(function() memory.write_dword(AO.start + 0x104, uint64(0xCAFEBABE)) end)
pcall(function() memory.write_dword(AO.start + 0x108, uint64(0x55667788)) end)
pcall(function() memory.write_dword(AO.start + 0x10C, uint64(0x99AABBCC)) end)
print(string.format("  +0x100 = %08X %08X %08X %08X",
    N(memory.read_dword(AO.start + 0x100)), N(memory.read_dword(AO.start + 0x104)),
    N(memory.read_dword(AO.start + 0x108)), N(memory.read_dword(AO.start + 0x10C))))
local landed = N(memory.read_dword(AO.start + 0x100)) == 0xDEAD1234

-- ---------------------------------------------------------------- [D] restore the protection
print("")
print("--- [D] restore prot " .. AO.prot .. " and read back ---")
local rv2, pr2 = protect(AO.start, AO.len, AO.prot)
print(string.format("  rv=%s processed=%s -> 547 prot %d", tostring(rv2), tostring(pr2), map547(AO.start)))
local after = N(memory.read_dword(AO.start + 0x100))
print(string.format("  +0x100 after restore = %08X (store %s, now %s)",
    after, landed and "landed" or "did NOT land",
    after == 0xDEAD1234 and "still there" or "gone"))
print(string.format("  +0x108 after restore = %08X", N(memory.read_dword(AO.start + 0x108))))

-- ---------------------------------------------------------------- [E] entry survived
print("")
print("--- [E] 674 after the round trip ---")
for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
local p = map547(AO.start)
print(string.format("  547 at 0x%X: prot %d", AO.start, p))

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1489b COMPLETE ===")
