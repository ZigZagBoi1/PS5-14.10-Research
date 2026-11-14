-- CRASH_CLASS: LOW -- every address touched is inside one anonymous mapping this probe made.
-- PROBE 1512a: does 548 op 3 with MAP_FIXED SPLIT a larger vm_map entry, or replace it whole?
--
-- Why it matters: op 3 is vm_map_delete(range) + vm_map_insert() inside the internal mapper.
-- Applied to the middle of one big entry there are exactly two behaviours:
--   (a) wholesale -- the whole entry is destroyed. One syscall frees a vm_object of any size.
--   (b) split     -- the entry is clipped twice and the range replaced. Each clip takes and drops
--                    vm_object references (vm_map_clip_start / clip_end, seen at 0x8ac8b564 /
--                    0x8ac8b7e5 in the 13.60 dump, both gated by `cmp byte [obj+0x9d],2` and
--                    `cmp qword [entry+0x70],0`). If a clip drops a reference it did not take,
--                    that is a vm_object use-after-free reachable with one syscall per carve.
-- Either answer is new: 1508a only ever carved a 0x4000 mapping, where the two are identical.
--
-- Discriminator: 547 reports the entry that contains a given address as {start, end, prot}. So
-- probe below the carved range and above it. If 547(lo) still answers with an entry that ENDS at
-- the carved start, the entry was split.
--
-- [A] mmap 16 MiB anon, prot 3; markers in page 0, page 1 (the carve target), page 2, +0x40000,
--     +0x800000 and the last dword of the mapping; 547 below / at / above
-- [B] 548(0, 0x10, {base+0x4000, 0, 0x4000, 3, op=3}, 1, &proc, 0) -- MAP_FIXED carve of page 1
-- [C] 547 below / at / above again; every marker read back
-- [D] a second carve at base+0x800000, same checks
-- [E] munmap(base, 0x1000000) and a final 547 -- does the tail still disappear cleanly
--
-- -- prior art:
--   results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt (op 3 honours MAP_FIXED
--     bit 0x10; rv equals the requested address; the marker at +0x100 dies)
--   results/phase36_realargs/1510a_low_address_ladder_20261109_225354.txt (0x4000 alignment and
--     floor; 0x0 refused)
--   results/phase36_realargs/1509b_sys548_op3_exec_20261109_225307.txt (op 3 strips exec bit 0x4
--     then applies write-implies-read)
--   results/phase36_realargs/1486a_gpu_pool_scan_20261109_203940.txt (op 2 protects a 3.9 GB
--     entry in one call, so entries that large exist in this map)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (plain munmap removes the
--     whole entry, not the requested sub-range -- op 3 may inherit the same habit)

print("=== PROBE 1512a: 548 op 3 SPLIT OR WHOLESALE ===")

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
local function rdq(a)
    local lo, hi = rd(a), rd(a + 4)
    if lo == nil or hi == nil then return nil end
    return lo + hi * 4294967296
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIGSYS ignored so an absent slot answers -1 instead of raising (353b)
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent  = memory.alloc(0x40)
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

-- 547: {start_lo@0, start_hi@4, end_lo@8, end_hi@0xC, prot@0x10, flags@0x14}
local rec = memory.alloc(0x30)
local function q547(addr)
    for i = 0, 0x2C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return nil end
    if sgn(rv) ~= 0 then return nil end
    local s, e = rdq(rec), rdq(rec + 8)
    if s == nil or e == nil then return nil end
    return s, e, rd(rec + 0x10), rd(rec + 0x14)
end

local function show547(tag, a)
    local s, e, p, f = q547(a)
    if s == nil then
        print(string.format("   %s 547(0x%X): no entry", tag, a))
    else
        print(string.format("   %s 547(0x%X): start=0x%X end=0x%X len=0x%X prot=0x%X flags=0x%X",
            tag, a, s, e, e - s, p or 0, f or 0))
    end
end

--============================================================== [A] baseline
print("")
print("[A] map 16 MiB anon prot 3, place markers")
local LEN = 0x1000000
local okm, mv = pcall(function()
    return mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local BASE = okm and sgn(mv) or -1
if BASE <= 0x10000 then
    print(string.format("   mmap failed: rv=%d %s -- VERDICT VOID", BASE, es()))
    return
end
print(string.format("   base = 0x%X", BASE))

local MARKS = {
    { 0x000000, 0x11110001 },  -- page 0 first dword
    { 0x003FFC, 0x11110002 },  -- page 0 last dword
    { 0x004000, 0x11110003 },  -- page 1 (the carve target)
    { 0x008000, 0x11110004 },  -- page 2
    { 0x040000, 0x11110005 },
    { 0x800000, 0x11110006 },
    { 0xFFFFFC, 0x11110007 },  -- very last dword
}
local function place_all()
    local n = 0
    for _, m in ipairs(MARKS) do
        wr(BASE + m[1], m[2])
        if rd(BASE + m[1]) == m[2] then n = n + 1 end
    end
    return n
end
local placed = place_all()
print(string.format("   markers placed: %d of %d", placed, #MARKS))
if placed ~= #MARKS then
    print("   VERDICT: VOID -- the mapping is not fully writable")
    return
end

show547("below", BASE)
show547("at   ", BASE + 0x4000)
show547("above", BASE + 0x100000)

--============================================================== [B] carve page 1
print("")
print("[B] 548 op3 MAP_FIXED carve of page 1")
local rv, proc = batch(0x10, BASE + 0x4000, 0x4000, 3, 3)
print(string.format("   rv=%d processed=%d %s", rv, proc, rv == -1 and es() or ""))
if proc ~= 1 then
    print("   VERDICT: VOID -- op 3 refused, nothing was carved")
    return
end
if rv ~= BASE + 0x4000 then
    print(string.format("   NOTE: landed at 0x%X, not the requested 0x%X", rv, BASE + 0x4000))
end

--============================================================== [C] what survived
print("")
print("[C] entry structure and marker survival after the carve")
show547("below", BASE)
show547("at   ", BASE + 0x4000)
show547("above", BASE + 0x100000)

local alive, dead = {}, {}
for _, m in ipairs(MARKS) do
    local v = rd(BASE + m[1])
    if v == nil then
        table.insert(dead, string.format("+0x%X FAULT", m[1]))
    elseif v == m[2] then
        table.insert(alive, string.format("+0x%X", m[1]))
    elseif v == 0 then
        table.insert(dead, string.format("+0x%X ZERO", m[1]))
    else
        table.insert(dead, string.format("+0x%X=0x%08X", m[1], v))
    end
end
print("   survivors: " .. (#alive > 0 and table.concat(alive, " ") or "(none)"))
print("   changed  : " .. (#dead > 0 and table.concat(dead, " ") or "(none)"))

local s0 = q547(BASE)
local s2 = q547(BASE + 0x8000)
local verdict
if s0 == nil and s2 == nil then
    verdict = "WHOLESALE"
elseif s0 ~= nil and s0 <= BASE and select(2, q547(BASE)) == BASE + 0x4000 then
    verdict = "SPLIT"
else
    verdict = "OTHER"
end
print("   shape: " .. verdict)

--============================================================== [D] second carve
print("")
print("[D] second carve at +0x800000")
local rv2, proc2 = batch(0x10, BASE + 0x800000, 0x4000, 3, 3)
print(string.format("   rv=%d processed=%d %s", rv2, proc2, rv2 == -1 and es() or ""))
show547("below2", BASE + 0x400000)
show547("above2", BASE + 0xC00000)

--============================================================== [E] cleanup
print("")
print("[E] munmap the whole 16 MiB and confirm the tail is gone")
local okmu, mur = pcall(function()
    return mk(73)(uint64(BASE), uint64(LEN), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("   munmap rv=%s", okmu and tostring(sgn(mur)) or "EXC"))
show547("after munmap", BASE)
show547("after munmap", BASE + 0x100000)

print("")
local final_pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[Z] alive pid=%d (was %d)", final_pid, PID))
print(string.format("[Z] VERDICT: %s -- one carve %s the containing entry",
    verdict, verdict == "SPLIT" and "split" or (verdict == "WHOLESALE" and "destroyed" or "did something else to")))
print("=== PROBE 1512a COMPLETE ===")
