-- CRASH_CLASS: LOW -- no store is made into any /AO region; the only writes are a probe-owned anon
-- page and the 548 entry buffer. Regions are located with 674, and 548 is asked only to change a
-- protection and change it back.
-- PROBE 1489a: is the /AO shared state an entry 548 can raise?
--
-- 1481f dumped the 336-entry map. Among the records it found a family that no other probe has
-- touched: `/AOSharedState` at 0x310F70000 with prot 1 (read-only), `/AOP_0000000087_*` at 0x10000
-- each and `/AOCtx_0000000087_*` at 0x4000 each, plus `/AOCtx_0000000087_ko675L` at 0x200F6C000.
-- Their 674 flag field is 0xC, which is not the flag of any mapping this process can create, so
-- they are shared objects owned by something else - the only memory in the map that may not be ours.
--
-- 548 op 2 changes the protection of any entry that is not execute-only (1480c/1481a/1486a). The
-- question here is narrow and safe: does op 2 accept a prot of 3 on an /AO entry? If it does, the
-- next probe can write and ask whether the write survives our process, which would make these pages
-- a cross-process channel. If it refuses with EACCES, they have a max_prot like module text and the
-- family is closed without ever writing into it.
--
-- [A] 674 with the proven shape, print every /AO record with its prot
-- [B] 548 op 2 prot 3 on /AOSharedState, then 547, then op 2 prot 1 to restore
-- [C] the same for every other /AO record, restored the same way
-- [D] 548 control on an anon page so a blanket refusal is distinguishable from a dead syscall
--
-- -- prior art:
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the /AO records and flags 0xC)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (op 2 on a device entry)
--   results/phase36_realargs/1485a_protect_exec_only_entry_20261109_203825.txt (an EACCES refusal)
--   probes/phase17_new_vectors/1251a_674_calibration.lua (the 674 call shape used here)

print("=== PROBE 1489a: /AO SHARED STATE UNDER 548 ===")

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
local function qw(addr)
    local lo = N(memory.read_dword(addr))
    local hi = N(memory.read_dword(addr + 4))
    return hi * 4294967296 + lo
end
local function nm(addr, maxlen)
    local out = {}
    for i = 0, maxlen - 1 do
        local c = N(memory.read_byte(addr + i))
        if c == 0 then break end
        if c >= 32 and c < 127 then out[#out + 1] = string.char(c) else out[#out + 1] = "." end
    end
    return table.concat(out)
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

local function fill_entry(addr, field8, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", field8))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1, -1, -1 end
    return N(memory.read_dword(rec + 0x10)), N(memory.read_dword(rec + 0x14)), N(memory.read_dword(rec + 0x00))
end

local function protect(addr, len, prot)
    fill_entry(addr, 0, len, prot, 2)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

-- ---------------------------------------------------------------- [A] the map
print("")
print("--- [A] 674 records whose name starts with /AO or contains SharedState ---")
local AO = {}
do
    local MAX = 400
    local buf = memory.alloc(MAX * 72 + 0x40)
    local cnt = memory.alloc(0x10)
    for i = 0, MAX * 72 + 0x30, 8 do pcall(function() memory.write_qword(buf + i, uint64(0)) end) end
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local ok, rv = pcall(function()
        return N(mk(674)(uint64(buf), uint64(72), uint64(MAX), uint64(cnt), uint64(0x40000000), uint64(0)))
    end)
    if not ok then
        print("  674 raised")
    else
        local n = N(memory.read_dword(cnt))
        if n <= 0 or n > MAX then n = rv end
        print(string.format("  674 rv=%s count=%d", tostring(rv), n))
        local printed = 0
        for i = 0, n - 1 do
            local r = buf + i * 72
            local s, e = qw(r + 0x00), qw(r + 0x08)
            local p, f = N(memory.read_dword(r + 0x18)), N(memory.read_dword(r + 0x1C))
            local name = nm(r + 0x20, 40)
            if name:find("SharedState") or name:sub(1, 3) == "/AO" then
                AO[#AO + 1] = {start = s, len = e - s, prot = p, name = name}
                if printed < 24 then
                    print(string.format("    0x%X len 0x%X prot=%d flags=0x%X %s", s, e - s, p, f, name))
                    printed = printed + 1
                end
            end
        end
        print(string.format("  /AO family: %d records", #AO))
    end
end

-- ---------------------------------------------------------------- [D] control first
print("")
print("--- [D] 548 control on an anon page ---")
local ctl_ok = false
do
    local va = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va > 0x10000 then
        local p0 = map547(va)
        local rv, pr = protect(va, 0x4000, 1)
        local p1 = map547(va)
        print(string.format("  ctl 0x%X prot %d -> op2(1) rv=%s processed=%d -> prot %d", va, p0, tostring(rv), pr, p1))
        if rv == 0 and p1 == 1 then ctl_ok = true end
        protect(va, 0x4000, 3)
    end
end
print(string.format("[D] control usable: %s", tostring(ctl_ok)))
if not ctl_ok then
    print("548 does not move protection this boot; stopping")
    print("=== PROBE 1489a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B]/[C] the /AO family
print("")
print("--- [B] op 2 prot 3 on each /AO record, then restore ---")
if #AO == 0 then
    print("  no /AO records found; nothing to ask")
else
    for i, r in ipairs(AO) do
        local before = map547(r.start)
        local rv, pr = protect(r.start, r.len, 3)
        local after = map547(r.start)
        local e = ""
        if rv == -1 then e = es() end
        print(string.format("  %-38s 0x%X len 0x%X prot %d -> op2(3) rv=%-3s processed=%s %s -> prot %d",
            r.name:sub(1, 38), r.start, r.len, before, tostring(rv), tostring(pr), e, after))
        if rv == 0 and after ~= before then
            local rb, prb = protect(r.start, r.len, before)
            local rest = map547(r.start)
            print(string.format("      restore -> rv=%s processed=%s prot now %d", tostring(rb), tostring(prb), rest))
        end
    end
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary: pid=%d (started %d)", PID, PID))
print(string.format("final canary live: %s", tostring(final == PID)))
print("=== PROBE 1489a COMPLETE ===")
