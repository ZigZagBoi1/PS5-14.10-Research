-- CRASH_CLASS: LOW -- 674 into our own buffer, 653 on the documented flag word, 673/654 which are
-- measured to return EINVAL rather than die. No kernel address is dereferenced.
-- PROBE 1484a: does blockpool_open create a mapping, and is it type 11
--
-- 1483a closed the device windows: they hold the GPU register-init table and shader body, no kernel
-- data. The remaining structural lead is the vm_object type-11 gate.
--
-- 654 blockpool_map and 673 blockpool_move both decode to: lookup the entry at arg1, require
-- entry->flags bit 1 clear, require entry->object non-NULL, require object byte +0x9d == 0xb, then
-- operate. Neither creates an object; 654's prologue reads uap[0]=addr (64 KiB aligned, inside the
-- map), uap[1]=len (64 KiB aligned), uap[2]=prot-ish (bits in {0,3,10}), uap[3]/uap[4] flag words.
-- There is no handle argument anywhere in either.
--
-- So the only way to obtain a type-11 object is for another call to create one. 1465a showed
-- 653(0x400000) returns a real handle (804) and 1466a showed no mmap flavour produces one, but
-- nobody has ever diffed 674 across a 653 call. That is this probe.
--
-- [0] baseline 674, every entry into an array
-- [A] 653(0x400000) -> handle
-- [B] 674 again, print every entry that was not in the baseline and every entry whose prot changed
-- [C] if a new entry appeared: first 16 bytes, then 673 on it with three target shapes
-- [D] if a new entry appeared: 654 on it with the flag words that pass its own decode
--
-- -- prior art:
--   results/phase36_realargs/1465a_blockpool_open_flags_20261109_175825.txt (653 handle 804)
--   results/phase36_realargs/1466a_sys673_flavours_20261109_175951.txt (no flavour is type 11)
--   results/phase36_realargs/1451a_sys673_object_type_20261109_172829.txt (673 gate chain)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (record layout)

print("=== PROBE 1484a: BLOCKPOOL MAPPING ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc674 = mk(674)
local cnt = memory.alloc(0x10)
local CAP = 512
local buf = memory.alloc(CAP * 72 + 0x1000)

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

local function nameat(b)
    local s = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        s = s .. string.char(ch)
    end
    return s
end

local function snap(tag)
    for i = 0, CAP * 72, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local okc, rv = pcall(function()
        return N(sc674(uint64(buf), uint64(72), uint64(CAP), uint64(cnt), uint64(0x40000000)))
    end)
    local n = 0
    pcall(function() n = N(memory.read_dword(cnt)) end)
    print(string.format("[%s] 674 rv=%s records=%d", tag, tostring(okc and rv or "EXC"), n))
    if not okc or rv ~= 0 or n <= 0 then return nil end
    if n > CAP then n = CAP end
    local t = {}
    for i = 0, n - 1 do
        local b = buf + i * 72
        local s = u64at(b, 0x00)
        t[tostring(s)] = { s = s, e = u64at(b, 0x08),
                           pr = N(memory.read_dword(b + 0x18)),
                           fl = N(memory.read_dword(b + 0x1C)),
                           nm = nameat(b) }
    end
    return t
end

local base = snap("0")
if not base then print("=== PROBE 1484a INCOMPLETE ===") return end

-- ---------------------------------------------------------------- [A] open a pool
print("")
print("--- [A] 653(0x400000) ---")
local sc653 = mk(653)
local okh, h = pcall(function() return N(sc653(uint64(0x400000), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
print(string.format("[A] 653 -> %s", tostring(okh and h or "EXC")))
if not okh or h < 0 then print("[A] " .. es()) end

-- ---------------------------------------------------------------- [B] diff
print("")
print("--- [B] map diff ---")
local after = snap("B")
if not after then print("=== PROBE 1484a INCOMPLETE ===") return end

local newent = nil
local newn, changedn = 0, 0
for k, v in pairs(after) do
    local o = base[k]
    if o == nil then
        newn = newn + 1
        print(string.format("    NEW  0x%X-0x%X prot=%d fl=%d %s", v.s, v.e, v.pr, v.fl, v.nm))
        if newent == nil then newent = v end
    elseif o.pr ~= v.pr then
        changedn = changedn + 1
        print(string.format("    PROT 0x%X-0x%X %d->%d %s", v.s, v.e, o.pr, v.pr, v.nm))
    end
end
for k, v in pairs(base) do
    if after[k] == nil then
        print(string.format("    GONE 0x%X-0x%X prot=%d %s", v.s, v.e, v.pr, v.nm))
    end
end
print(string.format("[B] new=%d prot-changed=%d", newn, changedn))

if newent == nil then
    print("")
    print("[B] 653 created no mapping - the type-11 object does not exist in our vm_map")
    local final0 = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("final canary: pid=%d (started %d)", final0, PID))
    print("=== PROBE 1484a COMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [C] is it type 11?
print("")
print(string.format("--- [C] target 0x%X-0x%X ---", newent.s, newent.e))

local head = {}
for i = 0, 16 do
    local v = nil
    pcall(function() v = N(memory.read_byte(newent.s + i)) end)
    head[#head + 1] = v and string.format("%02X", v) or "??"
end
print("    first 16 bytes: " .. table.concat(head, " "))

local sc673 = mk(673)
local sc654 = mk(654)
local function t673(a, b, c, d)
    local ok, rv = pcall(function()
        return N(sc673(uint64(string.format("0x%X", a)), uint64(string.format("0x%X", b)),
                       uint64(string.format("0x%X", c)), uint64(d), uint64(0), uint64(0)))
    end)
    if not ok then return "EXC" end
    if rv == -1 then return "-1 " .. es() end
    return tostring(rv)
end

local s1 = newent.s
local SPAN = 0x10000
if newent.e - newent.s > SPAN then SPAN = 0x10000 end
print(string.format("    673(0x%X, 0x%X, 0x%X)", s1, s1 + SPAN, s1 + 0x200000))
print("      -> " .. t673(s1, s1 + SPAN, s1 + 0x200000, 0))
print(string.format("    673(0x%X, 0x%X, 0x%X)", s1, s1 + SPAN, s1 + 0x100000))
print("      -> " .. t673(s1, s1 + SPAN, s1 + 0x100000, 0))
print(string.format("    673(0x%X, 0x%X, 0x%X)  self-move", s1, s1 + SPAN, s1))
print("      -> " .. t673(s1, s1 + SPAN, s1, 0))

-- ---------------------------------------------------------------- [D] 654 on it
print("")
print("--- [D] 654 on the same entry ---")
local function t654(a, l, p, f4, f5)
    local ok, rv = pcall(function()
        return N(sc654(uint64(string.format("0x%X", a)), uint64(string.format("0x%X", l)),
                       uint64(p), uint64(f4), uint64(f5), uint64(0)))
    end)
    if not ok then return "EXC" end
    if rv == -1 then return "-1 " .. es() end
    return tostring(rv)
end
for _, f4 in ipairs({0, 1, 0x10, 0x11}) do
    for _, p in ipairs({0, 1, 8, 9}) do
        print(string.format("    654(0x%X, 0x%X, %d, 0x%X, 0) -> %s",
            s1, SPAN, p, f4, t654(s1, SPAN, p, f4, 0)))
    end
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1484a COMPLETE ===")
