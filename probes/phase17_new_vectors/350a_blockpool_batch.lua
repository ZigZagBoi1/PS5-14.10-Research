-- CRASH_CLASS: MODERATE
-- PROBE 350a: call 657 with its recovered record format
--
-- sys_657.md: four slots (records, signed count, processed_out, flags), records
-- are 0x20 bytes, the opcode is the first 32-bit field, opcodes 1..5 dispatch,
-- anything else returns 0x2d, nonzero flags or a negative count returns 0x16,
-- count zero succeeds, and every record needs a map lookup on its qword at +8
-- with object type byte +0x9d == 11 - the same type wall 654 hit. The point is
-- to see how far the batch loop gets: a 0x2d means dispatch was reached, a
-- 0x16 means the flags/count gate, and the processed count tells whether the
-- cursor advanced.

print("=== PROBE 350a: BLOCKPOOL BATCH (657) ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end

local Z = uint64(0)
local sc658 = make_syscall(657)

local recs = memory.alloc(0x100)
for i = 0, 0x1F do
    pcall(function() memory.write_qword(recs + i * 8, uint64(0)) end)
end
local out = memory.alloc(0x40)
for i = 0, 7 do
    pcall(function() memory.write_qword(out + i * 8, uint64(0)) end)
end

local function batch(count, flags, label)
    pcall(function() memory.write_qword(out, uint64(0)) end)
    local ok, rv = pcall(function()
        return sc658(uint64(recs), uint64(count), uint64(out), uint64(flags), Z, Z)
    end)
    if not ok then
        print(string.format("  %-26s = EXC", label))
        return
    end
    local processed = to_num(memory.read_dword(out))
    print(string.format("  %-26s = %s  processed=%d", label, tostring(sgn(rv)), processed))
end

print("[A] the count and flags gates")
batch(0, 0, "count=0 flags=0")
batch(1, 0, "count=1 opcode=0")
batch(1, 1, "count=1 flags=1")
batch(-1, 0, "count=-1")

print("[B] opcodes 1..6 in one record")
for op = 1, 6 do
    pcall(function() memory.write_dword(recs, uint64(op)) end)
    batch(1, 0, string.format("count=1 opcode=%d", op))
end

print("[C] a record whose +8 points at a real mapping")
local page = memory.alloc(0x1000)
pcall(function() memory.write_dword(recs, uint64(1)) end)
pcall(function()
    local h, l = get_hi_lo(page)
    memory.write_dword(recs + 8, l)
    memory.write_dword(recs + 12, h)
end)
batch(1, 0, "opcode=1 with a mapped +8")

print("")
print("=== 350a DONE ===")
