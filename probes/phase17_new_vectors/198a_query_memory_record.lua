-- CRASH_CLASS: MODERATE
-- PROBE 198a: what 547 query_memory_protection actually returns
--
-- Context: 192a found that 547 accepts (address, out) and writes a 24-byte
-- record whose first dword is the address that was asked about. Nothing else
-- in that record has been read. A record that carries a physical address or a
-- kernel virtual address would be a KASLR-relevant leak, and it costs one call
-- per address to find out.
--
-- Section A reads the record for three user addresses with different backing
-- (heap, eboot text, a GPU mmap page). Section B asks about a kernel address
-- once, last, so a fault cannot hide the user-address results.

print("=== PROBE 198a: 547 record contents ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function show(v)
    if v == nil then return "killed" end
    return tostring(v)
end
local dead = false

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

local OUT = memory.alloc(0x40)
local HEAP = memory.alloc(0x100)
local gpu = nil
do
    local _, g = call(477, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
    if g ~= nil and g > 0 then gpu = g end
end
print(string.format("[0] heap=%s gpu=%s", show(to_num(HEAP)), show(gpu)))
print("")

local function dump_record(label, addr)
    for off = 0, 0x18 - 4, 4 do
        pcall(function() memory.write_dword(OUT + off, u64(0xA5A5A5A5)) end)
    end
    local _, rv = call(547, addr, OUT)
    if dead or rv == nil then
        print(string.format("    %-10s -> killed", label))
        return
    end
    local parts = {}
    for off = 0, 0x18 - 4, 4 do
        local ok, v = pcall(function() return memory.read_dword(OUT + off) end)
        parts[#parts + 1] = ok and string.format("%08X", to_num(v)) or "??"
    end
    print(string.format("    %-10s -> rev=%s  [%s]", label, show(rv), table.concat(parts, " ")))
end

print("[A] user addresses")
dump_record("heap", to_num(HEAP))
dump_record("heap+0x80", to_num(HEAP) + 0x80)
dump_record("codeptr", to_num(print))
if gpu then dump_record("gpu", gpu) end
print("")

print("[B] kernel address (may kill the process)")
dump_record("kffff", uint64(string.format("0x%08X%08X", 0xFFFF8000, 0)))
print("")

print("=== PROBE 198a COMPLETE ===")
