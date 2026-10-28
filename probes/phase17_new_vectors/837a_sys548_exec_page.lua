-- CRASH_CLASS: MODERATE (never reads a mapping; only 674 metadata)
-- PROBE 837a: can 548 give W to an executable page?
--
-- 836a: op 3 (map anon) honours a chosen user address but strips X (request 5 ->
-- prot 1, request 7 -> prot 3).  Case 0xabc0b0 of the handler is a direct
-- vm_map_protect(map, addr, addr+len, prot, 0), so if a page can be created with
-- X first, this op is the only route that might add W to it without the
-- mprotect wrapper's behaviour.  This only inspects protection metadata from
-- sys 674 -- it never dereferences the mapping.

print("=== PROBE 837a: executable mapping then protect ===")
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

local sc_mmap = make_syscall(477)
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

local function call548(addr, prot, op)
    zero(entry, 0x40)
    memory.write_qword(entry, addr)
    memory.write_qword(entry + 8, 0)
    memory.write_qword(entry + 0x10, 0x4000)
    memory.write_byte(entry + 0x18, prot)
    memory.write_dword(entry + 0x1C, op)
    local ok, ret = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(to_num(entry)), uint64(1), uint64(0))
    end)
    if not ok then return nil end
    return ret
end

for _, want in ipairs({4, 5, 6, 7}) do
    local r = to_num(sc_mmap(uint64(0), uint64(0x4000), uint64(want), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if r < 0 or r == 0 then
        print(string.format("[A] mmap prot=%d -> %s", want, hx(uint64(r))))
    else
        print(string.format("[A] mmap prot=%d -> %X  region prot=%X", want, r, prot_of(r)))
        for op = 0, 4 do
            local ret = call548(r, 7, op)
            if ret == nil then print("  PCALL-FAIL") break end
            print(string.format("   op=%d ret=%s prot=%X", op, hx(ret), prot_of(r)))
        end
    end
end

-- control: a plain RW page, protect op asking for RWX
do
    local r = to_num(sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    print(string.format("[B] control RW page=%X prot=%X", r, prot_of(r)))
    for op = 0, 4 do
        local ret = call548(r, 7, op)
        if ret == nil then print("  PCALL-FAIL") break end
        print(string.format("   op=%d ret=%s prot=%X", op, hx(ret), prot_of(r)))
    end
end

print("[Z] alive=true")
print("=== PROBE 837a COMPLETE ===")
