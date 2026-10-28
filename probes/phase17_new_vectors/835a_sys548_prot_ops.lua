-- CRASH_CLASS: HIGH
-- PROBE 835a: sys 548 op sweep with the entry layout the body requires
--
-- 13.60 body at 0xabbe60: arg4 ([uap+0x18]) is a signed count (js -> cleanup via
-- arg5), arg2 ([uap+8]) is a flag word tested against 0xe0bffb6f, arg3
-- ([uap+0x10]) is an array of 0x20-byte entries copied to the stack one by one:
--   +0x00 u64 addr   +0x08 u64 ?   +0x10 u64 len   +0x18 u8 prot   +0x1C u32 op
-- and the op switch is bounded by `cmp ecx,4 / ja` but its table lives outside the
-- dump.  Case 0xabc0b0 is a direct vm_map_protect([proc+0x200], addr, addr+len,
-- prot, 0) with addr and len required to be 0x4000-aligned and prot & 8 == 0.
--
-- This walks op 0..4 on a fresh RW mapping and reports the region's protection
-- from sys 674 after each call, so the protection op can be identified.

print("=== PROBE 835a: sys 548 op sweep ===")
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

local function num(addr, off)
    local lo = to_num(memory.read_dword(addr + off))
    local hi = to_num(memory.read_dword(addr + off + 4))
    return hi, lo
end

-- region containing `target`: returns prot dword, or -1 if not listed
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
        local shi, slo = num(rec, 0)
        local ehi, elo = num(rec, 8)
        local f = slo + shi * 4294967296
        local e = elo + ehi * 4294967296
        if target >= f and target < e then
            return to_num(memory.read_dword(rec + 0x18)), n
        end
    end
    return -1, n
end

local function region()
    local r = sc_mmap(uint64(0), uint64(3 * 0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local n = to_num(r)
    if n < 0 then return nil end
    return n
end

for op = 0, 4 do
    local r = region()
    if not r then print("[X] mmap failed") break end
    local p1 = prot_of(r)
    zero(entry, 0x40)
    memory.write_qword(entry, r)            -- addr
    memory.write_qword(entry + 8, 0)
    memory.write_qword(entry + 0x10, 0x4000) -- len
    memory.write_byte(entry + 0x18, 5)       -- prot R|X
    memory.write_dword(entry + 0x1C, op)
    print(string.format("[*] op=%d addr=%X prot-before=%X", op, r, p1))
    local ok, ret = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(to_num(entry)), uint64(1), uint64(0))
    end)
    if not ok then print("  PCALL-FAIL") break end
    local p2 = prot_of(r)
    print(string.format("  ret=%s prot-after=%X%s", hx(ret), p2, p2 ~= p1 and "  <-- CHANGED" or ""))
end

print("[Z] alive=true")
print("=== PROBE 835a COMPLETE ===")
