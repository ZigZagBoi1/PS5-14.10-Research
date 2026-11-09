-- CRASH_CLASS: MODERATE
-- PROBE 311a: sys 654 with the five slots its contract names
--
-- results/kernel_handlers/analysis/sys_654.md: narg=5 and the slots are
--   (address, length, operation, flags, reserved)
-- It rejects an address outside the process map, any low 16 bits set in
-- address or length (64 KiB alignment), flags outside bits 0x33, nonzero
-- reserved, and then routes operations 0, 3 and 10 through one helper and
-- 11..20 through another that translates operation/mode flags into per-page
-- metadata.
--
-- 183a called it as (handle, 0, 0x1000, buf) - a blockpool handle as the
-- address - so nothing ever reached the body. This probe supplies the real
-- shape on a 64 KiB-aligned GPU mapping and watches the region record that
-- sys 547 reports before and after each operation.

print("=== PROBE 311a: SYS 654 RANGE OPERATION ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wd(addr, v)
    pcall(function() memory.write_dword(addr, v) end)
end

local sc654 = make_syscall(654)
local sc547 = make_syscall(547)

-- region record via 547: { address, user_region } 0x18 bytes, prot at +0x10
local rec = memory.alloc(0x40)
local function prot_of(addr)
    wd(rec, 0)
    local ok, r = pcall(function() return sc547(addr, rec) end)
    if not ok then return "FAIL" end
    return string.format("ret=%d end=0x%X prot=0x%X", sgn(r), rd(rec + 8), rd(rec + 0x10))
end

-- 64 KiB aligned mapping
local sc_mmap = make_syscall(477)
local size = 0x40000
local okm, m = pcall(function()
    return sc_mmap(uint64(0), uint64(size), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local base = to_num(m)
if base == 0 or base == 0xFFFFFFFF then
    print("mmap failed: " .. tostring(base))
    return
end
local lo = to_num(uint64(base)) % (2 ^ 32)
local aligned = base - (lo % 0x10000)
print(string.format("mapping base=0x%X aligned=0x%X size=0x%X", base, aligned, size))
print("before: " .. prot_of(aligned + 0x10000))

local addr = uint64(string.format("0x%X", aligned + 0x10000))
local len = uint64(0x10000)

print("")
print("--- A: operations 0..20, flags 0, reserved 0 ---")
for op = 0, 20 do
    local okc, r = pcall(function()
        return sc654(addr, len, uint64(op), uint64(0), uint64(0))
    end)
    if not okc then print(string.format("  op %2d: DEAD", op)) break end
    local ret = sgn(r)
    print(string.format("  op %2d: ret=%d | %s", op, ret, prot_of(aligned + 0x10000)))
    if ret ~= -1 then
        local probe = rd(aligned + 0x10000)
        print(string.format("        first dword reads 0x%08X", probe))
    end
end

print("")
print("--- B: flags 0..0x33 on op 0 ---")
for _, fl in ipairs({ 0, 1, 2, 3, 0x10, 0x20, 0x30, 0x33, 0x40 }) do
    local okc, r = pcall(function()
        return sc654(addr, len, uint64(0), uint64(fl), uint64(0))
    end)
    if not okc then print(string.format("  flags 0x%X: DEAD", fl)) break end
    print(string.format("  flags 0x%X: ret=%d", fl, sgn(r)))
end

print("")
print("--- C: misalignment controls ---")
for _, off in ipairs({ 0, 1, 0x8000, 0x10000 }) do
    local a = uint64(string.format("0x%X", aligned + 0x10000 + off))
    local okc, r = pcall(function()
        return sc654(a, uint64(0x10000), uint64(0), uint64(0), uint64(0))
    end)
    if not okc then print(string.format("  off 0x%X: DEAD", off)) break end
    print(string.format("  off 0x%X: ret=%d", off, sgn(r)))
end

print("")
print("--- D: zero length ---")
do
    local okc, r = pcall(function()
        return sc654(addr, uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if okc then print(string.format("  len 0: ret=%d", sgn(r))) else print("  len 0: DEAD") end
end

print("=== DONE ===")
