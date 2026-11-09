-- CRASH_CLASS: LOW
-- PROBE 443a: can a registered object ever be destroyed?
--
-- 442a found an asymmetry between the two families:
--   * osem: 550 delete works on the creator's handle and removes the name (439a), 552 close
--     works on the opened handle.
--   * evf: 541 refuses the creator's handle (-1) and accepts the opened one (0), so there is
--     no delete path at all - and after every handle was closed, 540 still resolved the name
--     and returned a fresh handle (8710).
--
-- That means a name registered with attribute 0x100 holds a reference the process cannot drop.
-- This measures whether it is unbounded: create N registered evf objects under distinct names,
-- close every handle, and see how far it goes and whether the first name still resolves.

print("=== PROBE 443a: NAMED OBJECT LEAK ===")

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local nm = memory.alloc(0x40)
local function put(s)
    local j = 1
    while j <= #s do memory.write_byte(nm + j - 1, s:byte(j)); j = j + 1 end
    memory.write_byte(nm + #s, 0)
end

local N = 1000
local made, failed = 0, 0
local lastOk, firstBad = -1, -1
local k = 1
while k <= N do
    put(string.format("omp443a_%04d", k))
    local h = call(538, nm, 0x100, 0, 0, 0, 0)
    if h < 0 then
        failed = failed + 1
        if firstBad < 0 then firstBad = k end
    else
        made = made + 1
        lastOk = h
        call(541, h, 0, 0, 0, 0, 0)
    end
    k = k + 1
end
print(string.format("[A] created %d of %d (first failure at %d), last handle %d", made, N, firstBad, lastOk))

put("omp443a_0001")
local r1 = call(540, nm, 0, 0, 0, 0, 0)
put("omp443a_1000")
local r2 = call(540, nm, 0, 0, 0, 0, 0)
put("omp443a_absent")
local r3 = call(540, nm, 0, 0, 0, 0, 0)
print(string.format("[B] resolve first=%d last=%d absent=%d", r1, r2, r3))

print("=== 443a DONE ===")
