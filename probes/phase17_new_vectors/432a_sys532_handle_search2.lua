-- CRASH_CLASS: MODERATE
-- PROBE 432a: the same walk with the argument slots 308a actually used
--
-- results/kernel_handlers/analysis/sys_532_deep.md recovers the check in full: the checksum
-- is byte[3] + byte[0] + byte[1] + bits[8:15] + byte[5]*byte[4], compared against bytes
-- [6:7]; the type index is byte[4] xor 0x6b and must be <= 0xC; the type then selects one
-- of two key tables, and four bytes XOR-decoded through it give a registration entry ID that
-- is looked up in a table of about 2048 entries.
--
-- 308a forged a checksum-valid handle and got 0x800D0203 (entry not found) for types 0-0xC,
-- but it only ever tried one set of bytes. The ID is a function of the caller's bytes, so
-- the whole ID space is reachable by walking one byte at a time while keeping the checksum
-- right. Any answer other than 0203/0204 means the lookup resolved.
--
-- 431a put the handle in the third slot and every call answered 0x800D0202 (missing
-- argument). 308a, which did reach the checksum, stages two buffers: `532(cmd, 0, out,
-- inp, size, 0)` - output in slot 3, the packed handle in slot 4. That is the shape here.

print("=== PROBE 432a: SYS 532 HANDLE SEARCH (true slots) ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
local inp = 0
if page > 0 then inp = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0) end
print(string.format("[A] out=0x%X inp=0x%X", page, inp))
if page <= 0 or inp <= 0 then print("=== 432a DONE ===") return end

local function write_handle(b0, b1, b2, b3, b4, b5)
    local sum = (b3 + b0 + b1 + b2 + b5 * b4) % 0x10000
    memory.write_byte(inp + 0, b0)
    memory.write_byte(inp + 1, b1)
    memory.write_byte(inp + 2, b2)
    memory.write_byte(inp + 3, b3)
    memory.write_byte(inp + 4, b4)
    memory.write_byte(inp + 5, b5)
    memory.write_byte(inp + 6, sum % 0x100)
    memory.write_byte(inp + 7, math.floor(sum / 0x100))
    return sum
end

local function probe(b0, b1, b2, b3, b4, b5)
    write_handle(b0, b1, b2, b3, b4, b5)
    memory.write_dword(page, 0x41414141)
    local rv = call(532, 0x18, 0, page, inp, 8, 0)
    local st = to_num(memory.read_dword(page))
    return rv, st
end

-- [B] control: type 0, everything zero
local rv, st = probe(0, 0, 0, 0, 0x6b, 1)
print(string.format("[B] control handle: rv=%d status=0x%X", rv, st))

-- [C] every type against a fixed byte pattern
local seen = {}
local t = 0
while t <= 0x0C do
    local b4 = 0x6b
    -- xor with the type: b4 = type xor 0x6b
    b4 = 0
    local v = t
    local bit = 1
    local x = 0x6b
    local r = 0
    local p = 1
    while p < 256 do
        local a = math.floor(v / p) % 2
        local b = math.floor(x / p) % 2
        if a ~= b then r = r + p end
        p = p * 2
    end
    b4 = r
    local r2, s2 = probe(0x11, 0x22, 0x33, 0x44, b4, 1)
    print(string.format("[C] type %d (b4=0x%X) rv=%d status=0x%X", t, b4, r2, s2))
    t = t + 1
end

-- [D] hold the type and walk one byte at a time, watching for a change in the status
local types = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
local hits = 0
local ti = 1
while ti <= #types do
    local tv = types[ti]
    local b4 = 0
    local p = 1
    while p < 256 do
        local a = math.floor(tv / p) % 2
        local b = math.floor(0x6b / p) % 2
        if a ~= b then b4 = b4 + p end
        p = p * 2
    end
    local pos = 0
    while pos < 6 do
        local val = 0
        local stride = 1
        while val < 256 do
            local args = {0x11, 0x22, 0x33, 0x44, b4, 1}
            args[pos + 1] = val
            local r3, s3 = probe(args[1], args[2], args[3], args[4], args[5], args[6])
            if s3 ~= 0x800D0203 and s3 ~= 0x800D0204 and s3 ~= 0 then
                hits = hits + 1
                if hits <= 20 then
                    print(string.format("[D] type %d pos %d val 0x%X -> 0x%X", tv, pos, val, s3))
                end
            end
            val = val + 1
        end
        pos = pos + 1
    end
    ti = ti + 1
end
print(string.format("[D] unexpected statuses: %d", hits))

-- [E] the same walk with the ID byte assumed to be byte[5]
print(string.format("[E] type 0, b5 sweep start"))
local e_hits = 0
local b5 = 0
while b5 < 256 do
    local r4, s4 = probe(0x11, 0x22, 0x33, 0x44, 0xFF, b5)
    if s4 ~= 0x800D0203 and s4 ~= 0x800D0204 and s4 ~= 0 then
        e_hits = e_hits + 1
        print(string.format("[E] b5=0x%X -> 0x%X", b5, s4))
    end
    b5 = b5 + 1
end
print(string.format("[E] unexpected statuses: %d", e_hits))
print("=== 432a DONE ===")
