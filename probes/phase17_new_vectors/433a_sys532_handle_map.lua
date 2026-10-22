-- CRASH_CLASS: LOW
-- PROBE 433a: map the sys 532 handle decode by status
--
-- 432a reached the real check with the argument slots 308a used, `532(cmd, 0, out, inp,
-- size, 0)`, and the checksum formula the dossier gives is byte[3] + byte[0] + byte[1] +
-- byte[2] + byte[5]*byte[4] (the bextr(0x810) term is byte[2], not byte[1] as an earlier
-- reading had it). With the checksum right, walking byte[5] on type 0 returned 0x800D0205
-- (decryption variant mismatch) for a run of values instead of 0x800D0203 (not found).
--
-- So the handle really is decoded. This prints a compact map: for every type and every byte
-- position, how many of the 256 values land on each status. A 0x800D0206 (decoded value
-- invalid) or anything else means the decode produced a candidate.

print("=== PROBE 433a: SYS 532 HANDLE MAP ===")

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

local out = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
local inp = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[A] out=0x%X inp=0x%X", out, inp))
if out <= 0 or inp <= 0 then print("=== 433a DONE ===") return end

local function probe(bytes, b4, size)
    local sum = (bytes[4] + bytes[1] + bytes[2] + bytes[3] + bytes[6] * b4) % 0x10000
    local i = 1
    while i <= 6 do memory.write_byte(inp + i - 1, bytes[i]); i = i + 1 end
    memory.write_byte(inp + 6, sum % 0x100)
    memory.write_byte(inp + 7, math.floor(sum / 0x100))
    memory.write_dword(out, 0x41414141)
    call(532, 0x18, 0, out, inp, size, 0)
    return to_num(memory.read_dword(out))
end

local function bxor(a, b)
    local r, bit = 0, 1
    while bit < 256 do
        local x, y = a % 2, b % 2
        if x ~= y then r = r + bit end
        a, b, bit = (a - x) / 2, (b - y) / 2, bit * 2
    end
    return r
end

local function status_name(s)
    if s == 0x800D0203 then return "notfound" end
    if s == 0x800D0204 then return "checksum" end
    if s == 0x800D0205 then return "variant" end
    if s == 0x800D0206 then return "invaldec" end
    if s == 0x800D0202 then return "missing" end
    if s == 0x800D020D then return "errorstate" end
    if s == 0x800D0216 then return "perm" end
    if s == 0 then return "ok" end
    return string.format("0x%X", s)
end

local t = 0
while t <= 0x0C do
    local b4 = bxor(t, 0x6b)
    local summary = {}
    local pos = 0
    while pos < 6 do
        if pos ~= 4 then
        local vals = 0
        local counts = {}
        while vals < 256 do
            -- byte[4] is the type byte and must carry b4; an earlier revision left it zero,
            -- so every case mismatched the checksum and the map was all 0x800D0204
            local bytes = {0, 0, 0, 0, b4, 1}
            bytes[pos + 1] = vals
            local s = probe(bytes, b4, 0x40)
            local n = status_name(s)
            counts[n] = (counts[n] or 0) + 1
            vals = vals + 1
        end
        local parts = "pos " .. pos .. ":"
        for n, c in pairs(counts) do parts = parts .. string.format(" %s=%d", n, c) end
        summary[#summary + 1] = parts
        end
        pos = pos + 1
    end
    print(string.format("[B] type %2d (b4=0x%02X)", t, b4))
    local i = 1
    while i <= #summary do print("      " .. summary[i]); i = i + 1 end
    t = t + 1
end
print("=== 433a DONE ===")
