-- CRASH_CLASS: LOW
-- PROBE 423a: every protection value mprotect will accept
--
-- W^X has been recorded as absolute since the beginning: mprotect(EXEC) returns -1. But
-- every measurement used the handful of protection constants a person would try (5, 7,
-- 4). The PS5 mmap/mprotect protection field is not the FreeBSD one - the GPU mapping is
-- requested with 0x33 - so the space of values the kernel will accept has never been
-- walked. 65536 calls at ~5k/s is twelve seconds.
--
-- A return of 0 means the mapping was reprotected; the follow-up is a child that starts at
-- that mapping and writes a marker, which proves execution rather than trusting the return.

print("=== PROBE 423a: MPROTECT PROT SWEEP ===")

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
local function u64(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

-- [A] an ordinary anonymous mapping
local A = call(477, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[A] mmap rv=0x%X", A))
if A <= 0 then print("=== 423a DONE ===") return end

-- [B] the GPU-shaped mapping used by every heap probe
local G = call(477, 0, 0x4000, 0x33, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[B] gpu mmap rv=0x%X", G))

-- [C] walk every protection value on the ordinary mapping
local hits = 0
local first = {}
local prot = 0
while prot < 0x10000 do
    local rv = call(74, A, 0x4000, prot)
    if rv == 0 then
        hits = hits + 1
        if hits <= 16 then first[#first + 1] = prot end
    end
    prot = prot + 1
end
print(string.format("[C] ordinary mapping: %d accepted of 65536", hits))
if #first > 0 then
    local s = ""
    local i = 1
    while i <= #first do s = s .. string.format("0x%X ", first[i]); i = i + 1 end
    print("[C] first accepted: " .. s)
end

-- [D] the same on the GPU mapping, and on a kernel-chosen length
if G > 0 then
    local ghits = 0
    local gfirst = {}
    prot = 0
    while prot < 0x10000 do
        local rv = call(74, G, 0x4000, prot)
        if rv == 0 then
            ghits = ghits + 1
            if ghits <= 16 then gfirst[#gfirst + 1] = prot end
        end
        prot = prot + 1
    end
    print(string.format("[D] gpu mapping: %d accepted of 65536", ghits))
    if #gfirst > 0 then
        local s = ""
        local i = 1
        while i <= #gfirst do s = s .. string.format("0x%X ", gfirst[i]); i = i + 1 end
        print("[D] first accepted: " .. s)
    end
end

-- [E] line up the values the loader itself uses, for the record
print(string.format("[E] mprotect(A, 0x4000, 3) rv=%d", call(74, A, 0x4000, 3)))
print(string.format("[E] mprotect(A, 0, 7) rv=%d", call(74, A, 0, 7)))
print(string.format("[E] mprotect(A, 0x4000, 0x33) rv=%d", call(74, A, 0x4000, 0x33)))
print("=== 423a DONE ===")
