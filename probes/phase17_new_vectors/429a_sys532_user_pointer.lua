-- CRASH_CLASS: HIGH
-- PROBE 429a: does sys 532 survive a pointer into a hole it cannot fill
--
-- The shape fuzzer died on sys 532 cmd 0x18 with the pointer one page before the buffer and
-- size 8 (case 28 of results/fuzz/shape_run1.jsonl; size 0 and 1 had survived). That is
-- either a genuine kernel fault on an unvalidated user pointer, or the "before the buffer"
-- page simply happened to be mapped and the death was cumulative.
--
-- This removes the doubt: two pages are mapped together, the second is unmapped with
-- munmap(73), so the address used is inside a hole this process itself created. Each call
-- prints before it runs, so the size that kills is the last one printed.

print("=== PROBE 429a: SYS 532 USER POINTER ===")

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

local A = call(477, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[A] mmap two pages rv=0x%X", A))
if A <= 0 then print("=== 429a DONE ===") return end
local hole = A + 0x2000
local frozen = call(73, hole, 0x2000, 0, 0, 0, 0)
print(string.format("[B] munmap hole=0x%X rv=%d", hole, frozen))

-- control: a mapped pointer at the same size
print(string.format("[C] mapped ptr, size 8: rv=%d", call(532, 0x18, 0, A, 0, 8, 0)))

local sizes = {0, 1, 2, 4, 7, 8, 9, 0x10, 0x20, 0x40, 0x100}
local i = 1
while i <= #sizes do
    local sz = sizes[i]
    print(string.format("[D] hole ptr, size 0x%X ...", sz))
    local rv = call(532, 0x18, 0, hole, 0, sz, 0)
    print(string.format("[D]   rv=%d", rv))
    i = i + 1
end

-- the same over a null page and a far address, to see whether size or address is the factor
print(string.format("[E] null ptr, size 8: rv=%d", call(532, 0x18, 0, 0, 0, 8, 0)))
print(string.format("[E] hole ptr, cmd 0x2F, size 8: rv=%d", call(532, 0x2F, 0, hole, 0, 8, 0)))
print("=== 429a DONE ===")
