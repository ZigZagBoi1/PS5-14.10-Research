-- CRASH_CLASS: MODERATE
-- PROBE 430a: what sys 532 cmd 0x18 leaves in the caller's buffer
--
-- 429a showed that a pointer into a munmap'd hole returns -1 and a mapped pointer returns
-- 0, so the command copies to the user buffer when the pointer is valid. The shape fuzzer
-- then died at size 8 on a pointer that turned out to be inside the loader's own heap - the
-- copy landed on top of live loader data.
--
-- So the interesting question is what it copies and how much of it. The buffer is filled
-- with a sentinel first, the call is made, and the page is dumped afterwards: a status
-- dword is expected at the start, but anything past it that was not written by us is kernel
-- data handed to a game process, and a kernel-shaped qword would be a KASLR leak.

print("=== PROBE 430a: SYS 532 COPYOUT ===")

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

local PAGE = 0x1000
local page = call(477, 0, PAGE, 7, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[A] buffer=0x%X", page))
if page <= 0 then print("=== 430a DONE ===") return end

local SENTINEL = 0xAB
local function fill()
    local k = 0
    while k < PAGE do memory.write_byte(page + k, SENTINEL); k = k + 0x10 end
    k = 0
    while k < PAGE do memory.write_byte(page + k, SENTINEL); k = k + 1 end
end

local function dump(label, n)
    local k = 0
    local line = ""
    local written = 0
    local kernish = 0
    while k < PAGE do
        local a = memory.read_byte(page + k)
        if a ~= SENTINEL then written = written + 1 end
        k = k + 1
    end
    k = 0
    while k + 16 <= n do
        line = string.format("%s %08X %08X %08X %08X", line,
            to_num(memory.read_dword(page + k)),
            to_num(memory.read_dword(page + k + 4)),
            to_num(memory.read_dword(page + k + 8)),
            to_num(memory.read_dword(page + k + 12)))
        k = k + 16
        if #line > 100 then print("  " .. line); line = "" end
    end
    if #line > 0 then print("  " .. line) end
    -- kernel-shaped qwords anywhere in the page
    k = 0
    while k + 8 <= PAGE do
        local q = memory.read_qword(page + k)
        local h = 0
        if type(q) == "table" then h = to_num(q.h) end
        if h >= 0xFFFF8000 and h <= 0xFFFFFFFF then kernish = kernish + 1 end
        k = k + 8
    end
    print(string.format("[%s] bytes written %d of %d, kernel-shaped qwords %d", label, written, PAGE, kernish))
end

local sizes = {8, 0x18, 0x20, 0x40, 0x100, 0x800}
local i = 1
while i <= #sizes do
    local sz = sizes[i]
    fill()
    local rv = call(532, 0x18, 0, page, 0, sz, 0)
    print(string.format("[B] size 0x%X rv=%d", sz, rv))
    dump(string.format("size 0x%X", sz), 0x80)
    i = i + 1
end

-- [C] the same with cmd 0x2F, which returned 0 in the full sweep
fill()
local rvf = call(532, 0x2F, 0, page, 0, 0x800, 0)
print(string.format("[C] cmd 0x2F rv=%d", rvf))
dump("cmd 0x2F", 0x80)
print("=== 430a DONE ===")
