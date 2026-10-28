-- CRASH_CLASS: HIGH
-- PROBE 857a: SYS 532 ARGUMENT MATRIX
--
-- Context: 856b showed that only commands 0x18-0x1E and 0x20 respond, that the
-- status dword is written through the THIRD argument, and that the status
-- depends only on the fourth argument: arg4 == 0 gives 0x800D0202, arg4 == 1/2
-- gives 0x800D020F (0x18-0x1E) or 0x800D0208 (0x20). arg2 had no effect over
-- {0,1,2,4,0x100,0x1000}.
--
-- This probe widens arg4, varies arg5 and arg2 (value vs mapped pointer), and
-- tests a NULL status pointer, to find whether any shape gets past the
-- argument validation.

print("=== PROBE 857a: SYS 532 ARGUMENT MATRIX ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X",
        math.floor(a / 4294967296), a % 4294967296))
end
local function hex(v)
    local n = to_num(v)
    if type(v) == "table" then n = to_num(v) end
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("%016X", n)
end

local sc532 = make_syscall(532)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local p1 = to_num(memory.alloc(0x1000))
local p2 = to_num(memory.alloc(0x1000))

local function zero(p, n)
    for i = 0, n - 1 do memory.write_dword(p + i * 4, 0) end
end
-- returns ret, status dwords
local function call(cmd, a2, a3, a4, a5)
    zero(p1, 16)
    local ok, rv = pcall(function() return sc532(U(cmd), U(a2), U(a3), U(a4), U(a5)) end)
    if not ok then return nil end
    return to_num(rv), to_num(memory.read_dword(p1)), to_num(memory.read_dword(p1 + 4))
end

print(string.format("[0] pid=%s p1=%08X", tostring(make_syscall(20)()), p1))
print("")

local A4 = {0, 1, 2, 3, 4, 8, 0x10, 0x40, 0x100, 0x1000, 0x7FFFFFFF, 0xFFFFFFFF}
local CMDS = {0x18, 0x1F, 0x20, 0x2F}

for _, cmd in ipairs(CMDS) do
    print(string.format("[A] cmd=%02X  (arg2=0, arg3=page, arg5=0)", cmd))
    for _, a4 in ipairs(A4) do
        local rv, s0, s1 = call(cmd, 0, p1, a4, 0)
        print(string.format("   a4=%08X ret=%s st=%08X %08X",
            a4, rv == nil and "PCALLFAIL" or hex(rv), s0, s1))
    end
end
print("")

print("[B] arg2 as pointer (arg4=1, arg3=page, arg5=0)")
for _, cmd in ipairs(CMDS) do
    local rv, s0 = call(cmd, p2, p1, 1, 0)
    print(string.format("   cmd=%02X a2=page ret=%s st=%08X", cmd,
        rv == nil and "PCALLFAIL" or hex(rv), s0))
end
print("")

print("[C] arg5 sweep (arg4=1, arg3=page, arg2=0)")
for _, cmd in ipairs(CMDS) do
    for _, a5 in ipairs({1, 2, 0x100, 0x1000}) do
        local rv, s0 = call(cmd, 0, p1, 1, a5)
        print(string.format("   cmd=%02X a5=%08X ret=%s st=%08X", cmd, a5,
            rv == nil and "PCALLFAIL" or hex(rv), s0))
    end
end
print("")

print("[D] NULL status pointer (arg3=0)")
for _, cmd in ipairs(CMDS) do
    for _, a4 in ipairs({0, 1}) do
        local ok, rv = pcall(function() return sc532(U(cmd), U(0), U(0), U(a4), U(0)) end)
        print(string.format("   cmd=%02X a4=%d ret=%s", cmd, a4,
            (not ok) and "PCALLFAIL" or hex(rv)))
    end
end
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local s = "h857" .. tag
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 857a COMPLETE ===")
