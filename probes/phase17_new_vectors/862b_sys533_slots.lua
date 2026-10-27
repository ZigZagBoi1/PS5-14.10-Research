-- CRASH_CLASS: HIGH
-- PROBE 862b: 533 / 534 WITH THE CORRECT ARGUMENT SLOTS
--
-- 533 reads only arg2 and arg3 before its call:
--     0x7058ca mov r12,[r14+8]        ; arg2 = size
--     0x7058d3 test r12d,0x3fff       ; must be 0x4000-aligned
--     0x7058e0 mov r15d,[r14+0x10]    ; arg3 = flags
--     0x7058e4 test r15d,0xffffffc8   ; subset of 0x37
--     0x7058ff mov edi,1 ; xor esi,esi ; mov rdx,r12 ; xor r8d,r8d ; call
-- 862a passed (size, flags, 0) in those slots, i.e. arg2 = flags, which the
-- alignment test rejects; every call returned 0, so the gate path ran and the
-- validator never saw a real size. This probe passes arg2 = size.

print("=== PROBE 862b: 533 ARGUMENT SLOTS ===")
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
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("%016X", n)
end

local sc533 = make_syscall(533)
local sc534 = make_syscall(534)
local sc477 = make_syscall(477)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)

local function try(fn)
    local ok, rv = pcall(fn)
    if not ok then return nil end
    return to_num(rv)
end

print(string.format("[0] pid=%s", tostring(make_syscall(20)())))
print("")

print("[A] 533(arg1, size, flags) with size in arg2")
local hits = {}
for _, a1 in ipairs({0, 1, 2, 3, 4, 0x4000}) do
    for _, size in ipairs({0x4000, 0x8000, 0x10000}) do
        for _, flags in ipairs({0, 1, 2, 3, 4, 5, 7, 0x10, 0x20, 0x37}) do
            local rv = try(function() return sc533(U(a1), U(size), U(flags)) end)
            if rv == nil or rv ~= 0 then
                print(string.format("[A] a1=%06X size=%06X flags=%02X -> %s",
                    a1, size, flags, rv == nil and "PCALLFAIL" or hex(rv)))
                if rv and rv ~= 0 then hits[#hits + 1] = {a1, size, flags, rv} end
            end
        end
    end
end
print(string.format("[A] %d non-zero result(s) over 180 calls", #hits))
for _, h in ipairs(hits) do
    print(string.format("[A] hit a1=%06X size=%06X flags=%02X rv=%s",
        h[1], h[2], h[3], hex(h[4])))
end
print("")

-- misaligned and out-of-range shapes: expect EINVAL (22) if the validator runs
for _, size in ipairs({0, 1, 0x2000, 0x4001, 0x80000000}) do
    local rv = try(function() return sc533(U(0), U(size), U(0)) end)
    print(string.format("[A2] size=%08X flags=00 -> %s",
        size, rv == nil and "PCALLFAIL" or hex(rv)))
end
for _, flags in ipairs({8, 0x40, 0x100, 0xFFFFFFFF}) do
    local rv = try(function() return sc533(U(0), U(0x4000), U(flags)) end)
    print(string.format("[A2] size=004000 flags=%08X -> %s",
        flags, rv == nil and "PCALLFAIL" or hex(rv)))
end
print("")

print("[B] 534(id, flags) around the ids 533 might have produced")
for _, id in ipairs({0, 1, 2, 3, 0x10, 0x4000, 0x8000, 0x4205}) do
    for _, flags in ipairs({0, 1, 3}) do
        local rv = try(function() return sc534(U(id), U(flags)) end)
        if rv == nil or rv ~= 0 then
            print(string.format("[B] id=%06X flags=%02X -> %s",
                id, flags, rv == nil and "PCALLFAIL" or hex(rv)))
        end
    end
end
print("[B] (only non-zero results printed)")
print("")

-- try mapping the numeric results as fds with an exec request
if #hits > 0 then
    for _, h in ipairs(hits) do
        local fd = h[4]
        if fd > 2 and fd < 0x10000 then
            local m = try(function()
                return sc477(U(0), U(0x4000), U(7), U(0x1002), U(fd), U(0))
            end)
            print(string.format("[C] fd=%s mmap -> %s", tostring(fd),
                m == nil and "PCALLFAIL" or hex(m)))
        end
    end
else
    print("[C] nothing fd-shaped to map")
end
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local t = "h862b" .. tag
    for i = 1, #t do memory.write_byte(p + i - 1, string.byte(t, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 862b COMPLETE ===")
