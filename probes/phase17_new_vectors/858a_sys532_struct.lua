-- CRASH_CLASS: HIGH
-- PROBE 858a: SYS 532 WITH A REAL INPUT STRUCT
--
-- Context: 856b/857a varied every argument of 532 but always passed arg4 as
-- 0, 1, 2, 0x1000 or 0xFFFFFFFF. 857a's status ("0x800D0202" for arg4=0,
-- "0x800D020F"/"0x800D0208"/"0x800D0210" otherwise) is the copyin-failure
-- path: the handler does
--     0xaf0509 mov rdi,[rbp-0x870]      ; arg4
--     0xaf0510 lea rsi,[rbp-0x850]      ; kernel stack buffer
--     0xaf0517 mov edx,0x18
--     0xaf051c call 0xaf1340            ; copyin wrapper, returns status
-- so arg4 is a POINTER to a 0x18-byte input record. This probe passes a mapped,
-- zeroed record and then varies its contents, so the command body actually runs.

print("=== PROBE 858a: SYS 532 WITH A REAL INPUT STRUCT ===")
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
    if type(v) == "table" then n = 0 end
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("%016X", n)
end

local sc532 = make_syscall(532)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local st = to_num(memory.alloc(0x1000))   -- status output
local rec = to_num(memory.alloc(0x1000))  -- the 0x18 input record
local out = to_num(memory.alloc(0x1000))  -- possible second buffer

local function zero(p, n)
    for i = 0, n - 1 do memory.write_dword(p + i * 4, 0) end
end
local function d(p, i)
    return to_num(memory.read_dword(p + i * 4))
end
local function call(cmd, a2, a4, a5)
    zero(st, 64)
    local ok, rv = pcall(function() return sc532(U(cmd), U(a2), U(st), U(a4), U(a5)) end)
    if not ok then return nil end
    return to_num(rv)
end

print(string.format("[0] pid=%s st=%08X rec=%08X out=%08X",
    tostring(make_syscall(20)()), st, rec, out))
print("")

-- [A] every allowed command with a zeroed record
print("[A] zeroed 0x18 record in arg4, arg2=0, arg5=0")
for cmd = 0x18, 0x21 do
    zero(rec, 8)
    local rv = call(cmd, 0, rec, 0)
    print(string.format("[A] cmd=%02X ret=%s st=%08X %08X %08X %08X",
        cmd, rv == nil and "PCALLFAIL" or hex(rv), d(st, 0), d(st, 1), d(st, 2), d(st, 3)))
end
print("")

-- [B] arg5 as a pointer, record zeroed
print("[B] arg5=out (mapped), arg2=0")
for cmd = 0x18, 0x21 do
    zero(rec, 8); zero(out, 8)
    local rv = call(cmd, 0, rec, out)
    print(string.format("[B] cmd=%02X ret=%s st=%08X %08X out=%08X %08X",
        cmd, rv == nil and "PCALLFAIL" or hex(rv), d(st, 0), d(st, 1), d(out, 0), d(out, 1)))
end
print("")

-- [C] first dword of the record as a small value, second as arg2
print("[C] record[0] sweep")
for cmd = 0x18, 0x21 do
    for _, v in ipairs({1, 2, 4, 0x100, 0x1000}) do
        zero(rec, 8)
        memory.write_dword(rec, v)
        local rv = call(cmd, 0, rec, 0)
        print(string.format("[C] cmd=%02X rec0=%04X ret=%s st=%08X %08X",
            cmd, v, rv == nil and "PCALLFAIL" or hex(rv), d(st, 0), d(st, 1)))
    end
end
print("")

-- [D] does the record survive a partially unmapped page boundary?
print("[D] record at page end - 0x10 (crosses into an unmapped page)")
for cmd = 0x18, 0x21 do
    local rv = nil
    local ok, r = pcall(function()
        -- place the 0x18 record so its last 8 bytes are past the page
        local base = rec + 0x1000 - 0x10
        return sc532(U(cmd), U(0), U(st), U(base), U(0))
    end)
    local code = "PCALLFAIL"
    if ok then code = hex(r) end
    print(string.format("[D] cmd=%02X ret=%s st=%08X", cmd, code, d(st, 0)))
end
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local s = "h858" .. tag
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 858a COMPLETE ===")
