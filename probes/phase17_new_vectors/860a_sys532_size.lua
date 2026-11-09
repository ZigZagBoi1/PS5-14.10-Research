-- CRASH_CLASS: HIGH
-- PROBE 860a: SYS 532 SIZE-GATED QUERY
--
-- Context: 859a's failures were all 0x800D0208, and the disassembly explains
-- why.  After the arg4 copyin the handler compares the FIFTH argument (uap+0x20)
-- against a fixed buffer size:
--     0xaf0345 lea rdi,[rbp-0x850] ; mov esi,0x818 ; call 0x258ff0   (bzero)
--     0xaf0382 cmp r14d,0x20
--     0xaf0396 cmp rdx,0x30   / je 0xaf03e9      ; cmd 0x20 wants 0x30
--     0xaf03d2 cmp rdx,0x818  / jne 0xaf039c     ; everything else 0x818
--     0xaf03e9 mov rdi,[rbp-0x870] (arg4) ; lea rsi,[rbp-0x850] ; call 0xaf1340
-- so arg5 is a SIZE, not a pointer, and it must be exactly 0x818 or 0x30.
--
-- This probe passes a mapped 0x818-byte buffer as arg4 and the matching size as
-- arg5, then dumps whatever comes back.

print("=== PROBE 860a: SYS 532 SIZE-GATED QUERY ===")
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
local function d(p, i) return to_num(memory.read_dword(p + i * 4)) end

local sc532 = make_syscall(532)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local st = to_num(memory.alloc(0x1000))
local buf = to_num(memory.alloc(0x2000))

local function zero(p, n)
    for i = 0, n - 1 do memory.write_dword(p + i * 4, 0) end
end

local function run(cmd, size, fill)
    zero(st, 32)
    zero(buf, 0x818 / 4)
    if fill then
        for i = 0, (size / 4) - 1 do memory.write_dword(buf + i * 4, 0x11110000 + i) end
    end
    local ok, rv = pcall(function()
        return sc532(U(cmd), U(0), U(st), U(buf), U(size))
    end)
    local code = "PCALLFAIL"
    if ok then code = hex(rv) end
    return code
end

print(string.format("[0] pid=%s st=%08X buf=%08X", tostring(make_syscall(20)()), st, buf))
print("")

print("[A] size 0x818, zeroed buffer")
for cmd = 0x18, 0x21 do
    local code = run(cmd, 0x818, false)
    print(string.format("[A] cmd=%02X ret=%s st=%08X buf=%08X %08X %08X %08X",
        cmd, code, d(st, 0), d(buf, 0), d(buf, 1), d(buf, 2), d(buf, 3)))
end
print("")

print("[B] size 0x30, zeroed buffer")
for cmd = 0x18, 0x21 do
    local code = run(cmd, 0x30, false)
    print(string.format("[B] cmd=%02X ret=%s st=%08X buf=%08X %08X",
        cmd, code, d(st, 0), d(buf, 0), d(buf, 1)))
end
print("")

print("[C] size 0x818, buffer prefilled with a pattern")
for cmd = 0x18, 0x20 do
    local code = run(cmd, 0x818, true)
    print(string.format("[C] cmd=%02X ret=%s st=%08X buf=%08X %08X %08X %08X %08X",
        cmd, code, d(st, 0), d(buf, 0), d(buf, 1), d(buf, 2), d(buf, 3), d(buf, 4)))
end
print("")

print("[D] size sweep on cmd 0x1E (the one that answered a value)")
for _, size in ipairs({0x30, 0x40, 0x100, 0x400, 0x800, 0x818, 0x820}) do
    local code = run(0x1E, size, false)
    print(string.format("[D] size=%04X ret=%s st=%08X buf=%08X",
        size, code, d(st, 0), d(buf, 0)))
end
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local s = "h860" .. tag
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 860a COMPLETE ===")
