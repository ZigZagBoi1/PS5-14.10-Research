-- CRASH_CLASS: HIGH
-- PROBE 861a: SYS 532 SIDE EFFECTS AND THE 2F COMMAND
--
-- Context: 860a proved arg5 is a size (0x30 or 0x818 are the two the first
-- layer accepts) and that the ungated commands answer 0203/0204/0208 without
-- writing the caller buffer. Command 0x1E accepts any size <= 0x800 and returns
-- 0; command 0x20 with size 0x30 returns 0x800D0219; command 0x2F answered
-- 0x800D0210 with a small arg5 in 857a.
--
-- Questions here: (1) is any of these commands stateful (does calling 0x1E
-- change what 0x18-0x1D answer)? (2) does 0x1E's status dword behave like a
-- counter or an id source? (3) what does 0x2F want?

print("=== PROBE 861a: SYS 532 SIDE EFFECTS ===")
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

local function call(cmd, rec0, size, ptr)
    memory.write_dword(st, 0)
    memory.write_dword(buf, rec0)
    local ok, rv = pcall(function()
        return sc532(U(cmd), U(0), U(st), U(ptr or buf), U(size))
    end)
    if not ok then return nil end
    return d(st, 0)
end

print(string.format("[0] pid=%s st=%08X buf=%08X", tostring(make_syscall(20)()), st, buf))
print("")

print("[A] cmd 2F size sweep with a mapped buffer")
for _, size in ipairs({0, 0x10, 0x30, 0x100, 0x800, 0x818, 0x2000}) do
    zero(buf, 8)
    local s = call(0x2F, 0, size)
    print(string.format("[A] size=%04X -> %s buf=%08X",
        size, s == nil and "PCALLFAIL" or string.format("%08X", s), d(buf, 0)))
end
print("")

print("[B] cmd 1E repeated: is the status a counter?")
local seq = {}
for i = 1, 12 do
    local s = call(0x1E, 1, 0x30)
    seq[#seq + 1] = s == nil and "XXXX" or string.format("%08X", s)
end
print("[B] rec0=1 " .. table.concat(seq, " "))
seq = {}
for i = 1, 12 do
    local s = call(0x1E, 0, 0x30)
    seq[#seq + 1] = s == nil and "XXXX" or string.format("%08X", s)
end
print("[B] rec0=0 " .. table.concat(seq, " "))
print("")

print("[C] does calling 1E unlock 18-1D?")
for _, rec0 in ipairs({0, 1}) do
    local before = call(0x18, rec0, 0x818)
    for i = 1, 50 do call(0x1E, 0, 0x30) end
    local after = call(0x18, rec0, 0x818)
    print(string.format("[C] rec0=%d before=%s after=%s",
        rec0,
        before == nil and "PCALLFAIL" or string.format("%08X", before),
        after == nil and "PCALLFAIL" or string.format("%08X", after)))
end
print("")

print("[D] cmd 20 size 0x30 with a pattern")
zero(buf, 0x30 / 4)
for i = 0, 11 do memory.write_dword(buf + i * 4, 0xC0DE0000 + i) end
local s = call(0x20, 0, 0x30)
print(string.format("[D] st=%s buf=%08X %08X %08X",
    s == nil and "PCALLFAIL" or string.format("%08X", s),
    d(buf, 0), d(buf, 1), d(buf, 2)))
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local t = "h861" .. tag
    for i = 1, #t do memory.write_byte(p + i - 1, string.byte(t, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 861a COMPLETE ===")
