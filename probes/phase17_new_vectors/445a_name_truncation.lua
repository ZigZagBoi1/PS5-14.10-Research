-- CRASH_CLASS: LOW
-- PROBE 445a: does a registered name collide when it is longer than the field?
--
-- 442a/444a established the evf lifetime: 538(name, 0x100) registers the object in a
-- process-scoped registry, 540(name) opens it and returns a second handle, 539 deletes it
-- from the creator's handle, 541 closes a handle. 442a also showed the registry survives
-- every handle being closed.
--
-- Every dossier bounds the name copy at 0x20. If the registry key is the truncated copy,
-- two names that differ only after byte 0x20 land on the same key, and a lookup can hand
-- back an object of another family. This measures whether that happens.

print("=== PROBE 445a: NAME TRUNCATION ===")
print("")

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
local function fmt(v)
    if v == nil then return "nil" end
    if v == -999 then return "EXC" end
    if v == -1 then return "-1" end
    return string.format("0x%X", v)
end

local namebuf = call(477, 0, 0x200, 3, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[A] name buffer = 0x%X", namebuf))
if namebuf <= 0 then print("=== 445a DONE ===") return end

local function put(off, s)
    local i = 1
    while i <= #s do memory.write_byte(namebuf + off + i - 1, string.byte(s, i)); i = i + 1 end
    memory.write_byte(namebuf + off + #s, 0)
    return namebuf + off
end

-- registry-scoped names: identical through byte 0x20, different after it
local p1 = put(0x000, string.rep("A", 0x20) .. "ONE")
local p2 = put(0x080, string.rep("A", 0x20) .. "TWO")
print("[B] two names differing only after 0x20 bytes")
local h1 = call(538, p1, 0x100, 0, 0, 0, 0)
print("    create(N1) = " .. fmt(h1))
local h2 = call(538, p2, 0x100, 0, 0, 0, 0)
print("    create(N2) = " .. fmt(h2))
local o1 = call(540, p1, 0, 0, 0, 0, 0)
local o2 = call(540, p2, 0, 0, 0, 0, 0)
print("    open(N1) = " .. fmt(o1) .. "   open(N2) = " .. fmt(o2))
print("    same handle = " .. tostring(o1 == o2 and o1 > 0))

print("")
print("[C] a 0x40-byte name (longer than the 0x20 bound)")
local p3 = put(0x100, string.rep("B", 0x40))
local h3 = call(538, p3, 0x100, 0, 0, 0, 0)
print("    create(64 chars) = " .. fmt(h3))

print("")
print("[D] one name registered as two families")
local p4 = put(0x180, "omp445a_shared")
local he = call(538, p4, 0x100, 0, 0, 0, 0)
local ho = call(549, p4, 0x100, 0, 1, 0, 0)
print("    evf create = " .. fmt(he) .. "   osem create = " .. fmt(ho))
local oe = call(540, p4, 0, 0, 0, 0, 0)
local oo = call(551, p4, 0, 0, 0, 0, 0)
print("    evf open = " .. fmt(oe) .. "   osem open = " .. fmt(oo))
print("    same handle = " .. tostring(oe == oo and oe > 0))
print("=== 445a DONE ===")
