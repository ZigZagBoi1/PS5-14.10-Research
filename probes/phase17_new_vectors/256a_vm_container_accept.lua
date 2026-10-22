-- CRASH_CLASS: HIGH
-- PROBE 256a: 559 takes 0xFFFFFFFF and says 1
--
-- 255a called 559 with ids 0..8, 0xF and 0x100 and got -1 from all of them, but
-- 559(0xFFFFFFFF) returned 1. That is the first value in this range that is not
-- a refusal, so this probe asks what it did. Its mmap helper had prot and flags
-- swapped, so the mapping rows of 255a mean nothing and are redone here in the
-- order 158a's helper used: prot 0x33, flags 0x1002.
--
--   A  baseline: mmap, 547 on the new page - proves the helper works
--   B  559(0xFFFFFFFF), then mmap again and 547 on the page from A
--   C  0xFFFFFFFE, 0x80000000, 0xFFFFFFFF again, 0, and 0x100000000
--
-- If the accepted id moved the process into another container, the page from A
-- should stop resolving through 547, or the new mapping should land elsewhere.

print("=== PROBE 256a: what 559(0xFFFFFFFF) did ===")
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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
local function call(num, a, b, c, d, e, f)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0), e or uint64(0), f or uint64(0))
    end)
    if not ok then return nil end
    return rv
end
local function mmap(size, prot, flags)
    return call(477, uint64(0), uint64(size), uint64(prot), uint64(flags), uint64(0xFFFFFFFF), uint64(0))
end
local function query(addr)
    local b = memory.alloc(0x200)
    pcall(function() for o = 0, 0x1FC, 4 do memory.write_dword(b + o, 0) end end)
    local rv = call(547, uint64(addr), uint64(b), uint64(0x200))
    local s = ""
    for o = 0, 0x14, 4 do
        local ok, v = pcall(function() return memory.read_dword(b + o) end)
        s = s .. " " .. (ok and string.format("%08X", to_num(v)) or "??")
    end
    return rv, s
end

print("[0] pid=" .. tostring(pid()))
print("")
print("[A] baseline with prot 0x33, flags 0x1002")
local m0 = mmap(0x4000, 0x33, 0x1002)
print("    mmap(0x4000, 0x33, 0x1002) -> " .. q(m0) .. "  pid=" .. tostring(pid()))
local m0n = to_num(m0)
if m0n ~= nil and m0n > 0 and m0n < 0x100000000000 then
    pcall(function() memory.write_dword(m0n, 0x12345678) end)
    print("    wrote marker, read back -> " .. q(pcall(function() return memory.read_dword(m0n) end) and 0 or nil))
    local rv, rec = query(m0n)
    print("    547(m0) -> " .. q(rv) .. " rec:" .. rec)
else
    print("    mmap did not return a userland address")
end

print("")
print("[B] 559(0xFFFFFFFF)")
print("    559 -> " .. q(call(559, uint64(0xFFFFFFFF), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))
local m1 = mmap(0x4000, 0x33, 0x1002)
print("    mmap after switch -> " .. q(m1) .. "  pid=" .. tostring(pid()))
if m0n ~= nil and m0n > 0 and m0n < 0x100000000000 then
    local rv, rec = query(m0n)
    print("    547(m0) after switch -> " .. q(rv) .. " rec:" .. rec)
end
if to_num(m1) ~= nil and to_num(m1) > 0 and to_num(m1) < 0x100000000000 then
    local mv = to_num(m1)
    pcall(function() memory.write_dword(mv, 0xAABBCCDD) end)
    local rv, rec = query(mv)
    print("    547(m1) -> " .. q(rv) .. " rec:" .. rec)
end

print("")
print("[C] the neighbouring ids")
local ids = { 0xFFFFFFFE, 0x80000000, 0xFFFFFFFF, 0, 0x100000000, 0x7FFFFFFF }
for i = 1, #ids do
    print(string.format("    559(0x%X) -> %-22s pid=%s", ids[i], q(call(559, uint64(ids[i]), uint64(0), uint64(0))), tostring(pid())))
end

print("")
print("    mmap still works -> " .. q(mmap(0x4000, 0x33, 0x1002)) .. "  pid=" .. tostring(pid()))
print("")
print("=== PROBE 256a COMPLETE ===")
