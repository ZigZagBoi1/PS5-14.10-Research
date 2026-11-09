-- CRASH_CLASS: LOW
-- PROBE 570a: is the "second delete returns 0" behaviour a large-block effect?
--
-- Context: 569a showed a 4-item block object answers a serial second delete of
-- item0 with 0x80020003, while 568a's 100-item block answered 0 for every id in
-- both racing helpers. A single caller repeating one id is the cheapest way to
-- tell whether the slot lingers only for large entries.

print("=== PROBE 570a: AIO BLOCK SIZE vs SECOND DELETE ===")

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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local function page(n)
    local p = to_num(memory.alloc(n))
    for i = 0, n / 4 - 1 do wd(p + i * 4, 0) end
    return p
end

local reqs = page(0x4000)
local data = page(0x400)
local status = page(0x400)
local ids = page(0x40)
local one = page(0x40)
local states = page(0x40)
local RES = page(0x40)
local D = reqs + 0x100

local path = page(0x20)
wd(path, 0x7665642F) wd(path + 4, 0x6172752F) wd(path + 8, 0x6D6F646E) wd(path + 0xC, 0)
local fd = sgn(sc(5)(U(path), Z, Z, Z, Z, Z))
print(string.format("[0] fd=%d reqs=%08X", fd, reqs))
if fd < 3 then print("=== 570a ABORT: no fd ===") return end

local function desc(at, len, buf, res)
    wq(at + 0x00, U(0)) wq(at + 0x08, U(len))
    wq(at + 0x10, U(buf)) wq(at + 0x18, U(res))
    wq(at + 0x20, U(fd)) wq(at + 0x28, U(0))
end

local function del(id)
    wd(one, id)
    wd(status, 0xA5A5A5A5)
    local r = sgn(sc(662)(U(one), U(1), U(status), Z, Z, Z))
    return r, rd(status)
end

local function trial(n, label)
    for i = 0, n - 1 do desc(D + i * 0x28, 0x10, data + (i % 16) * 0x40, RES + (i % 16) * 8) end
    local r = sgn(sc(669)(U(1 + 0x1000), U(D), U(n), U(1), U(ids), Z))
    local base = rd(ids)
    if r ~= 0 or base == 0 then
        print(string.format("[%s] create ret=%d base=%s", label, r, hx(base)))
        return
    end
    for i = 0, n - 1 do
        wd(one, base + i * 0x10000)
        pcall(function() sc(664)(U(one), U(1), U(states), Z, Z, Z) end)
    end
    local a1, s1 = del(base)
    local a2, s2 = del(base)
    local b1, t1 = del(base + 0x10000)
    local b2, t2 = del(base + 0x10000)
    print(string.format("[%s] n=%d base=%s | item0: %s %s then %s %s | item1: %s %s then %s %s",
        label, n, hx(base), a1, hx(s1), a2, hx(s2), b1, hx(t1), b2, hx(t2)))
end

trial(2, "A")
trial(4, "B")
trial(16, "C")
trial(100, "D")
trial(1, "E")

print(string.format("[F] alive=%s", tostring(pcall(function() return sc(20)() end))))
print("=== 570a DONE ===")
