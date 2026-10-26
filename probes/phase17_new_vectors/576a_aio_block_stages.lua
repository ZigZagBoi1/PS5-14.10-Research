-- CRASH_CLASS: HIGH
-- PROBE 576a: where does a multi-item block create die?
--
-- Context: single-item creates are stable at 100 objects (568a), but block
-- creates (flags 1+0x1000) have killed the process at count=16 (570a) and at
-- count=64 (571a/574a). This probe walks sizes upward and separates create from
-- poll, printing a marker after every step so the last line on the wire names
-- the step that killed it.

print("=== PROBE 576a: AIO BLOCK STAGES ===")

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
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local sc = make_syscall
local D     = to_num(memory.alloc(0x4000))
local data  = to_num(memory.alloc(0x4000))
local ids   = to_num(memory.alloc(0x400))
local states= to_num(memory.alloc(0x40))
for i = 0, 0xFFF do wd(D + i * 4, 0) end
for i = 0, 0xFFF do wd(data + i * 4, 0) end

local sp = make_syscall(135)
local fds = to_num(memory.alloc(64))
local rv = sgn(sp(U(1), U(1), U(0), U(fds), Z, Z))
local fd = rd(fds)
print(string.format("[0] socketpair rv=%d fd=%d", rv, fd))

local function desc(at, len, buf, res, f)
    wq(at + 0x00, Z)
    wq(at + 0x08, U(len))
    wq(at + 0x10, U(buf))
    wq(at + 0x18, U(res))
    wd(at + 0x20, f)
    wd(at + 0x24, 0)
end

local function create(n, tag)
    local dpage = D
    for i = 0, n - 1 do desc(dpage + i * 0x28, 16, data + i * 0x40, data + 0x2000 + i * 8, fd) end
    wd(ids, 0)
    local r = sgn(make_syscall(669)(U(1 + 0x1000), U(dpage), U(n), U(1), U(ids), Z))
    local base = rd(ids)
    print(string.format("[%s] block create n=%d ret=%d base=%s", tag, n, r, hx(base)))
    return r, base
end

local function poll_one(id, tag)
    local one = to_num(memory.alloc(8))
    wd(one, id)
    pcall(function() make_syscall(664)(U(one), U(1), U(states), Z, Z, Z) end)
    print(string.format("[%s] poll %s -> %s", tag, hx(id), hx(rd(states))))
end

local function poll_all(base, n, tag)
    local ok, bad = 0, 0
    for i = 0, n - 1 do
        local one = to_num(memory.alloc(8))
        wd(one, base + i * 0x10000)
        pcall(function() make_syscall(664)(U(one), U(1), U(states), Z, Z, Z) end)
        local st = rd(states)
        if st == 3 or st == 0x10003 then ok = ok + 1 else bad = bad + 1 end
    end
    print(string.format("[%s] poll all n=%d ok=%d other=%d", tag, n, ok, bad))
end

local r8, b8 = create(8, "1")
if r8 == 0 then
    poll_one(b8, "2")
    poll_all(b8, 8, "3")
end

local r16, b16 = create(16, "4")
if r16 == 0 then
    poll_one(b16, "5")
end

local r32, b32 = create(32, "6")
if r32 == 0 then
    poll_one(b32, "7")
    poll_all(b32, 32, "8")
end

print(string.format("[9] alive=%s", tostring(pcall(function() return make_syscall(20)() end))))
print("=== 576a DONE ===")
