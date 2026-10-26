-- CRASH_CLASS: HIGH
-- PROBE 574a: where in a 64-item poll does it die
--
-- Context: 570a died inside its n=16 case while n=2 and n=4 printed clean, and a
-- count=100 block create had worked minutes earlier in 568a. This probe separates
-- create from poll and walks the size upward with a print after every step.

print("=== PROBE 574a: AIO 64-ITEM POLL BISECT ===")

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
local ids = page(0x40)
local one = page(0x40)
local states = page(0x40)
local RES = page(0x40)
local D = reqs + 0x100

local path = page(0x20)
wd(path, 0x7665642F) wd(path + 4, 0x6172752F) wd(path + 8, 0x6D6F646E) wd(path + 0xC, 0)
local fd = sgn(sc(5)(U(path), Z, Z, Z, Z, Z))
print(string.format("[0] fd=%d", fd))
if fd < 3 then print("=== 571a ABORT: no fd ===") return end

local function desc(at, len, buf, res)
    wq(at + 0x00, U(0)) wq(at + 0x08, U(len))
    wq(at + 0x10, U(buf)) wq(at + 0x18, U(res))
    wq(at + 0x20, U(fd)) wq(at + 0x28, U(0))
end

local function create(n)
    for i = 0, n - 1 do desc(D + i * 0x28, 0x10, data + (i % 8) * 0x40, RES + (i % 8) * 8) end
    wd(ids, 0)
    return sgn(sc(669)(U(1 + 0x1000), U(D), U(n), U(1), U(ids), Z)), rd(ids)
end

local function poll_all(base, n, tag)
    local ok, bad = 0, 0
    for i = 0, n - 1 do
        wd(one, base + i * 0x10000)
        pcall(function() sc(664)(U(one), U(1), U(states), Z, Z, Z) end)
        local st = rd(states)
        if st == 3 or st == 0x10003 then ok = ok + 1 else bad = bad + 1 end
    end
    print(string.format("[%s] poll ok=%d other=%d", tag, ok, bad))
end

local r, base = create(64)
print(string.format("[A] create n=64 ret=%d base=%s", r, hx(base)))
if r == 0 then
    for block = 0, 7 do
        local ok, bad, last = 0, 0, 0
        for i = block * 8, block * 8 + 7 do
            wd(one, base + i * 0x10000)
            pcall(function() sc(664)(U(one), U(1), U(states), Z, Z, Z) end)
            local st = rd(states)
            last = st
            if st == 3 or st == 0x10003 then ok = ok + 1 else bad = bad + 1 end
        end
        print(string.format("[B] ids %d-%d ok=%d other=%d last=%s", block * 8, block * 8 + 7, ok, bad, hx(last)))
    end
end
print(string.format("[E] alive=%s", tostring(pcall(function() return sc(20)() end))))
print("=== 574a DONE ===")
