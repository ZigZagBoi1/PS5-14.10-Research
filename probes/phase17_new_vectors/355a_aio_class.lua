-- CRASH_CLASS: MODERATE
-- PROBE 355a: does the AIO submit class select a different copy path
--
-- 669 has been exercised with class 1 only (352a-352p). The 13.60 dossier
-- lists class 1..3 and says the fd is resolved through capability-gated file
-- reference helpers, but it does not say what the class changes. Two
-- possibilities matter: a different worker, or a different copy direction.
--
-- Each case is followed by a control on class 1, because a submit that fails
-- still returns 0 and leaves the reason in the result word (352e).

print("=== PROBE 355a: AIO SUBMIT CLASS ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local H, L = 0, 0
local function U(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function hi_lo(v)
    local h = 0
    local l = to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    return h, l
end
local function rd(addr) local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end return -1 end
local function wd(addr, val) pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) pcall(function() memory.write_qword(addr, val) end) end

local sc5 = make_syscall(5)
local path = memory.alloc(0x40)
for i = 0, 0x3F, 8 do wq(path + i, 0) end
local zero_name = "/dev/zero"
for i = 1, #zero_name do pcall(function() memory.write_byte(path + i - 1, zero_name:byte(i)) end) end
local fd = sgn(sc5(U(0, to_num(path)), U(0, 0)))

local page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(page + i, 0) end

local reqs = memory.alloc(0x100)
local ids = memory.alloc(0x40)
local states = memory.alloc(0x40)
for i = 0, 0xF8, 8 do wq(reqs + i, 0) end
for i = 0, 0x38, 8 do wq(ids + i, 0); wq(states + i, 0) end

local function submit(class)
    wq(reqs + 0, U(0, 0))        -- offset
    wq(reqs + 8, U(0, 0x10))     -- byte count
    wq(reqs + 16, U(0, to_num(page)))
    wq(reqs + 24, U(0, to_num(page) + 0x100))
    wd(reqs + 32, fd)
    return sgn(make_syscall(669)(U(0, 1), U(0, to_num(reqs)), U(0, 1), U(0, class), U(0, to_num(ids))))
end
local function poll()
    local rv = sgn(make_syscall(664)(U(0, to_num(ids)), U(0, 1), U(0, to_num(states))))
    return rv, rd(states)
end
local function release()
    pcall(function() make_syscall(666)(U(0, to_num(ids)), U(0, 1), U(0, to_num(states))) end)
    pcall(function() make_syscall(662)(U(0, to_num(ids)), U(0, 1), U(0, to_num(states))) end)
end

print(string.format("fd(/dev/zero)=%d  page=0x%X", fd, to_num(page)))

for _, class in ipairs({0, 1, 2, 3, 4}) do
    local sub = submit(class)
    local p, st = poll()
    print(string.format("  class %d: submit=%d id=0x%X poll=%d state=0x%X data0=0x%X",
        class, sub, rd(ids), p, st, rd(page)))
    release()
end

print("")
print("[B] control on class 1 after every case above")
local sub = submit(1)
local p, st = poll()
print(string.format("  control: submit=%d id=0x%X poll=%d state=0x%X data0=0x%X",
    sub, rd(ids), p, st, rd(page)))
release()

print("")
print("=== 355a DONE ===")
