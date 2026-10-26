-- CRASH_CLASS: HIGH
-- PROBE 577a: complete a whole block at once and see which size dies
--
-- Context: 576a created blocks of 8/16/32 pending socketpair reads with no
-- crash and states 1-2; the earlier deaths at count=16 and 64 used a device fd
-- whose reads complete instantly. So the suspect is the completion path for
-- many items of one block, not the create. Here the completions are driven
-- deliberately: write len*count bytes to the peer so the kernel completes all
-- of the block's reads, then poll.

print("=== PROBE 577a: AIO COMPLETION STORM ===")

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

local D      = to_num(memory.alloc(0x4000))
local data   = to_num(memory.alloc(0x4000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x40))
for i = 0, 0xFFF do wd(D + i * 4, 0) end
for i = 0, 0xFFF do wd(data + i * 4, 0) end

local function pair()
    local fds = to_num(memory.alloc(64))
    local rv = sgn(make_syscall(135)(U(1), U(1), U(0), U(fds), Z, Z))
    return rv, rd(fds), rd(fds + 4)
end

local function desc(at, len, buf, res, f)
    wq(at + 0x00, Z)
    wq(at + 0x08, U(len))
    wq(at + 0x10, U(buf))
    wq(at + 0x18, U(res))
    wd(at + 0x20, f)
    wd(at + 0x24, 0)
end

local function poll_all(base, n, tag)
    local st = {}
    for i = 0, n - 1 do
        local one = to_num(memory.alloc(8))
        wd(one, base + i * 0x10000)
        pcall(function() make_syscall(664)(U(one), U(1), U(states), Z, Z, Z) end)
        st[#st + 1] = rd(states)
    end
    local line = ""
    for i = 1, #st do line = line .. " " .. hx(st[i]) end
    print(string.format("[%s] states%s", tag, line))
end

local function stage(n, tag)
    local rv, f0, f1 = pair()
    print(string.format("[%s] pair rv=%d f0=%d f1=%d", tag, rv, f0, f1))
    if f0 < 3 then return end
    for i = 0, n - 1 do desc(D + i * 0x28, 16, data + i * 0x40, data + 0x2000 + i * 8, f0) end
    wd(ids, 0)
    local r = sgn(make_syscall(669)(U(1 + 0x1000), U(D), U(n), U(1), U(ids), Z))
    local base = rd(ids)
    print(string.format("[%s] create n=%d ret=%d base=%s", tag, n, r, hx(base)))
    if r ~= 0 then return end
    poll_all(base, n, tag .. "-pre")
    local w = to_num(memory.alloc(0x400))
    for i = 0, 0x100 - 1 do wd(w + i * 4, 0x41414141) end
    local wr
    for k = 0, n - 1 do
        wr = sgn(make_syscall(4)(U(f1), U(w), U(0x100), Z, Z, Z))
    end
    print(string.format("[%s] wrote peer rv=%d", tag, wr))
    poll_all(base, n, tag .. "-post")
end

stage(8, "A")
stage(16, "B")
stage(32, "C")
print(string.format("[Z] alive=%s", tostring(pcall(function() return make_syscall(20)() end))))
print("=== 577a DONE ===")
