-- CRASH_CLASS: MODERATE
-- PROBE 732a: is a pending aio read a real kernel job?
--
-- Context: 731a created a block of two reads on an empty socketpair and both
-- items polled 00000002, not 00000001. If the read is really submitted, writing
-- to the peer must move the item to 3 and put the bytes in the caller buffer.
-- That would make aio a live subsystem on 14.10 rather than the bookkeeping
-- surface the 13.60 gate at 0x8b4c78d0 suggested.

print("=== PROBE 732a: AIO REAL READ ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end

local sp = mk(135)
local fds = to_num(memory.alloc(64))
local rv = pcall(function() return sp(U(1),U(1),U(0),U(fds),Z,Z) end)
local fdA, fdB = rd(fds), rd(fds+4)
print(string.format("[A] socketpair fd=%d,%d", fdA, fdB))

local D    = to_num(memory.alloc(0x4000))
local buf  = to_num(memory.alloc(0x4000))
local res  = to_num(memory.alloc(0x4000))
local ids  = to_num(memory.alloc(0x400))
local st   = to_num(memory.alloc(0x400))
for k=0,0xFFF do wd(buf+k*4,0); wd(res+k*4,0) end
local function desc(at)
    wq(at+0x00, Z);              wq(at+0x08, U(16))
    wq(at+0x10, U(buf));         wq(at+0x18, U(res))
    wd(at+0x20, fdA);            wd(at+0x24, 0)
end
desc(D); desc(D+0x28)
wd(ids, 0)
local ok, r = pcall(function() return mk(669)(U(1+0x1000), U(D), U(2), U(1), U(ids), Z) end)
local base = rd(ids)
print(string.format("[A] create ret=%s base=%08X", tostring(to_num(r)), base))

local function pollall(tag)
    wd(ids, base); wd(ids+4, base+0x10000)
    pcall(function() return mk(664)(U(ids), U(2), U(st), Z, Z, Z) end)
    print(string.format("[%s] poll id0=%08X id1=%08X", tag, rd(st), rd(st+4)))
    return rd(st), rd(st+4)
end
pollall("B")

-- write to the peer end
local msg = to_num(memory.alloc(32))
for k=0,3 do wd(msg+k*4, 0x44434241 + k*0x04040404) end
local wok, wr = pcall(function() return mk(3)(U(fdB), U(msg), U(16), Z, Z, Z) end)
print(string.format("[C] write(peer,16) ok=%s ret=%s", tostring(wok), tostring(to_num(wr))))
sleep_ms(30)
pollall("C")

print(string.format("[D] buf[0..15]=%08X %08X %08X %08X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
print(string.format("[D] res[0]=%08X res[1]=%08X", rd(res), rd(res+0x20)))

-- cancel path on a fresh pending create
local D2 = to_num(memory.alloc(0x4000))
desc(D2); desc(D2+0x28)
local ok2, r2 = pcall(function() return mk(669)(U(1), U(D2), U(2), U(1), U(ids), Z) end)
local base2 = rd(ids)
print(string.format("[E] create2 ret=%s base=%08X", tostring(to_num(r2)), base2))
wd(ids, base2)
pcall(function() return mk(664)(U(ids), U(1), U(st), Z, Z, Z) end)
print(string.format("[E] poll2 id0=%08X", rd(st)))
wd(ids, base2)
local okc, rc = pcall(function() return mk(666)(U(ids), U(1), U(st), Z, Z, Z) end)
print(string.format("[E] cancel ret=%s out=%08X", tostring(to_num(rc)), rd(st)))
pcall(function() return mk(664)(U(ids), U(1), U(st), Z, Z, Z) end)
print(string.format("[E] poll2 after cancel=%08X", rd(st)))
wd(ids, base2)
local okd, rd2 = pcall(function() return mk(662)(U(ids), U(1), U(st), Z, Z, Z) end)
print(string.format("[E] delete after cancel ret=%s status=%08X", tostring(to_num(rd2)), rd(st)))

print(string.format("[F] health=%d alive", to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== 732a DONE ===")
