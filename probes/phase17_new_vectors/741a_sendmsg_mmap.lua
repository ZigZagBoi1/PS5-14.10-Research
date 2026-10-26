-- CRASH_CLASS: MODERATE
-- PROBE 741a: sendmsg/recvmsg on a socketpair, everything in mmap memory
--
-- 740a: mmap pages survive the SIGSYS shield while memory.alloc does not.
-- 738a: with the shield up, plain Lua construction is safe only in mmap pages.
-- This is the sendmsg smoke test the earlier probes never got to: one iovec,
-- 16 bytes each way, then a look at every field afterwards.

print("=== PROBE 741a: SENDMSG IN MMAP MEMORY ===")
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
local sc_mmap = mk(477); local sc_pair = mk(135)
local sc_send = mk(28);  local sc_recv = mk(27); local sc_write = mk(6); local sc_read = mk(5)
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local Z = uint64(0)
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end
local function rq(a) return to_num(memory.read_qword(a)) end
local function rd(a) return to_num(memory.read_dword(a)) end
local n=0
local function say(t) n=n+1; print(string.format("[%02d] %s", n, t)) end
local function map(px)
    local ok, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v == 0 or v >= 0x8000000000000000 then return 0 end
    for k=0,(px/4)-1 do wd(v+k*4, 0) end
    return v
end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end

local fds = map(0x4000)
say("socketpair -> "..tostring(call(sc_pair, 1, 1, 0, fds, 0, 0)))
local s0 = rd(fds); local s1 = rd(fds+4)
say(string.format("fds %d %d", s0, s1))

local HDR = map(0x4000); local iov = map(0x4000); local dat = map(0x4000); local addr = map(0x4000)
say(string.format("pages %X %X %X %X", HDR, iov, dat, addr))
for k=0,3 do wd(dat+k*4, 0x41414141) end
wq(HDR+0x00, 0); wd(HDR+0x08, 0)
wq(HDR+0x10, U(iov)); wq(HDR+0x18, 1)
wq(HDR+0x20, 0);  wd(HDR+0x28, 0); wd(HDR+0x2c, 0)
wq(iov+0x00, U(dat)); wq(iov+0x08, 16)
say("msghdr built")

local act = map(0x4000); local old = map(0x4000)
wd(act, 1)
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
say("shield up, control="..tostring(call(mk(4095), 0,0,0,0,0,0)))

say("sendmsg -> "..tostring(call(sc_send, s0, HDR, 0, 0, 0, 0)))
say(string.format("after send: HDR+0=%X +8=%X +0x10=%X +0x18=%X +0x20=%X +0x28=%X +0x2c=%X",
    rq(HDR+0), rq(HDR+8), rq(HDR+0x10), rq(HDR+0x18), rq(HDR+0x20), rq(HDR+0x28), rq(HDR+0x2c)))
say(string.format("iov after: %X %X", rq(iov), rq(iov+8)))

for k=0,3 do wd(dat+k*4, 0x42424242) end
wq(HDR+0x10, U(iov)); wq(HDR+0x18, 1)
wq(iov+0x00, U(dat)); wq(iov+0x08, 16)
say("recvmsg -> "..tostring(call(sc_recv, s1, HDR, 0, 0, 0, 0)))
say(string.format("recv: dat=%X words %X %X %X %X", rq(dat), rd(dat), rd(dat+4), rd(dat+8), rd(dat+12)))
say(string.format("after recv: HDR+0=%X +8=%X +0x10=%X +0x18=%X +0x20=%X +0x28=%X +0x2c=%X",
    rq(HDR+0), rq(HDR+8), rq(HDR+0x10), rq(HDR+0x18), rq(HDR+0x20), rq(HDR+0x28), rq(HDR+0x2c)))
say("health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 741a DONE ===")
