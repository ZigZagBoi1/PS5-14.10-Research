-- CRASH_CLASS: MODERATE
-- PROBE 742a: does the socket layer write a kernel pointer into user memory?
--
-- A static read of the 13.60 capture named the getsockaddr helper behind
-- sendto/sendmsg (malloc(namelen) -> copyin -> free on error) as a possible
-- source of a dangling kernel pointer handed back to userland. The read is
-- probably a misread of an internal out-param, so this measures it:
--   A. socket(97) + sendto with a real sockaddr_in, read the page back
--   B. sendmsg with msg_name set, read the msghdr and the page back
--   C. msg_control/msg_controllen matrix, read the control block back
-- Everything lives in mmap pages (740a) and the shield is up (741a).

print("=== PROBE 742a: SOCKADDR AND CONTROL ===")
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
local sc_mmap = mk(477)
local sc_socket = mk(97); local sc_sendto = mk(133); local sc_sendmsg = mk(28)
local sc_pair = mk(135); local sc_close = mk(6)
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local Z = uint64(0)
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end
local function wb(a,v) memory.write_byte(a,v) end
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
-- kernel-shaped = high half in 0xFFFF8000..0xFFFFFFFF
local function kern(v) local h = math.floor(v/4294967296); return h >= 0xFFFF8000 and h <= 0xFFFFFFFF end
local function scan(tag, base, px)
    local hits, first = 0, 0
    for k=0,(px/8)-1 do
        local v = rq(base+k*8)
        if kern(v) then hits = hits + 1; if first == 0 then first = v end end
    end
    if hits > 0 then say(string.format("%s KERNEL-SHAPED hits=%d first=%X", tag, hits, first))
    else say(tag.." no kernel-shaped qword") end
end

local fds = map(0x4000); local dat = map(0x4000)
local SA = map(0x4000); local CTL = map(0x4000); local HDR = map(0x4000); local iov = map(0x4000)
say("pages ready")
for k=0,3 do wd(dat+k*4, 0x41414141) end
-- sockaddr_in: len 16, family AF_INET 2, port 0x1234, addr 127.0.0.1
wb(SA+0x00, 16); wb(SA+0x01, 2); wb(SA+0x02, 0x34); wb(SA+0x03, 0x12)
wb(SA+0x04, 0x7F); wb(SA+0x05, 0); wb(SA+0x06, 0); wb(SA+0x07, 1)
say(string.format("sockaddr built: %X %X %X %X", rd(SA), rd(SA+4), rd(SA+8), rd(SA+12)))

local act = map(0x4000); local old = map(0x4000)
wd(act, 1)
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
say("shield up, control="..tostring(call(mk(4095),0,0,0,0,0,0)))

local fd = call(sc_socket, 2, 2, 0, 0, 0, 0)
say("socket(AF_INET,SOCK_DGRAM) -> "..tostring(fd))
say("sendto -> "..tostring(call(sc_sendto, fd, dat, 16, 0, SA, 16)))
say(string.format("sockaddr after sendto: %X %X %X %X", rd(SA), rd(SA+4), rd(SA+8), rd(SA+12)))
scan("sockaddr page", SA, 0x4000)

wq(HDR+0x00, U(SA)); wd(HDR+0x08, 16)
wq(HDR+0x10, U(iov)); wq(HDR+0x18, 1)
wq(HDR+0x20, 0); wd(HDR+0x28, 0); wd(HDR+0x2c, 0)
wq(iov+0x00, U(dat)); wq(iov+0x08, 16)
say("sendmsg with name -> "..tostring(call(sc_sendmsg, fd, HDR, 0, 0, 0, 0)))
say(string.format("hdr after: +0=%X +8=%X +0x10=%X +0x18=%X", rq(HDR), rq(HDR+8), rq(HDR+0x10), rq(HDR+0x18)))
say(string.format("sockaddr after sendmsg: %X %X %X %X", rd(SA), rd(SA+4), rd(SA+8), rd(SA+12)))

say("socketpair -> "..tostring(call(sc_pair, 1, 1, 0, fds, 0, 0)))
local s0 = rd(fds)
say(string.format("pair fd=%d", s0))
-- cmsghdr: len 0xc, level SOL_SOCKET 0xffff, type SCM_RIGHTS 1
wd(CTL+0x00, 0xc); wd(CTL+0x04, 0xffff); wd(CTL+0x08, 1); wd(CTL+0x0c, 0xdeadbeef)
local lens = {0, 1, 4, 0xb, 0xc, 0x10, 0x800, 0x801, 0x1000, 0x10000}
for i=1,#lens do
    local L = lens[i]
    wq(HDR+0x00, 0); wd(HDR+0x08, 0)
    wq(HDR+0x10, U(iov)); wq(HDR+0x18, 1)
    wq(HDR+0x20, U(CTL)); wd(HDR+0x28, L); wd(HDR+0x2c, 0)
    wq(iov+0x00, U(dat)); wq(iov+0x08, 16)
    local r = call(sc_sendmsg, s0, HDR, 0, 0, 0, 0)
    say(string.format("ctl len=0x%X -> %s  ctl[0]=%X ctl[4]=%X ctl[8]=%X", L, tostring(r), rd(CTL), rd(CTL+4), rd(CTL+8)))
    scan(string.format("ctl len=0x%X", L), CTL, 0x800)
    wd(HDR+0x28, 0)
end
say("health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 742a DONE ===")
