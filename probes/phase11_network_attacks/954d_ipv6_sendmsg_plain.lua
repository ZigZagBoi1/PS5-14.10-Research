-- CRASH_CLASS: LOW
-- PROBE 50i: why a plain sendmsg fails where one with a control buffer succeeds
--
-- 50h had a bound receiver, yet the three plain sends (controllen=0) returned
-- -1 and every send carrying a cmsg returned the byte count. Either the kernel
-- refuses msg_control set with a zero controllen, or the failures are an order
-- effect (a queued ICMPv6 error), or the control-bearing packets are not
-- actually delivered at all. This probe separates those: it alternates the two
-- shapes in a fixed order, and then reads what the receiver has.

print("=== PROBE 50i: plain vs control sendmsg ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function rbyte(a) local ok,v=pcall(function() return memory.read_byte(a) end) if ok then return to_num(v) end return -1 end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local SYS_socket, SYS_sendmsg, SYS_connect, SYS_bind, SYS_getsockname = 97, 28, 98, 104, 32
local SYS_recvfrom = 29
local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41
local MSG_DONTWAIT = 0x80

local srv = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
local srv_sa = memory.alloc(0x40); zero(srv_sa, 0x40)
wb(srv_sa, 28); wb(srv_sa + 1, 28)
local br = call(mk(SYS_bind), uint64(srv), uint64(srv_sa), uint64(28))
local lenp = memory.alloc(8); zero(lenp, 8); wd(lenp, 28)
local gr = call(mk(SYS_getsockname), uint64(srv), uint64(srv_sa), uint64(lenp))
local port = rbyte(srv_sa + 2) * 256 + rbyte(srv_sa + 3)
print(string.format("[0] srv=%d bind=%d getsockname=%d port=%d pid=%s",
    srv, br, gr, port, tostring(pid())))

local fd = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
local sa = memory.alloc(0x40); zero(sa, 0x40)
wb(sa, 28); wb(sa + 1, 28)
wb(sa + 2, math.floor(port / 256)); wb(sa + 3, port % 256)
wb(sa + 23, 1)
print("[1] connect=" .. call(mk(SYS_connect), uint64(fd), uint64(sa), uint64(28)))

local data = memory.alloc(0x40); zero(data, 0x40); wd(data, 0x41414141)
local iov = memory.alloc(0x20); zero(iov, 0x20)
wq(iov, data); wq(iov + 8, 4)
local ctrl = memory.alloc(0x1000); zero(ctrl, 0x1000)
local mh = memory.alloc(0x80); zero(mh, 0x80)
wq(mh + 16, iov); wq(mh + 24, 1)

local function send(ctrlptr, n)
    wq(mh + 32, ctrlptr)
    wq(mh + 40, n)
    return call(mk(SYS_sendmsg), uint64(fd), uint64(mh), uint64(0))
end

-- a valid PKTINFO cmsg
wq(ctrl, 36); wd(ctrl + 8, IPPROTO_IPV6); wd(ctrl + 12, 46); wb(ctrl + 35, 1)

print("")
print("--- alternating shapes, same destination ---")
print("  1 plain (control NULL, len 0)      ret=" .. send(uint64(0), 0))
print("  2 cmsg  (control set,  len 40)     ret=" .. send(uint64(ctrl), 40))
print("  3 plain (control set,  len 0)      ret=" .. send(uint64(ctrl), 0))
print("  4 cmsg                             ret=" .. send(uint64(ctrl), 40))
print("  5 plain (control NULL, len 0)      ret=" .. send(uint64(0), 0))
print("  6 cmsg                             ret=" .. send(uint64(ctrl), 40))
print("  7 plain (control set,  len 0)      ret=" .. send(uint64(ctrl), 0))

print("")
print("--- what the receiver actually got ---")
local rbuf = memory.alloc(0x100); zero(rbuf, 0x100)
for i = 1, 8 do
    local n = call(mk(SYS_recvfrom), uint64(srv), uint64(rbuf), uint64(0x100), uint64(MSG_DONTWAIT))
    print("  recv " .. i .. " ret=" .. n)
    if n < 0 then break end
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
pcall(function() mk(6)(uint64(srv)) end)
print("=== PROBE 50i COMPLETE ===")
