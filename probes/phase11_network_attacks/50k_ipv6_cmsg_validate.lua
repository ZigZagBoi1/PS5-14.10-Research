-- CRASH_CLASS: LOW
-- PROBE 50k: is the IPv6 control buffer parsed at all
--
-- Stock FreeBSD 9 ip6_setpktopts() walks the control mbuf and ip6_setpktopt()
-- validates each option: PKTINFO must be exactly sizeof(in6_pktinfo)=20 and its
-- interface index must exist (ENXIO), HOPLIMIT must be 4 bytes in [-1,255],
-- TCLASS 4 bytes in [-1,255], NEXTHOP needs a sockaddr, and an unknown type
-- falls to EINVAL. Every one of those is a shape that MUST fail.
--
-- 50h sent several of these and got the byte count back, which is either a real
-- deviation or proof the control buffer never reached that function. This probe
-- runs only MUST-FAIL shapes plus one valid baseline, so the answer is binary.

print("=== PROBE 50k: cmsg validation battery ===")

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
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local SYS_socket, SYS_sendmsg, SYS_connect, SYS_bind, SYS_getsockname = 97, 28, 98, 104, 32
local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41

local srv = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
local srv_sa = memory.alloc(0x40); zero(srv_sa, 0x40)
wb(srv_sa, 28); wb(srv_sa + 1, 28)
local br = call(mk(SYS_bind), uint64(srv), uint64(srv_sa), uint64(28))
local lenp = memory.alloc(8); zero(lenp, 8); wd(lenp, 28)
call(mk(SYS_getsockname), uint64(srv), uint64(srv_sa), uint64(lenp))
local port = rbyte(srv_sa + 2) * 256 + rbyte(srv_sa + 3)
print(string.format("[0] srv=%d bind=%d port=%d pid=%s", srv, br, port, tostring(pid())))

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
wq(mh + 16, iov); wq(mh + 24, 1); wq(mh + 32, ctrl)

local function send(n)
    wq(mh + 40, n)
    return call(mk(SYS_sendmsg), uint64(fd), uint64(mh), uint64(0))
end
local function cmsg(off, len, level, type)
    wq(ctrl + off, len)
    wd(ctrl + off + 8, level)
    wd(ctrl + off + 12, type)
    local adv = (len + 7) - ((len + 7) % 8)
    if adv < 16 then adv = 16 end
    return off + adv
end

print("")
print("  case                                   expect  ret")
local function run(tag, expect, fn)
    zero(ctrl, 0x1000)
    local n = fn()
    local r = send(n)
    print(string.format("  %-38s %-7s %s", tag, expect, tostring(r)))
    if pid() == 0 then print("  [!] process died"); return false end
    return true
end

-- baseline that must succeed
run("PKTINFO 20 bytes, ifindex 0", "send", function()
    cmsg(0, 36, IPPROTO_IPV6, 46); return 40 end)
-- must fail shapes
run("PKTINFO 4 bytes", "EINVAL", function()
    cmsg(0, 20, IPPROTO_IPV6, 46); return 24 end)
run("PKTINFO 24 bytes", "EINVAL", function()
    cmsg(0, 40, IPPROTO_IPV6, 46); return 40 end)
run("PKTINFO ifindex 0x7FFFFFFF", "ENXIO", function()
    cmsg(0, 36, IPPROTO_IPV6, 46); wd(ctrl + 32, 0x7FFFFFFF); return 40 end)
run("HOPLIMIT 4 bytes = 300", "EINVAL", function()
    cmsg(0, 20, IPPROTO_IPV6, 47); wd(ctrl + 16, 300); return 24 end)
run("HOPLIMIT 2 bytes", "EINVAL", function()
    cmsg(0, 18, IPPROTO_IPV6, 47); return 24 end)
run("HOPLIMIT 4 bytes = 5 (valid)", "send", function()
    cmsg(0, 20, IPPROTO_IPV6, 47); wd(ctrl + 16, 5); return 24 end)
run("TCLASS 4 bytes = 300", "EINVAL", function()
    cmsg(0, 20, IPPROTO_IPV6, 61); wd(ctrl + 16, 300); return 24 end)
run("NEXTHOP 8 bytes", "EINVAL", function()
    cmsg(0, 24, IPPROTO_IPV6, 48); return 24 end)
run("type 0x7F unknown", "EINVAL", function()
    cmsg(0, 20, IPPROTO_IPV6, 0x7F); return 24 end)
run("type 0 unknown", "EINVAL", function()
    cmsg(0, 20, IPPROTO_IPV6, 0); return 24 end)
run("RTHDR len8 rlen255 segleft1", "EINVAL", function()
    cmsg(0, 24, IPPROTO_IPV6, 51); wb(ctrl + 17, 255); wb(ctrl + 19, 1); return 24 end)
run("RTHDR len8 rlen0 segleft1", "EINVAL", function()
    cmsg(0, 24, IPPROTO_IPV6, 51); wb(ctrl + 19, 1); return 24 end)
run("HOPOPTS len8 hdrlen255", "EINVAL", function()
    cmsg(0, 24, IPPROTO_IPV6, 49); wb(ctrl + 17, 255); return 24 end)
run("HOPOPTS len8 hdrlen0 (valid)", "send", function()
    cmsg(0, 24, IPPROTO_IPV6, 49); return 24 end)
run("cmsg_len 15 (< header)", "EINVAL", function()
    cmsg(0, 15, IPPROTO_IPV6, 46); return 16 end)
run("level 0xFFFF (skipped)", "send", function()
    cmsg(0, 20, 0xFFFF, 1); return 24 end)

print("")
print("--- receiver view ---")
local rbuf = memory.alloc(0x100); zero(rbuf, 0x100)
for i = 1, 6 do
    local n = call(mk(29), uint64(srv), uint64(rbuf), uint64(0x100), uint64(0x80))
    print("  recv " .. i .. " ret=" .. n)
    if n < 0 then break end
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
pcall(function() mk(6)(uint64(srv)) end)
print("=== PROBE 50k COMPLETE ===")
