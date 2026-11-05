-- CRASH_CLASS: HIGH
-- PROBE 50l: IPv6 ancillary data, correct cmsghdr layout
--
-- 50f/50g/50h/50k built cmsghdrs with 64-bit fields (len at +0 as a qword,
-- level at +8, type at +12). FreeBSD's cmsghdr is 32-bit fields at +0/+4/+8
-- with the data at +16, which is what 108a proves works for SCM_RIGHTS. Every
-- IPv6 cmsg in those probes therefore had level 0 and was skipped by
-- ip6_setpktopts ("if (cm->cmsg_level != IPPROTO_IPV6) continue"), so their
-- "everything is accepted" result described nothing.
--
-- This probe uses the working layout and runs the MUST-FAIL battery from the
-- FreeBSD 9 source plus the option-header shapes with mismatched internal
-- lengths.

print("=== PROBE 50l: IPv6 ancillary data, correct layout ===")

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
-- data_len bytes of option data; returns total control length
local function cmsg(off, data_len, level, type)
    wd(ctrl + off, DATA + data_len)
    wd(ctrl + off + 4, level)
    wd(ctrl + off + 8, type)
    local sp = DATA + data_len
    sp = (sp + 7) - ((sp + 7) % 8)
    return off + sp
end
local function d(i, v) wb(ctrl + DATA + i, v) end
local function d32(i, v) wd(ctrl + DATA + i, v) end

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

run("PKTINFO 20 bytes, ifindex 0", "send", function()
    cmsg(0, 20, IPPROTO_IPV6, 46); return 40 end)
run("PKTINFO 4 bytes", "EINVAL", function()
    cmsg(0, 4, IPPROTO_IPV6, 46); return 24 end)
run("PKTINFO 24 bytes", "EINVAL", function()
    cmsg(0, 24, IPPROTO_IPV6, 46); return 40 end)
run("PKTINFO ifindex 0x7FFFFFFF", "ENXIO", function()
    cmsg(0, 20, IPPROTO_IPV6, 46); d32(16, 0x7FFFFFFF); return 40 end)
run("PKTINFO ifindex 1", "send", function()
    cmsg(0, 20, IPPROTO_IPV6, 46); d32(16, 1); return 40 end)
run("HOPLIMIT 4 bytes = 300", "EINVAL", function()
    cmsg(0, 4, IPPROTO_IPV6, 47); d32(0, 300); return 24 end)
run("HOPLIMIT 2 bytes", "EINVAL", function()
    cmsg(0, 2, IPPROTO_IPV6, 47); return 24 end)
run("HOPLIMIT 4 bytes = 5", "send", function()
    cmsg(0, 4, IPPROTO_IPV6, 47); d32(0, 5); return 24 end)
run("TCLASS 4 bytes = 300", "EINVAL", function()
    cmsg(0, 4, IPPROTO_IPV6, 61); d32(0, 300); return 24 end)
run("TCLASS 4 bytes = 8", "send", function()
    cmsg(0, 4, IPPROTO_IPV6, 61); d32(0, 8); return 24 end)
run("NEXTHOP 8 bytes", "EINVAL", function()
    cmsg(0, 8, IPPROTO_IPV6, 48); return 24 end)
run("type 0x7F unknown", "EINVAL", function()
    cmsg(0, 4, IPPROTO_IPV6, 0x7F); return 24 end)
run("type 0 unknown", "EINVAL", function()
    cmsg(0, 4, IPPROTO_IPV6, 0); return 24 end)
run("cmsg_len 15 (< header)", "EINVAL", function()
    wd(ctrl, 15); wd(ctrl + 4, IPPROTO_IPV6); wd(ctrl + 8, 46); return 16 end)
run("level 0xFFFF (skipped)", "send", function()
    cmsg(0, 4, 0xFFFF, 1); return 24 end)

print("--- header options: internal length vs cmsg_len ---")
run("RTHDR len8 rlen0 segleft0", "send", function()
    cmsg(0, 8, IPPROTO_IPV6, 51); return 24 end)
run("RTHDR len8 rlen0 segleft1", "EINVAL", function()
    cmsg(0, 8, IPPROTO_IPV6, 51); d(3, 1); return 24 end)
run("RTHDR len8 rlen255 segleft1", "EINVAL", function()
    cmsg(0, 8, IPPROTO_IPV6, 51); d(1, 255); d(3, 1); return 24 end)
run("RTHDR len24 rlen2 segleft1", "send", function()
    cmsg(0, 24, IPPROTO_IPV6, 51); d(1, 2); d(3, 1); return 32 end)
run("RTHDR len24 rlen2 segleft9", "EINVAL", function()
    cmsg(0, 24, IPPROTO_IPV6, 51); d(1, 2); d(3, 9); return 32 end)
run("RTHDR len7 (not 8-aligned)", "EINVAL", function()
    cmsg(0, 7, IPPROTO_IPV6, 51); return 24 end)
run("HOPOPTS len8 hdrlen0", "send", function()
    cmsg(0, 8, IPPROTO_IPV6, 49); return 24 end)
run("HOPOPTS len8 hdrlen255", "EINVAL", function()
    cmsg(0, 8, IPPROTO_IPV6, 49); d(1, 255); return 24 end)
run("HOPOPTS len24 hdrlen2", "send", function()
    cmsg(0, 24, IPPROTO_IPV6, 49); d(1, 2); return 32 end)
run("DSTOPTS len8 hdrlen255", "EINVAL", function()
    cmsg(0, 8, IPPROTO_IPV6, 50); d(1, 255); return 24 end)
run("RTHDRDSTOPTS (35) len8 hdrlen255", "EINVAL", function()
    cmsg(0, 8, IPPROTO_IPV6, 35); d(1, 255); return 24 end)

print("--- two cmsgs ---")
run("PKTINFO then HOPLIMIT", "send", function()
    local o = cmsg(0, 20, IPPROTO_IPV6, 46)
    return cmsg(o, 4, IPPROTO_IPV6, 47) end)
run("PKTINFO then TCLASS=3", "send", function()
    local o = cmsg(0, 20, IPPROTO_IPV6, 46)
    local o2 = cmsg(o, 4, IPPROTO_IPV6, 61)
    wb(ctrl + o + DATA, 3)
    return o2 end)
run("cmsg_len 0x1000 with ctrl 40", "EINVAL", function()
    wd(ctrl, 0x1000); wd(ctrl + 4, IPPROTO_IPV6); wd(ctrl + 8, 46); return 40 end)
run("cmsg_len 8 with ctrl 40", "EINVAL", function()
    wd(ctrl, 8); wd(ctrl + 4, IPPROTO_IPV6); wd(ctrl + 8, 46); return 40 end)
run("second cmsg at offset 12 (misaligned)", "EINVAL", function()
    wd(ctrl, DATA + 20); wd(ctrl + 4, IPPROTO_IPV6); wd(ctrl + 8, 46)
    wd(ctrl + 12, DATA + 4); wd(ctrl + 16, IPPROTO_IPV6); wd(ctrl + 20, 47)
    return 40 end)

print("")
print("--- receiver view (first six) ---")
local rbuf = memory.alloc(0x100); zero(rbuf, 0x100)
for i = 1, 6 do
    local n = call(mk(29), uint64(srv), uint64(rbuf), uint64(0x100), uint64(0x80))
    print("  recv " .. i .. " ret=" .. n)
    if n < 0 then break end
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
pcall(function() mk(6)(uint64(srv)) end)
print("=== PROBE 50l COMPLETE ===")
