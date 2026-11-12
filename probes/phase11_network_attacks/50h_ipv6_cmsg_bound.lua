-- CRASH_CLASS: HIGH
-- PROBE 50h: ancillary parsing, measured against a bound receiver
--
-- 50f/50g sent to ::1 port 9 with nobody listening. On loopback that produces
-- an ICMPv6 port-unreachable, and a connected UDP socket reports the queued
-- error on the NEXT send, so success and failure alternated by parity and did
-- not describe the parser at all. This probe keeps a bound receiver open and
-- sends to it, so -1 is a real refusal.
--
-- Same shapes as 50f/50g: cmsg_len below its header, truncation, oversize,
-- unknown level/type, legacy 2292 numbers, and option headers whose internal
-- length disagrees with cmsg_len.

print("=== PROBE 50h: ancillary parsing, receiver present ===")

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
local gr = call(mk(SYS_getsockname), uint64(srv), uint64(srv_sa), uint64(lenp))
local port = (rd(srv_sa + 2) % 65536) * 256 + (rd(srv_sa + 2) % 256)
-- port is network order in the low 16 bits of that dword: read bytes instead
local function rbyte(a) local ok,v=pcall(function() return memory.read_byte(a) end) if ok then return to_num(v) end return -1 end
port = rbyte(srv_sa + 2) * 256 + rbyte(srv_sa + 3)
print(string.format("[0] srv=%d bind=%d getsockname=%d port=%d pid=%s",
    srv, br, gr, port, tostring(pid())))
if br ~= 0 or port <= 0 then print("[!] no receiver"); return end

local fd = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
local sa = memory.alloc(0x40); zero(sa, 0x40)
wb(sa, 28); wb(sa + 1, 28)
wb(sa + 2, math.floor(port / 256)); wb(sa + 3, port % 256)
wb(sa + 23, 1)
print("[1] send socket=" .. fd .. " connect=" .. call(mk(SYS_connect), uint64(fd), uint64(sa), uint64(28)))

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
print("--- baseline (three plain sends, must all be 4) ---")
for i = 1, 3 do
    zero(ctrl, 0x1000)
    print("  send " .. i .. " ret=" .. send(0))
end

print("--- cmsg_len boundary per type, controllen padded ---")
local names = {[46]="PKTINFO", [47]="RTHDRDSTOPTS", [48]="NEXTHOP", [49]="HOPOPTS",
               [50]="DSTOPTS", [51]="RTHDR", [52]="TCLASS"}
print("  type            " .. table.concat({"12","13","14","15","16","17","18","20","24"}, "  "))
for _, T in ipairs({46, 47, 48, 49, 50, 51, 52}) do
    local row = {}
    for _, L in ipairs({12, 13, 14, 15, 16, 17, 18, 20, 24}) do
        zero(ctrl, 0x1000)
        local align = cmsg(0, L, IPPROTO_IPV6, T)
        row[#row + 1] = string.format("%-3s", tostring(send(align)))
        if pid() == 0 then print("  died at " .. names[T] .. " len=" .. L); return end
    end
    print("  " .. string.format("%-15s", names[T]) .. table.concat(row, "  "))
end

print("--- singular shapes ---")
local function one(tag, setup, ctrl_len)
    zero(ctrl, 0x1000)
    setup()
    local r = send(ctrl_len)
    print(string.format("  %-34s ret=%-5s alive=%s", tag, tostring(r), tostring(pid())))
end

one("PKTINFO valid 20-byte data", function() cmsg(0, 36, IPPROTO_IPV6, 46); wb(ctrl + 35, 1) end, 40)
one("PKTINFO data 4 bytes", function() cmsg(0, 20, IPPROTO_IPV6, 46) end, 24)
one("PKTINFO data 0 bytes", function() cmsg(0, 16, IPPROTO_IPV6, 46) end, 16)
one("cmsg_len 15", function() cmsg(0, 15, IPPROTO_IPV6, 46) end, 16)
one("cmsg_len 0x1000, ctrl 40", function() cmsg(0, 0x1000, IPPROTO_IPV6, 46) end, 40)
one("level 0xFFFF", function() cmsg(0, 20, 0xFFFF, 1) end, 24)
one("level 41 type 0x7F", function() cmsg(0, 20, IPPROTO_IPV6, 0x7F) end, 24)
one("RTHDR len8 rlen0 segleft0", function() cmsg(0, 24, IPPROTO_IPV6, 51) end, 24)
one("RTHDR len8 rlen0 segleft1", function() cmsg(0, 24, IPPROTO_IPV6, 51); wb(ctrl + 19, 1) end, 24)
one("RTHDR len8 rlen255 segleft1", function() cmsg(0, 24, IPPROTO_IPV6, 51); wb(ctrl + 17, 255); wb(ctrl + 19, 1) end, 24)
one("HOPOPTS len8 hdrlen0", function() cmsg(0, 24, IPPROTO_IPV6, 49) end, 24)
one("HOPOPTS len8 hdrlen255", function() cmsg(0, 24, IPPROTO_IPV6, 49); wb(ctrl + 17, 255) end, 24)
one("HOPOPTS len80 hdrlen255", function() cmsg(0, 80, IPPROTO_IPV6, 49); wb(ctrl + 17, 255) end, 80)
one("DSTOPTS len8 hdrlen255", function() cmsg(0, 24, IPPROTO_IPV6, 50); wb(ctrl + 17, 255) end, 24)
one("two cmsgs, second misaligned", function() local o = cmsg(0, 17, IPPROTO_IPV6, 46); cmsg(o - 1, 20, IPPROTO_IPV6, 46) end, 40)

print("--- legacy 2292 ---")
for _, T in ipairs({19, 20, 21, 22, 23, 24, 25}) do
    zero(ctrl, 0x1000)
    cmsg(0, 24, IPPROTO_IPV6, T)
    print(string.format("  type=%-3d ret=%-5s alive=%s", T, tostring(send(24)), tostring(pid())))
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
pcall(function() mk(6)(uint64(srv)) end)
print("=== PROBE 50h COMPLETE ===")
