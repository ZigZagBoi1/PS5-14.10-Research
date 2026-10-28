-- CRASH_CLASS: HIGH
-- PROBE 50f: IPv6 ancillary data - malformed control messages on sendmsg
--
-- 50e showed MSFILTER is not implemented, but the ordinary ancillary paths are
-- live: SCM_RIGHTS works (108a). For AF_INET6 the send path parses every cmsg
-- into ip6_pktopt (IPV6_PKTINFO, HOPOPTS, DSTOPTS, RTHDR, RTHDRDSTOPTS, NEXTHOP);
-- that parser trusts two independent lengths - the cmsg_len from the control
-- buffer and the header length declared inside the option data - and mismatch
-- between them is the classic source of kernel over-reads.
--
-- Cases: valid control (baseline), truncated cmsg, cmsg_len below the header,
-- cmsg_len zero, cmsg_len far beyond msg_controllen, unknown level/type, legacy
-- 2292 numbers, and option data whose internal length disagrees with cmsg_len.
-- A -1 is a clean refusal; a dead process is the finding.

print("=== PROBE 50f: IPv6 ancillary data ===")

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

local SYS_socket, SYS_sendmsg, SYS_connect = 97, 28, 98
local AF_INET6, SOCK_DGRAM, IPPROTO_UDP = 28, 2, 17
local IPPROTO_IPV6 = 41

local fd = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
print("[0] socket=" .. fd .. " pid=" .. tostring(pid()))
if fd < 0 then print("[!] no socket"); return end

-- destination ::1 port 9 (discard); the send path parses cmsg before routing
local sa = memory.alloc(0x40); zero(sa, 0x40)
wb(sa, 28)          -- sin6_len
wb(sa + 1, 28)      -- sin6_family
wb(sa + 2, 0x09)    -- port 9, network order
wb(sa + 3, 0x00)
wb(sa + 23, 1)      -- ::1
print("[1] connect=" .. call(mk(SYS_connect), uint64(fd), uint64(sa), uint64(28)))

-- fixed parts: payload iovec and msghdr
local data = memory.alloc(0x40); zero(data, 0x40); wd(data, 0x41414141)
local iov = memory.alloc(0x20); zero(iov, 0x20)
wq(iov, data); wq(iov + 8, 4)

local ctrl = memory.alloc(0x400); zero(ctrl, 0x400)
local mh = memory.alloc(0x80); zero(mh, 0x80)
wq(mh + 16, iov)
wq(mh + 24, 1)
wq(mh + 32, ctrl)

local function send(controllen)
    wq(mh + 40, controllen)
    return call(mk(SYS_sendmsg), uint64(fd), uint64(mh), uint64(0))
end
-- cmsg_len, level, type; returns offset of the next cmsg slot
local function cmsg(off, len, level, type)
    wq(ctrl + off, len)
    wd(ctrl + off + 8, level)
    wd(ctrl + off + 12, type)
    local adv = (len + 7) - ((len + 7) % 8)
    if adv < 16 then adv = 16 end
    return off + adv
end
local function dm(i, b) wb(ctrl + 16 + i, b) end

print("")
print("--- baseline: plain sendmsg, no control ---")
print("  no control: ret=" .. send(0) .. " alive=" .. tostring(pid()))

print("--- A: valid IPV6_PKTINFO (20 bytes of data) ---")
local o = cmsg(0, 16 + 20, IPPROTO_IPV6, 46)
wb(ctrl + 16 + 19, 1)          -- ifindex byte, ::1 source
print("  ret=" .. send(o) .. " alive=" .. tostring(pid()))

print("--- B: PKTINFO truncated to 4 bytes of data ---")
zero(ctrl, 0x400)
o = cmsg(0, 16 + 4, IPPROTO_IPV6, 46)
print("  ret=" .. send(o) .. " alive=" .. tostring(pid()))

print("--- C: cmsg_len below the 16-byte header ---")
zero(ctrl, 0x400)
for _, L in ipairs({4, 8, 15}) do
    cmsg(0, L, IPPROTO_IPV6, 46)
    print("  cmsg_len=" .. L .. " ret=" .. send(16) .. " alive=" .. tostring(pid()))
end

print("--- D: cmsg_len zero ---")
zero(ctrl, 0x400)
cmsg(0, 0, IPPROTO_IPV6, 46)
print("  ret=" .. send(16) .. " alive=" .. tostring(pid()))

print("--- E: cmsg_len far beyond msg_controllen ---")
zero(ctrl, 0x400)
cmsg(0, 0x10000, IPPROTO_IPV6, 46)
print("  ret=" .. send(40) .. " alive=" .. tostring(pid()))
zero(ctrl, 0x400)
cmsg(0, 0x1000, IPPROTO_IPV6, 46)
print("  controllen=40 cmsg_len=0x1000 ret=" .. send(40) .. " alive=" .. tostring(pid()))

print("--- F: unknown level / type ---")
zero(ctrl, 0x400)
cmsg(0, 16 + 8, 0xFFFF, 1)
print("  level=0xFFFF ret=" .. send(24) .. " alive=" .. tostring(pid()))
zero(ctrl, 0x400)
cmsg(0, 16 + 8, IPPROTO_IPV6, 0x7F)
print("  level=41 type=0x7F ret=" .. send(24) .. " alive=" .. tostring(pid()))

print("--- G: legacy 2292 numbers ---")
for _, T in ipairs({19, 20, 21, 22, 23, 24, 25}) do
    zero(ctrl, 0x400)
    cmsg(0, 16 + 8, IPPROTO_IPV6, T)
    print("  type=" .. T .. " ret=" .. send(24) .. " alive=" .. tostring(pid()))
end

print("--- H: RTHDR (51) internal length vs cmsg_len ---")
zero(ctrl, 0x400)
cmsg(0, 16 + 8, IPPROTO_IPV6, 51)
wb(ctrl + 16 + 0, 0); wb(ctrl + 16 + 1, 0); wb(ctrl + 16 + 2, 0); wb(ctrl + 16 + 3, 0)
print("  len=8 rthdr_len=0 segleft=0 ret=" .. send(24) .. " alive=" .. tostring(pid()))
zero(ctrl, 0x400)
cmsg(0, 16 + 8, IPPROTO_IPV6, 51)
wb(ctrl + 16 + 0, 0); wb(ctrl + 16 + 1, 0); wb(ctrl + 16 + 2, 0); wb(ctrl + 16 + 3, 1)
print("  len=8 rthdr_len=0 segleft=1 ret=" .. send(24) .. " alive=" .. tostring(pid()))
zero(ctrl, 0x400)
cmsg(0, 16 + 8, IPPROTO_IPV6, 51)
wb(ctrl + 16 + 1, 255); wb(ctrl + 16 + 3, 1)
print("  len=8 rthdr_len=255 segleft=1 ret=" .. send(24) .. " alive=" .. tostring(pid()))

print("--- I: HOPOPTS (49) internal length vs cmsg_len ---")
zero(ctrl, 0x400)
cmsg(0, 16 + 8, IPPROTO_IPV6, 49)
wb(ctrl + 16 + 0, 0); wb(ctrl + 16 + 1, 0)
print("  len=8 hdrlen=0 ret=" .. send(24) .. " alive=" .. tostring(pid()))
zero(ctrl, 0x400)
cmsg(0, 16 + 8, IPPROTO_IPV6, 49)
wb(ctrl + 16 + 1, 255)
print("  len=8 hdrlen=255 ret=" .. send(24) .. " alive=" .. tostring(pid()))
zero(ctrl, 0x400)
cmsg(0, 16 + 64, IPPROTO_IPV6, 49)
wb(ctrl + 16 + 1, 255)
print("  len=80 hdrlen=255 ret=" .. send(80) .. " alive=" .. tostring(pid()))

print("--- J: DSTOPTS (50) and RTHDRDSTOPTS (47) ---")
for _, T in ipairs({50, 47, 48}) do
    zero(ctrl, 0x400)
    cmsg(0, 16 + 8, IPPROTO_IPV6, T)
    wb(ctrl + 16 + 1, 255)
    print("  type=" .. T .. " hdrlen=255 ret=" .. send(24) .. " alive=" .. tostring(pid()))
end

print("--- K: two cmsgs, second starts one byte off the 8-byte boundary ---")
zero(ctrl, 0x400)
o = cmsg(0, 16 + 1, IPPROTO_IPV6, 46)
wb(ctrl + o - 1, 0)
cmsg(o - 1, 16 + 4, IPPROTO_IPV6, 46)
print("  ret=" .. send(o + 16) .. " alive=" .. tostring(pid()))

print("--- L: controllen larger than the buffer we filled ---")
zero(ctrl, 0x400)
cmsg(0, 16 + 20, IPPROTO_IPV6, 46)
print("  ret=" .. send(0x400) .. " alive=" .. tostring(pid()))

print("[Z] alive=" .. tostring(pid()) .. " fd=" .. fd)
pcall(function() mk(6)(uint64(fd)) end)
print("=== PROBE 50f COMPLETE ===")
