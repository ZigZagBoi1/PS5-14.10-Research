-- CRASH_CLASS: LOW
-- PROBE 92b: Check if IPV6_2292PKTOPTIONS (opt 25) is implemented
--
-- Before running the race, verify the setsockopt option works at all.
-- Tests: set with cmsg payload, set with empty, get.
-- Also tests the RFC 3542 versions (IPV6_PKTINFO=46 etc.) for comparison.

print("=== PROBE 92b: 2292 GATE CHECK ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

-- Create IPv6 UDP socket
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("socket="..s6)
if s6<=0 then print("FAIL") return end

local PV6=41

-- Helper: setsockopt and report
local function try_set(name, opt, buf, blen)
    local rv=N(native.fcall_with_rax(stub,105,s6,PV6,opt,buf,blen))
    print(string.format("  set %-30s opt=%d len=%d rv=%d", name, opt, blen, rv))
    return rv
end

-- Helper: getsockopt and report
local function try_get(name, opt)
    local gb=memory.alloc(256); z(gb,256)
    local gl=memory.alloc(4); wd(gl,256)
    local rv=N(native.fcall_with_rax(stub,118,s6,PV6,opt,N(gb),N(gl)))
    local olen=rd(gl)
    print(string.format("  get %-30s opt=%d rv=%d olen=%d", name, opt, rv, olen))
    return rv, olen
end

-- ============================================================
-- Section A: RFC 3542 options (known working)
-- ============================================================
print("--- A: RFC 3542 (reference) ---")

-- IPV6_PKTINFO (46): 20 bytes in6_pktinfo
local pi=memory.alloc(20); z(pi,20)
try_set("IPV6_PKTINFO", 46, N(pi), 20)
try_get("IPV6_PKTINFO", 46)

-- IPV6_UNICAST_HOPS (4): 4 bytes int
local hb=memory.alloc(4); wd(hb,64)
try_set("IPV6_UNICAST_HOPS", 4, N(hb), 4)
try_get("IPV6_UNICAST_HOPS", 4)

-- IPV6_MULTICAST_HOPS (10): 4 bytes int
try_set("IPV6_MULTICAST_HOPS", 10, N(hb), 4)
try_get("IPV6_MULTICAST_HOPS", 10)

-- ============================================================
-- Section B: RFC 2292 options (the vulnerable ones)
-- ============================================================
print("")
print("--- B: RFC 2292 (CVE-2020-7457 target) ---")

-- IPV6_2292PKTINFO (2): like PKTINFO but old API
try_set("IPV6_2292PKTINFO", 2, N(pi), 20)
try_get("IPV6_2292PKTINFO", 2)

-- IPV6_2292PKTOPTIONS (25): serialized cmsg
-- Build: cmsghdr(len=28, level=41, type=46) + in6_pktinfo(20 bytes)
local cm=memory.alloc(48); z(cm,48)
wd(cm+0, 28)   -- cmsg_len
wd(cm+4, PV6)  -- cmsg_level
wd(cm+8, 46)   -- cmsg_type = IPV6_PKTINFO
-- payload: 20 bytes zero in6_pktinfo

try_set("IPV6_2292PKTOPTIONS(cmsg)", 25, N(cm), 32)
try_get("IPV6_2292PKTOPTIONS", 25)

-- Also try with 0 length (clear path)
try_set("IPV6_2292PKTOPTIONS(clear)", 25, N(cm), 0)
try_get("IPV6_2292PKTOPTIONS(after clear)", 25)

-- IPV6_2292HOPLIMIT (3)
local hl=memory.alloc(4); wd(hl,1)
try_set("IPV6_2292HOPLIMIT", 3, N(hl), 4)

-- IPV6_2292HOPOPTS (4 in old numbering?)
-- Actually in FreeBSD: 2292HOPOPTS=22, 2292DSTOPTS=23, 2292RTHDR=24
try_set("IPV6_2292HOPOPTS", 22, N(cm), 0)
try_set("IPV6_2292DSTOPTS", 23, N(cm), 0)
try_set("IPV6_2292RTHDR", 24, N(cm), 0)

-- ============================================================
-- Section C: Raw socket test
-- ============================================================
print("")
print("--- C: Raw socket ---")
local sr=N(native.fcall_with_rax(stub,97,28,3,0))
print("raw_socket="..sr)
if sr>0 then
    local rv=N(native.fcall_with_rax(stub,105,sr,PV6,25,N(cm),32))
    print("  raw set 2292PKTOPTIONS rv="..rv)
    native.fcall_with_rax(stub,6,sr)
else
    print("  raw socket failed (expected on console)")
end

-- Cleanup
native.fcall_with_rax(stub,6,s6)
print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 92b DONE ===")
