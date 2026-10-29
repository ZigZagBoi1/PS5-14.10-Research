-- CRASH_CLASS: LOW
-- PROBE 50j: which IPV6 option numbers does this kernel actually know
--
-- 50h sent IPPROTO_IPV6 cmsgs for types 46-52 with nonsense contents and every
-- one returned success, which is what an UNKNOWN type does (skip and continue),
-- not what a validating parser does. So the first question is not "does the
-- parser validate" but "are those the right numbers".
--
-- Each candidate is asked twice: setsockopt with a 4-byte int, then getsockopt
-- readback. A boolean flag accepts 1 and returns 1; an enum accepts a small
-- value and returns it; a header option rejects a 4-byte value outright.
-- Differences between the three tell the classes apart without guessing.

print("=== PROBE 50j: IPV6 option numbers ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local SYS_socket, SYS_setsockopt, SYS_getsockopt = 97, 105, 118
local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41

local fd = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
print("[0] fd=" .. fd .. " pid=" .. tostring(pid()))
if fd < 0 then return end

local v = memory.alloc(0x20)
local o = memory.alloc(0x20)
local lp = memory.alloc(8)

print("")
print("  opt  set(1)  get   readback")
for n = 40, 90 do
    zero(v, 0x20); zero(o, 0x20); zero(lp, 8)
    wd(v, 1)
    wd(lp, 4)
    local s = call(mk(SYS_setsockopt), uint64(fd), uint64(IPPROTO_IPV6), uint64(n), uint64(v), uint64(4))
    local g = -999
    local rb = -999
    if s == 0 then
        g = call(mk(SYS_getsockopt), uint64(fd), uint64(IPPROTO_IPV6), uint64(n), uint64(o), uint64(lp))
        if g == 0 then rb = rd(o) end
    end
    if s == 0 or g == 0 then
        print(string.format("  %-4d %-7d %-5d %d", n, s, g, rb))
    end
    if pid() == 0 then print("  [!] died at opt=" .. n); return end
end

print("")
print("--- same probe on a TCP socket (some options are only valid there) ---")
local tfd = call(mk(SYS_socket), uint64(AF_INET6), uint64(1), uint64(6))
print("  tcp fd=" .. tfd)
if tfd and tfd > 0 then
    for n = 40, 90 do
        zero(v, 0x20); zero(o, 0x20); zero(lp, 8)
        wd(v, 1); wd(lp, 4)
        local s = call(mk(SYS_setsockopt), uint64(tfd), uint64(IPPROTO_IPV6), uint64(n), uint64(v), uint64(4))
        local g = -999
        local rb = -999
        if s == 0 then
            g = call(mk(SYS_getsockopt), uint64(tfd), uint64(IPPROTO_IPV6), uint64(n), uint64(o), uint64(lp))
            if g == 0 then rb = rd(o) end
        end
        if s == 0 or g == 0 then print(string.format("  %-4d %-7d %-5d %d", n, s, g, rb)) end
        if pid() == 0 then print("  [!] died at opt=" .. n); return end
    end
    pcall(function() mk(6)(uint64(tfd)) end)
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
print("=== PROBE 50j COMPLETE ===")
