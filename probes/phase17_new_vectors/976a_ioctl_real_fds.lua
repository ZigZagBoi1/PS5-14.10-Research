-- CRASH_CLASS: MODERATE
-- PROBE 976a: ioctl on the descriptors the process actually holds
--
-- Every earlier ioctl probe used a socket or fd 0 with arbitrary codes, so "ioctl
-- returns -1" described those arguments, not the ioctl path. 975c/975e made the real
-- table visible: fd 0-19 are non-socket descriptors, some read-write. This asks them
-- for the one thing ioctl is good for: a request that succeeds.
print("=== PROBE 976a: IOCTL ON REAL FDS ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local pid=to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local arg=memory.alloc(0x40)
for i=0,0x3C,4 do wd(arg+i,0) end
wd(arg,1)   -- FIONBIO on
local ap=addr_of(arg)

local REQS = {
    {0x8004667E, "FIONBIO"},
    {0x40487413, "TIOCGWINSZ"},
    {0x4004746A, "TIOCGETA"},
    {0x20006415, "FIONREAD"},
    {0x4004667F, "FIOASYNC"},
}
local function try(fd, req)
    local ok, rv = pcall(function() return mk(54)(uint64(fd), uint64(req), uint64(ap)) end)
    if not ok then return nil end
    return to_num(rv)
end

print("[B] sweep fds 0..19 with benign requests")
for fd=0,19 do
    local line = string.format("  fd=%-2d", fd)
    for _,r in ipairs(REQS) do
        local rv = try(fd, r[1])
        line = line .. string.format(" %s=%s", r[2], rv==nil and "FAIL" or string.format("%d", rv))
    end
    print(line)
end

print("[C] control: a socketpair fd, where FIONBIO must succeed")
local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  socketpair=%d,%d FIONBIO(peer)=%s", fd0, fd1, tostring(try(fd1, 0x8004667E))))
print(string.format("  FIONBIO(0)=%s  FIONBIO(1)=%s", tostring(try(0,0x8004667E)), tostring(try(1,0x8004667E))))
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
