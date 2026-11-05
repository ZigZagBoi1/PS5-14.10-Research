-- CRASH_CLASS: LOW
-- PROBE 975e: raw sockaddr bytes from getsockname / getpeername for every socket
print("=== PROBE 975e: FD PEER ADDRESSES ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function rb(a) local o,v=pcall(function() return to_num(memory.read_byte(a)) end) if o then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hexdump(p, n)
    local s=""
    for i=0,n-1 do s = s .. string.format("%02x", rb(p+i)<0 and 0 or rb(p+i)) end
    return s
end
local function ascii(p, n)
    local s=""
    for i=0,n-1 do
        local c=rb(p+i)
        if c>=32 and c<127 then s=s..string.char(c) else s=s.."." end
    end
    return s
end
local pid=to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local sa=memory.alloc(0x120)
local lp=memory.alloc(8)

local function addr(fd, syscallno, tag)
    for i=0,0x11C,4 do wd(sa+i,0) end
    wd(lp,0x110)
    local ok, rv = pcall(function() return mk(syscallno)(uint64(fd),uint64(sa),uint64(lp)) end)
    if not ok then print(string.format("  fd=%-2d %-6s PCALL-FAIL", fd, tag)) return end
    local r = to_num(rv)
    if r ~= 0 then
        print(string.format("  fd=%-2d %-6s ret=%d", fd, tag, r))
        return
    end
    local len = rd(lp)
    local fam = rb(sa+1)
    print(string.format("  fd=%-2d %-6s len=%-3d fam=%-3d %s | %s",
        fd, tag, len, fam, hexdump(sa, math.min(len, 32)), ascii(sa, math.min(len, 32))))
end

local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("[B] socketpair = %d, %d", fd0, fd1))

print("[C] sockets 20..%d, getsockname then getpeername", fd1)
for fd=20,fd1 do
    addr(fd, 32, "local")
    addr(fd, 31, "peer")
end
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
