-- CRASH_CLASS: MODERATE
-- PROBE 985a: plain read/write/mmap on the descriptors the kernel hands out
--
-- Gap D in the project's own register: read()/write()/mmap() were only ever tried on
-- /dev/zero, /dev/random, /dev/null and /dev/urandom. fds 10 and 14 answer 653 with
-- EINVAL and Sony status 0x803B0004 instead of -1, and 653 itself hands out 22/23/24,
-- so this sweeps plain I/O over every descriptor that is not a socket.

print("=== PROBE 985a: DEVICE FD I/O ===")
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
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function call(tag, n, ...)
    local a = {...}
    local ok, rv = pcall(function() return mk(n)(unpack(a)) end)
    if not ok then return nil end
    local h,l = hi_lo(rv)
    return l, string.format("0x%08X_%08X", h, l)
end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

-- collect the descriptors the kernel offers
local ids = {}
local function add(v) if v and v >= 0 and v < 0x10000 then ids[#ids+1] = v end end
add((call("653(0)", 653, uint64(0))))
add((call("653(0x100000)", 653, uint64(0x100000))))
add((call("653(0x400000)", 653, uint64(0x400000))))
print("    from 653: " .. table.concat(ids, ", "))

local probe_fds = {3, 10, 14, 18, 19, 20, 21}
for _,v in ipairs(ids) do probe_fds[#probe_fds+1] = v end

local buf = memory.alloc(0x1000)
for i=0,0xFFF,4 do wd(buf+i, 0xCCCCCCCC) end
local ba = addr_of(buf)

print("[B] read(3) on each descriptor")
for _,fd in ipairs(probe_fds) do
    for i=0,0xFFF,4 do wd(buf+i, 0xCCCCCCCC) end
    local l, s = call("read", 3, uint64(fd), uint64(ba), uint64(0x100))
    if l == nil then
        print(string.format("    fd=%d PCALL-FAIL", fd))
    else
        print(string.format("    fd=%d ret=%s  first=0x%08X 0x%08X", fd, s, rd(buf), rd(buf+4)))
    end
end

print("[C] write(4) of a recognisable buffer")
for _,fd in ipairs(probe_fds) do
    local l, s = call("write", 4, uint64(fd), uint64(ba), uint64(0x10))
    if l ~= nil then print(string.format("    fd=%d write ret=%s", fd, s)) end
end

print("[D] mmap(477) at a fixed address on each descriptor")
for _,fd in ipairs(probe_fds) do
    local l, s = call("mmap", 477, uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(fd), uint64(0))
    if l ~= nil then print(string.format("    fd=%d mmap ret=%s", fd, s)) end
end

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
