-- CRASH_CLASS: MODERATE
-- PROBE 975a: aio submit as an file-descriptor oracle
--
-- fstat(189) kills the process and dup(41) returns -1, so the descriptor table has
-- never been enumerable. But 669 submits a read on a caller-chosen fd; if the submit
-- itself rejects a bad fd, that is an oracle that does not touch the descriptor.

print("=== PROBE 975a: AIO AS FD ORACLE ===")
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

local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  socketpair fds = %d, %d", fd0, fd1))

local reqs = memory.alloc(0x28)
local ids  = memory.alloc(8)
local st   = memory.alloc(8)
local err  = memory.alloc(8)
local buf  = memory.alloc(0x100)
local ba   = addr_of(buf)

local function probe_fd(fd, tag)
    for i=0,0x28-4,4 do wd(reqs+i,0) end
    wd(reqs+0x08, 0x40)
    wd(reqs+0x10, ba % 4294967296) wd(reqs+0x14, math.floor(ba/4294967296))
    wd(reqs+0x20, fd)
    wd(ids,0) wd(st,0)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(1),uint64(3),uint64(ids)) end)
    if not ok then print(string.format("  [%s fd=%d] PCALL-FAIL", tag, fd)) return -1,-1 end
    local h,l = hi_lo(rv)
    local r = to_num(rv)
    local id = rd(ids)
    pcall(function() return mk(664)(uint64(ids),uint64(1),uint64(st)) end)
    print(string.format("  [%s fd=%d] submit=%d id=0x%08X state=%d", tag, fd, r, id, rd(st)))
    if id ~= 0 then
        wd(reqs, id)
        pcall(function() return mk(662)(uint64(reqs),uint64(1),uint64(err)) end)
    end
    return r, rd(st)
end

print("[B] discrimination: a live socketpair fd vs a definitely-bad fd")
probe_fd(fd0, "live")
probe_fd(fd1, "live-peer")
probe_fd(0x7FF, "bad")

print("[C] sweep the low descriptors")
local live, dead, other = 0, 0, 0
local livefds = {}
for fd=0,31 do
    if fd ~= fd0 and fd ~= fd1 then
        local r, s = probe_fd(fd, "sweep")
        if r == 0 then live = live + 1 livefds[#livefds+1] = fd
        elseif r == -1 then dead = dead + 1
        else other = other + 1 end
    end
end
print(string.format("[D] sweep: live=%d dead=%d other=%d", live, dead, other))
local s=""
for i=1,#livefds do s = s .. livefds[i] .. "," end
print("    live fds: " .. s)

print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
