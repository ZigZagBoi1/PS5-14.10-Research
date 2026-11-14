-- CRASH_CLASS: MODERATE
-- PROBE 940a: what puts an aio object in flight, and does completing the read release it
--
-- 894a left two of four slots answering 0x80020010 on delete while the other two
-- freed. The difference was never explained: those slots may simply have been
-- submitted and still blocked on a socketpair with no data. This probe separates
-- "submitted and pending" from "never submitted" by completing the read in the
-- same run.

print("=== PROBE 940a: AIO IN-FLIGHT ORACLE ===")
print("")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function show(tag, ok, rv)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function addr_of(t)
    local s=tostring(t) local m=s:match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(t)
end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
show("socketpair", pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  fds = %d, %d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); return end

local N = 4
local reqs = memory.alloc(0x28*N)
local ids  = memory.alloc(8*N)
local st   = memory.alloc(8*N)
local e1   = memory.alloc(8*N)
local e2   = memory.alloc(8*N)
local buf  = memory.alloc(0x1000)
for i=0,0x28*N-1,4 do wd(reqs+i,0) end
local ba = addr_of(buf)
print(string.format("  buf=0x%X", ba))
for i=0,N-1 do
    local r = reqs + i*0x28
    wd(r+0x08, 0x1000)
    wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
    wd(r+0x20, fd0)
end

print("[B] submit 669(cmd=0x1001, reqs, 4, prio=3, ids)")
show("submit", pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end))
for i=0,N-1 do print(string.format("    id[%d]=0x%08X", i, rd(ids+i*4))) end

print("[C] poll before any data is written")
show("poll", pcall(function() return mk(664)(uint64(ids),uint64(N),uint64(st)) end))
for i=0,N-1 do print(string.format("    state[%d]=%d", i, rd(st+i*4))) end

print("[D] delete one while the reads have no data")
local one = memory.alloc(8) wd(one, rd(ids))
local eo  = memory.alloc(8)
show("del one", pcall(function() return mk(662)(uint64(one),uint64(1),uint64(eo)) end))
print(string.format("    err=0x%08X (0x80020010 = in flight)", rd(eo)))

print("[E] write 16 bytes into the peer so the reads can complete")
local wbuf = memory.alloc(64)
for i=0,60,4 do wd(wbuf+i, 0x41424344) end
show("write", pcall(function() return mk(4)(uint64(fd1),uint64(wbuf),uint64(16),uint64(0)) end))

print("[F] poll after the write")
show("poll2", pcall(function() return mk(664)(uint64(ids),uint64(N),uint64(st)) end))
for i=0,N-1 do print(string.format("    state[%d]=%d", i, rd(st+i*4))) end

print("[G] delete again, four at once")
show("del all", pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(e1)) end))
for i=0,N-1 do print(string.format("    err[%d]=0x%08X", i, rd(e1+i*4))) end

print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
