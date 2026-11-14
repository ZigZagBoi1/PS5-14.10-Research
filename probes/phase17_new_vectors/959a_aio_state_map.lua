-- CRASH_CLASS: LOW
-- PROBE 959a: map the aio state transitions exactly
--
-- 941b saw 2,2 then 3,3 after a 8 KB send; 943a with four objects saw 1,1,1,1
-- after the same send. One of the two readings is wrong, so this probe records the
-- state after every step with no child thread and no delete until the end.

print("=== PROBE 959a: AIO STATE MAP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local N=4
local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0,fd1=rd(sv),rd(sv+4)
print(string.format("[0] pid=%s fds=%d,%d", tostring(to_num(mk(20)())), fd0, fd1))
local reqs=memory.alloc(0x28*N) local ids=memory.alloc(8*N) local st=memory.alloc(8*N)
local one=memory.alloc(8) local buf=memory.alloc(0x1000*N) local ba=addr_of(buf)
local wb=memory.alloc(0x3000)
for i=0,0x2FFC,4 do wd(wb+i,0x41424344) end
for i=0,0x28*N-1,4 do wd(reqs+i,0) end
for i=0,N-1 do
    local q=reqs+i*0x28
    wd(q+0x08,0x1000)
    wd(q+0x10,(ba+i*0x1000)%4294967296) wd(q+0x14,math.floor((ba+i*0x1000)/4294967296))
    wd(q+0x20,fd0)
end
local function states(tag)
    mk(664)(uint64(ids),uint64(N),uint64(st))
    print(string.format("  [%s] states %d %d %d %d", tag, rd(st), rd(st+4), rd(st+8), rd(st+12)))
end
local function sendbytes(n, tag)
    local ok,rv=pcall(function() return mk(133)(uint64(fd1),uint64(wb),uint64(n),uint64(0x80),uint64(0),uint64(0)) end)
    local v=0 if ok and type(rv)=="table" and rv.l then v=rv.l elseif ok then v=to_num(rv) end
    print(string.format("  [%s] sent=%d", tag, v))
end
mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids))
for i=0,N-1 do print(string.format("    id[%d]=0x%08X", i, rd(ids+i*4))) end
states("submit")
sendbytes(0x1000, "send4k")
states("after4k")
sendbytes(0x1000, "send8k")
states("after8k")
sendbytes(0x2000, "send16k")
states("after16k")
for i=0,N-1 do
    wd(one, rd(ids+i*4))
    local ok,rv=pcall(function() return mk(662)(uint64(one),uint64(1),uint64(one)) end)
    print(string.format("    del[%d] ret=0x%08X elem=0x%08X", i, ok and to_num(rv) or 0, rd(one)))
end
states("afterdelete")
print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
