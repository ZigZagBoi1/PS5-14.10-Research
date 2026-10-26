-- CRASH_CLASS: LOW
-- PROBE 705a: kinfo_proc for kernel threads and the ALL list. Our own process's
-- kinfo_proc had every kernel pointer replaced by sentinels; kernel threads may
-- be handled differently.
print("=== PROBE 705a: KINFO_PROC FOR KERNEL THREADS ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local sc=mk(202)
local mib=memory.alloc(32)
local lp=memory.alloc(8)
local buf=memory.alloc(0x10000)
local function scan(tag,n)
  local kern=0
  local first=0
  for i=0,math.min(n,0x4000)-8,8 do
    local v=rq(N(buf)+i)
    if v then
      local h=math.floor(v/4294967296)
      if h>=0xFFFF8000 and h<=0xFFFFFFFF then
        kern=kern+1
        if first<5 then print(string.format("   %s off=0x%X val=%016X",tag,i,v)) first=first+1 end
      end
    end
  end
  return kern
end
local function query(sub,pid,size)
  wd(N(mib),1) wd(N(mib)+4,14)
  if sub then wd(N(mib)+8,sub) end
  if pid then wd(N(mib)+12,pid) end
  for i=0,0xFFF0,4 do wd(N(buf)+i,0) end
  wd(N(lp),size)
  local n = sub and (pid and 4 or 3) or 2
  local o,r=pcall(function() return sc(U(N(mib)),U(n),U(N(buf)),U(N(lp)),U(0),U(0)) end)
  local rv=o and N(r) or -999
  return rv,N(memory.read_dword(N(lp)))or 0
end
local cases={
 {"ALL",0,nil},
 {"PID0",1,0},{"PID1",1,1},{"PID2",1,2},{"PID3",1,3},{"PID7",1,7},{"PID100",1,100},
}
for _,c in ipairs(cases) do
  local rv,ln=query(c[2],c[3],0x10000)
  local kern=0
  if rv==0 then kern=scan(c[1],ln) end
  print(string.format("[%s] rv=%d len=%d kern=%d",c[1],rv,ln,kern))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
