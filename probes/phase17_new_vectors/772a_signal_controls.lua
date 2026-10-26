-- CRASH_CLASS: HIGH
-- PROBE 772a: knote lifetime for EVFILT_SIGNAL
--
-- 771b sections A and B were clean; section C (helper churning kevent while
-- the parent storms signals) died at 8.9 s, the same wall helper-thread probes
-- hit before. These two controls separate the wall from the race:
--   [A] helper writes a progress word only, parent storms
--   [B] helper churns EV_DELETE/EV_ADD, parent does not storm
print("=== PROBE 772a: SIGNAL KNOTE CHURN ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function ww(a,v) pcall(function() memory.write_word(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local SIG=30
local EV_ADD,EV_DELETE,EV_ONESHOT=0x0001,0x0002,0x0010
local F_SIG=0xFFFA
local pid=call(mk(20),0,0,0,0,0,0)
local act=to_num(memory.alloc(0x40)); zero(act,0x40); wd(act,1)
call(mk(416),SIG,act,0,0,0,0)
local ev=to_num(memory.alloc(0x200)); local ts=to_num(memory.alloc(0x10))
local function reg(kq,ch) return call(mk(363),kq,ch,1,ev,1,ts) end
local function poll(kq,n) zero(ev,0x200); return call(mk(363),kq,0,0,ev,n or 4,ts) end
-- [A] helper with no syscalls, parent storms
local kq2=call(mk(362),0,0,0,0,0,0)
local ch=to_num(memory.alloc(0x40)); zero(ch,0x40)
wq(ch+0,SIG); ww(ch+8,F_SIG); ww(ch+10,EV_ADD)
local chd=to_num(memory.alloc(0x40)); zero(chd,0x40)
wq(chd+0,SIG); ww(chd+8,F_SIG); ww(chd+10,EV_DELETE)
call(mk(363),kq2,ch,1,ev,1,ts)
local prog=to_num(memory.alloc(8)); wd(prog,0)
local N=20000
local function body_for(kind)
  local b
  if kind=="spin" then
    b = [[
local PROG,N = tonumber("!PROG!"),tonumber("!N!")
for i=1,N do memory.write_dword(PROG,i) end
]]
  else
    b = [[
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=363 setmetatable(t,getmetatable(syscall.pipe))
local KQ,CHD,CH,TS,PROG,N = tonumber("!KQ!"),tonumber("!CHD!"),tonumber("!CH!"),tonumber("!TS!"),tonumber("!PROG!"),tonumber("!N!")
for i=1,N do
    pcall(function() t(U(KQ),U(CHD),1,0,0,U(TS)) end)
    pcall(function() t(U(KQ),U(CH),1,0,0,U(TS)) end)
    memory.write_dword(PROG,i)
end
]]
  end
  return b:gsub("!KQ!",kq2):gsub("!CHD!",chd):gsub("!CH!",ch):gsub("!TS!",ts):gsub("!PROG!",prog):gsub("!N!",N)
end
local function run(kind,storm_on,label)
  wd(prog,0)
  local ok,thr=pcall(run_lua_code_in_new_thread,body_for(kind),{async=true})
  local storm=0
  while true do
    local p=rd(prog) or 0
    if p>=N then break end
    if storm_on then call(mk(37),pid,SIG,0,0,0,0) end
    storm=storm+1
    if storm>300000 then break end
    if not storm_on and storm>50000 and (rd(prog) or 0)==0 then break end
  end
  print(string.format("[%s] helper=%s storm=%d progress=%d alive=%s",label,tostring(ok),storm,rd(prog) or 0,tostring(call(mk(20),0,0,0,0,0,0))))
end
run("spin",true,"A")
run("churn",false,"B")
print("=== 772a DONE ===")
