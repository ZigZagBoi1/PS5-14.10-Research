-- CRASH_CLASS: MODERATE
-- PROBE 657a: thr_get_ucontext (634) / thr_set_ucontext (635) with a real tid
print("=== PROBE 657a: THR UCONTEXT GET/SET ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local TB=memory.alloc(8); wq(N(TB),uint64(0))
pcall(function() mk(432)(U(N(TB)),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local tid=rd(N(TB)) or 0
print(string.format("[A] tid=%s",tostring(tid)))
local BUF=memory.alloc(0x400)
local function z() for k=0,0x3F8,8 do wq(N(BUF)+k,uint64(0)) end end
local SH={
 {"634(tid,buf)",634,function() return {U(tid),U(N(BUF)),U(0),U(0),U(0),U(0)} end},
 {"634(tid,buf,0x400)",634,function() return {U(tid),U(N(BUF)),U(0x400),U(0),U(0),U(0)} end},
 {"634(buf,tid)",634,function() return {U(N(BUF)),U(tid),U(0),U(0),U(0),U(0)} end},
 {"634(0,buf)",634,function() return {U(0),U(N(BUF)),U(0),U(0),U(0),U(0)} end},
 {"635(tid,buf)",635,function() return {U(tid),U(N(BUF)),U(0),U(0),U(0),U(0)} end},
 {"635(buf,tid)",635,function() return {U(N(BUF)),U(tid),U(0),U(0),U(0),U(0)} end},
}
for _,s in ipairs(SH) do
  z()
  local a=s[3]()
  local ok,rv=pcall(function() return mk(s[2])(a[1],a[2],a[3],a[4],a[5],a[6]) end)
  local nz,kern=0,0
  for k=0,0x3F8,8 do
    local v=rd(N(BUF)+k) or 0
    if v~=0 then nz=nz+1; local hi=math.floor(v/4294967296); if hi>=0xFFFF8000 then kern=kern+1 end end
  end
  print(string.format("[B] %s ret=%s nz=%d kern=%d",s[1],ok and tostring(N(rv)) or "ERR",nz,kern))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
