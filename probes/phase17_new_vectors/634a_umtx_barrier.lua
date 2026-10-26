-- CRASH_CLASS: MODERATE
-- PROBE 634a: a ROP chain that waits on _umtx_op(WAIT) and resumes on one WAKE
print("=== PROBE 634a: UMTX BARRIER IN A ROP CHAIN ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("[A] pid=%d",pid))
local W=memory.alloc(8)
wq(N(W),uint64(0))
local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x10000})
local sc454=mk(454)
c:push_syscall_with_ret(sc454, U(N(W)), uint64(2), uint64(0))
local gp=mk(20)
for i=1,20 do c:push_syscall_with_ret(gp) end
print("[B] chain built")
local t=thread:new(c)
t:run(true)
print("[C] launched")
for i=1,600000 do local x=i end
local rets=c.retval_addr
local n=#rets
local last=rets[n] and N(memory.read_qword(rets[n])) or -1
print(string.format("[D] before wake last_ret=%s",tostring(last)))
wq(N(W),uint64(1))
local o,r=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[E] wake rv=%s",tostring(o and r or "err")))
t:join()
local after=rets[n] and N(memory.read_qword(rets[n])) or -1
print(string.format("[F] after wake last_ret=%s (pid=%d)",tostring(after),pid))
print("[Z] alive")
