-- CRASH_CLASS: HIGH
-- PROBE 627a: mdbg_service cmd 3/4 with real structs (read-shaped)
print("=== PROBE 627a: MDBG READ SHAPES ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function hex(a) return string.format("%08X_%08X",math.floor((a or 0)/4294967296),math.floor((a or 0)%4294967296)) end
-- ignore SIGSYS so an absent slot returns -1 instead of killing
local sa=memory.alloc(0x20)
wq(N(sa),uint64(1)) wd(N(sa)+8,0) wq(N(sa)+16,uint64(0))
pcall(function() mk(416)(uint64(12),uint64(N(sa)),uint64(0)) end)

local sc601=mk(601)
local st=memory.alloc(0x200)
local out=memory.alloc(0x2000)
for i=0,0x1FC,4 do wd(N(st)+i,0) end
for i=0,0x1FFC,4 do wd(N(out)+i,0) end
local target=0x1A4060000
local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local n=N((function() local o,v=pcall(function() return memory.read_dword(N(cnt)) end) return o and v or 0 end)())
for i=0,n-1 do
    local b=N(bufp)+i*72
    local s=rq(b) local e=rq(b+8) local p=rd(b+0x18)
    if p==5 and e and s and (e-s)>0x92C6B then target=s end
end
print(string.format("[A] target=%s",hex(target)))

local function shape(cmd,tag,a,b,c)
    for i=0,0x1FC,4 do wd(N(st)+i,0) end
    wd(N(st)+0,a); wd(N(st)+8,b); wd(N(st)+16,c)
    local o,rv=pcall(function() return sc601(uint64(cmd),uint64(N(st)),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    local t=o and string.format("%s",tostring(rv)) or "ERR"
    print(string.format("  [%s] cmd=%d a=%s b=%s c=%s -> %s",tag,cmd,hex(a),hex(b),hex(c),t))
    return o
end
local TO=N(target)
local A,B,Cc,CC,CD,CE=TO,0x40,N(out),TO+0x10,0x100,N(out)+0x800

local ok=true
ok=shape(3,"A",A,B,Cc); print(string.format("   out0=%s",hex(rq(N(out)))))
if ok then ok=shape(3,"B",B,A,Cc) end
if ok then ok=shape(3,"C",Cc,B,A) end
if ok then ok=shape(3,"D",A,A,Cc) end
if ok then ok=shape(3,"E",A,B,0) end
if ok then ok=shape(4,"F",A,B,Cc) end
if ok then ok=shape(4,"G",Cc,B,A) end
print(string.format("[B] out=%s %s",hex(rq(N(out))),hex(rq(N(out)+8))))
pcall(function() mk(416)(uint64(12),uint64(0),uint64(0)) end)
print("[Z] alive")
