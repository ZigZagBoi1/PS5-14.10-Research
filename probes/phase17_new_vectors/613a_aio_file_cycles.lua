-- CRASH_CLASS: MODERATE
-- PROBE 613a: 200 create/poll/delete cycles reading a FILE (no socket back-pressure)
print("=== PROBE 613a: FILE CYCLES ===")
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

local sc_open,sc_create,sc_poll,sc_del,sc_read=mk(5),mk(669),mk(664),mk(662),mk(3)
local path=memory.alloc(64)
local p="/app0/eboot.bin"
for i=1,#p do pcall(function() memory.write_byte(N(path)+i-1,string.byte(p,i)) end) end
pcall(function() memory.write_byte(N(path)+#p,0) end)
local ok,fd=pcall(function() return sc_open(U(N(path)),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
fd=N(fd)
print(string.format("[A] open=%s fd=%d",tostring(ok),fd))

local buf=memory.alloc(0x4000)
local data=memory.alloc(0x100)
local out=memory.alloc(0x40)
local cell=memory.alloc(16)
local pollo=memory.alloc(0x40)

local function make(off,nb)
    for i=0,0xFC,4 do wd(N(data)+i,0) end
    wd(N(data)+0,fd) wd(N(data)+4,0)
    wq(N(data)+8,U(N(buf))) wq(N(data)+0x10,uint64(nb)) wq(N(data)+0x18,uint64(off))
    wq(N(out),uint64(0))
    local ok2,rv=pcall(function() return sc_create(uint64(1),U(N(data)),uint64(1),uint64(1),U(N(out))) end)
    if not ok2 or N(rv)~=0 then return nil end
    return rd(N(out))
end
local function poll(id)
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
    return rd(N(pollo))
end
local function del(id)
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_del(U(N(cell)),uint64(1),U(N(pollo))) end)
    return rd(N(pollo))
end

if fd<0 then print("[!] open failed"); return end
print("[B] cycles")
local okn,badn=0,0
for it=1,200 do
    local id=make(0,0x40)
    if not id then print(string.format("  r%d CREATE-FAIL",it)); break end
    local p=poll(id)
    local s=del(id)
    if s==0 then okn=okn+1 else badn=badn+1; print(string.format("  r%d poll=%08X del=%08X",it,p,s)) end
    if it%20==0 then print(string.format("  r%d ok=%d bad=%d",it,okn,badn)) end
end
print(string.format("[C] ok=%d bad=%d",okn,badn))
print("[Z] alive")
