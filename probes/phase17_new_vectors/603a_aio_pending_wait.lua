-- CRASH_CLASS: HIGH
-- PROBE 603a: can an aio read stay pending, and does aio_multi_wait block on it?
print("=== PROBE 603a: AIO PENDING + WAIT ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={} for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t
end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end

local sc_sp=mk(135) local sc_create=mk(669) local sc_poll=mk(664)
local sc_del=mk(662) local sc_wait=mk(663) local sc_write=mk(4) local sc_tod=mk(116)

local sv=memory.alloc(8) wq(N(sv),uint64(0))
local r=pcall(function() return sc_sp(uint64(1),uint64(1),uint64(0),U(N(sv))) end)
local fda, fdb = rd(N(sv)), rd(N(sv)+4)
print(string.format("[A] socketpair fd_a=%d fd_b=%d", fda, fdb))

local now=memory.alloc(16)
local function ms()
    pcall(function() sc_tod(U(N(now)),uint64(0)) end)
    return N(memory.read_dword(N(now)))*1000 + math.floor(N(memory.read_dword(N(now)+4))/1000)
end

local buf=memory.alloc(0x4000)
local data=memory.alloc(0x100)
local out=memory.alloc(0x40)
local cell=memory.alloc(16)
local pollo=memory.alloc(0x40)

local function try(tag, layout, flags)
    for i=0,0xFC,4 do wd(N(data)+i,0) end
    if layout==1 then wd(N(data)+0,0) wd(N(data)+4,fda) wq(N(data)+8,uint64(0)) wq(N(data)+0x10,U(N(buf))) wq(N(data)+0x18,uint64(0x4000))
    elseif layout==2 then wd(N(data)+0,0) wd(N(data)+4,fda) wq(N(data)+8,U(N(buf))) wq(N(data)+0x10,uint64(0x4000)) wq(N(data)+0x18,uint64(0))
    elseif layout==3 then wd(N(data)+0,fda) wd(N(data)+4,0) wq(N(data)+8,U(N(buf))) wq(N(data)+0x10,uint64(0x4000)) wq(N(data)+0x18,uint64(0))
    else wd(N(data)+0,1) wd(N(data)+4,fda) wq(N(data)+8,U(N(buf))) wq(N(data)+0x10,uint64(0x4000)) wq(N(data)+0x18,uint64(0)) end
    wq(N(out),uint64(0))
    local ok,rv=pcall(function() return sc_create(U(flags),U(N(data)),uint64(1),uint64(1),U(N(out))) end)
    if not ok then print(string.format("  %s CREATE-FAIL",tag)) return nil end
    local id=rd(N(out))
    if N(rv)~=0 or id==nil then print(string.format("  %s ret=%s",tag,N(rv))) return nil end
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
    print(string.format("  %s id=%08X poll=%08X",tag,id,rd(N(pollo))))
    return id
end

print("[B] descriptor layouts (read from an empty socket)")
local id1=try("L1",1,1)
local id2=try("L2",2,1)
local id3=try("L3",3,1)
local id4=try("L4",4,1)

print("[C] wait on the last pending id with a 100 ms timeout")
local ids={}
for _,v in ipairs({id1,id2,id3,id4}) do if v then ids[#ids+1]=v end end
if #ids==0 then print("  no ids"); return end
for _,id in ipairs(ids) do
    wd(N(cell),id)
    wd(N(pollo),0xCCCCCCCC)
    wq(N(pollo)+8,uint64(0))
    local ts=memory.alloc(16)
    wq(N(ts)+0,uint64(0)) wq(N(ts)+8,uint64(100000000))
    local t0=ms()
    local ok,rv=pcall(function() return sc_wait(U(N(cell)),uint64(1),U(N(pollo)),U(N(ts)),uint64(0),uint64(0)) end)
    local dt=ms()-t0
    print(string.format("  id=%08X wait ret=%s dt=%dms out=%08X alive=true",id,N(rv),dt,rd(N(pollo))))
end

print("[D] feed the socket, poll again")
local msg=memory.alloc(0x100)
for i=0,0xFC,4 do wd(N(msg)+i,0x41414141) end
pcall(function() sc_write(U(fdb),U(N(msg)),uint64(0x100),uint64(0),uint64(0),uint64(0)) end)
for _,id in ipairs(ids) do
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
    print(string.format("  id=%08X poll=%08X",id,rd(N(pollo))))
end
print("[Z] alive")
