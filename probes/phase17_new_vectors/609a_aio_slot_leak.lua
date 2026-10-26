-- CRASH_CLASS: HIGH
-- PROBE 609a: does deleting a request mid-completion leak a slot?
print("=== PROBE 609a: SLOT LEAK ===")
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

local sc_sp,sc_create,sc_poll,sc_del,sc_write=mk(135),mk(669),mk(664),mk(662),mk(4)
local sv=memory.alloc(8) wq(N(sv),uint64(0))
pcall(function() sc_sp(uint64(1),uint64(1),uint64(0),U(N(sv))) end)
local fda,fdb=rd(N(sv)),rd(N(sv)+4)
print(string.format("[A] fd_a=%d fd_b=%d",fda,fdb))

local buf=memory.alloc(0x2000)
local data=memory.alloc(0x100)
local out=memory.alloc(0x40)
local cell=memory.alloc(16)
local pollo=memory.alloc(0x40)
local msg=memory.alloc(0x200)
for i=0,0x1FC,4 do wd(N(msg)+i,0x41424344) end

local function make()
    for i=0,0xFC,4 do wd(N(data)+i,0) end
    wd(N(data)+0,fda) wd(N(data)+4,0)
    wq(N(data)+8,U(N(buf))) wq(N(data)+0x10,uint64(0x40)) wq(N(data)+0x18,uint64(0))
    wq(N(out),uint64(0))
    local ok,rv=pcall(function() return sc_create(uint64(1),U(N(data)),uint64(1),uint64(1),U(N(out))) end)
    if not ok then return nil, "pcall" end
    if N(rv)~=0 then return nil, N(rv) end
    return rd(N(out)), 0
end
local function del(id)
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_del(U(N(cell)),uint64(1),U(N(pollo))) end)
    return rd(N(pollo))
end

local ROUNDS=400
local made, failed = 0, 0
for it=1,ROUNDS do
    local id,rv=make()
    if not id then
        print(string.format("  create failed at round %d rv=%s",it,tostring(rv)))
        failed=failed+1
        if failed>3 then break end
    else
        made=made+1
        pcall(function() sc_write(U(fdb),U(N(msg)),uint64(0x40),uint64(0),uint64(0),uint64(0)) end)
        local s=del(id)
        if s~=0 then print(string.format("  r%d delete st=%08X",it,s)) end
    end
    if it%50==0 then
        local probe_id = make()
        print(string.format("  r%d made=%d health=%s",it,made,probe_id and string.format("%08X",probe_id) or "FAIL"))
        if probe_id then del(probe_id) end
    end
end
print(string.format("[B] made=%d failed=%d",made,failed))
print("[Z] alive")
