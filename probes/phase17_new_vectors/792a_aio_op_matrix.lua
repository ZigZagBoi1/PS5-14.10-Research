-- CRASH_CLASS: HIGH
-- PROBE 792a: the aio descriptor's +0x24 operation field, values beyond 3
--
-- 752a tested op 0..3 on a socket: 0 and 1 go in flight, 2 and 3 never start.
-- If op indexes a handler table without a bound check, values past the end
-- reach garbage. One create per op, file fd, valid buffer, polled each time.
print("=== PROBE 792a: AIO OP MATRIX ===")
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
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local D=to_num(memory.alloc(0x200)); local buf=to_num(memory.alloc(0x1000))
local res=to_num(memory.alloc(0x100)); local ids=to_num(memory.alloc(0x40)); local out=to_num(memory.alloc(0x40))
-- open a file fd
local path=to_num(memory.alloc(0x100))
local function wstr(a,s) for i=1,#s do pcall(function() memory.write_byte(a+i-1,string.byte(s,i)) end) end pcall(function() memory.write_byte(a+#s,0) end) end
wstr(path,"/savedata0/thread.lua")
local fd=call(mk(5),path,0,0,0,0,0)
print("[0] fd="..tostring(fd).." alive="..alive())
local function clip(v) if v>0x10 then v=0x10 end return v end
for op=0,0x10 do
    zero(D,0x200); zero(res,0x100); zero(out,0x40)
    wq(D+0x00,0); wq(D+0x08,16); wq(D+0x10,buf); wq(D+0x18,res)
    wd(D+0x20,fd); wd(D+0x24,op)
    local cr=call(mk(669),0x1001,D,1,1,out,0)
    local id=rd(out) or 0
    local st=nil
    if cr==0 and id>0 then
        zero(res,0x100); wd(ids,id)
        call(mk(664),ids,1,res,0,0,0)
        st=rd(res)
        -- cancel so nothing stays pending, then delete
        call(mk(666),ids,1,res,0,0,0)
        zero(res,0x100); wd(ids,id)
        call(mk(662),ids,1,res,0,0,0)
    end
    print(string.format("[A] op=%02X create=%s id=%08X state=%s alive=%s",op,tostring(cr),id,tostring(st),alive()))
    if cr=="ERR" then break end
end
print("[E] final alive="..alive())
print("=== 792a DONE ===")
