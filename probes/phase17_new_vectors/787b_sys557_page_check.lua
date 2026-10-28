-- CRASH_CLASS: HIGH
-- PROBE 787b: dword-level check of the target page after a 557 create
print("=== PROBE 787b: 557 PAGE CHECK ===")
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
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local pl=to_num(memory.alloc(0x100)); local tgt=to_num(memory.alloc(0x1000))
for i=0,0x1000-4,4 do wd(tgt+i,0xDEADBEEF) end
for i=0,0x100-8,8 do wq(pl+i,0) end
local function scan()
    local hits=0
    for i=0,0x1000-4,4 do if rd(tgt+i)~=0xDEADBEEF then hits=hits+1 end end
    return hits
end
print(string.format("[0] before: d0=%08X d1=%08X scan=%d",rd(tgt),rd(tgt+4),scan()))
-- case with no pointer at all
local r0=call(mk(557),pl,0x1000,0,0,0,0)
for i=1,2000 do call(mk(20),0,0,0,0,0,0) end
print(string.format("[A] zeros create=%s scan=%d d0=%08X alive=%s",tostring(r0),scan(),rd(tgt),tostring(call(mk(20),0,0,0,0,0,0))))
if type(r0)=="number" and r0>0 then print("[A] destroy="..tostring(call(mk(558),r0,0,0,0,0,0))) end
-- case with the page in slot 0
for i=0,0x1000-4,4 do wd(tgt+i,0xDEADBEEF) end
wq(pl,tgt)
local r1=call(mk(557),pl,0x1000,0,0,0,0)
for i=1,2000 do call(mk(20),0,0,0,0,0,0) end
print(string.format("[B] slot0 create=%s scan=%d d0=%08X d1=%08X alive=%s",tostring(r1),scan(),rd(tgt),rd(tgt+4),tostring(call(mk(20),0,0,0,0,0,0))))
if type(r1)=="number" and r1>0 then print("[B] destroy="..tostring(call(mk(558),r1,0,0,0,0,0))) end
-- does the payload itself get modified? it is copied into the kernel, but check
print(string.format("[C] payload[0]=%08X payload[1]=%08X",rd(pl),rd(pl+4)))
print("=== 787b DONE ===")
