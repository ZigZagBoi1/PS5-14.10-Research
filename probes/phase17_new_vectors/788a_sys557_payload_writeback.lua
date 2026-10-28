-- CRASH_CLASS: HIGH
-- PROBE 788a: 557 appears to write back into the 32-byte payload
--
-- 787b left payload[0]=11211E00 payload[1]=00000003 after two creates, and
-- those bytes started zeroed. Either the kernel writes into uap[0], or it
-- copies the wrapper back. Read every dword before and after one create.
print("=== PROBE 788a: 557 PAYLOAD WRITEBACK ===")
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
local function dump(tag,a,n)
    local t={}
    for i=0,n-1 do t[#t+1]=string.format("%08X",rd(a+i*4) or 0) end
    print(tag.." "..table.concat(t," "))
end
local pl=to_num(memory.alloc(0x200))
for i=0,0x200-4,4 do wd(pl+i,0) end
dump("[0] before",pl,12)
local r=call(mk(557),pl,0x1000,0,0,0,0)
dump("[A] after create ("..tostring(r)..")",pl,12)
local r2=call(mk(557),pl,0x1000,0,0,0,0)
dump("[B] after second ("..tostring(r2)..")",pl,12)
-- second buffer at a different address: is the writeback to uap[0] or to a fixed place?
local pl2=to_num(memory.alloc(0x200))
for i=0,0x200-4,4 do wd(pl2+i,0) end
local r3=call(mk(557),pl2,0x1000,0,0,0,0)
dump("[C] pl2 after ("..tostring(r3)..")",pl2,12)
dump("[C] pl again",pl,12)
for _,id in ipairs({r,r2,r3}) do
    if type(id)=="number" and id>0 then call(mk(558),id,0,0,0,0,0) end
end
dump("[D] after destroys pl",pl,12)
print("[E] alive="..tostring(call(mk(20),0,0,0,0,0,0)))
print("=== 788a DONE ===")
