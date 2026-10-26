-- CRASH_CLASS: LOW
-- PROBE 781a: is 557's return just arithmetic on its arguments?
--
-- 779a returned 16901 then 518 for two shapes; 780a returned 519..524 for six
-- identical shapes. A monotonic counter and a function of arg1 both fit. Print
-- the argument values and compare.
print("=== PROBE 781a: SYS 557 RELATION ===")
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
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
print(string.format("[A] page=%08X page2=%08X",page,page+0x1000))
local cases={
  {"page,1000", page, 0x1000},
  {"page+1000,1000", page+0x1000, 0x1000},
  {"page+10000,1000", page+0x10000, 0x1000},
  {"10000,1000", 0x10000, 0x1000},
  {"page,0", page, 0},
  {"0,1000", 0, 0x1000},
  {"page,1000 again", page, 0x1000},
}
for _,c in ipairs(cases) do
    local r=call(mk(557),c[2],c[3],0,0,0,0)
    local r2=nil
    if c[4] then r2=r end
    print(string.format("[B] 557(%-16s)=%s  hi16=%s",c[1],tostring(r),tostring(math.floor(to_num(c[2])/65536))))
end
print(string.format("[C] 557(page,1000,page2,800)=%s",tostring(call(mk(557),page,0x1000,page+0x1000,0x800,0,0))))
print(string.format("[D] 557(page,1000,0,800)=%s",tostring(call(mk(557),page,0x1000,0,0x800,0,0))))
print(string.format("[E] 560(page,1000)=%s 560(0,1000)=%s 560(page,0)=%s",tostring(call(mk(560),page,0x1000,0,0,0,0)),tostring(call(mk(560),0,0x1000,0,0,0,0)),tostring(call(mk(560),page,0,0,0,0,0))))
print("[F] alive="..tostring(call(mk(20),0,0,0,0,0,0)))
print("=== 781a DONE ===")
