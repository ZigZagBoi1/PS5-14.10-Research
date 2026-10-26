-- CRASH_CLASS: MODERATE
-- PROBE 593a: is the 653 id a device context for 622 / a pool arg for 654?
print("=== PROBE 593a ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={} for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t
end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local Z=uint64(0)
local p=tn(memory.alloc(0x2000))
for i=0,0x7FF do memory.write_dword(p+i*4,0) end
local sc653,sc654,sc622=mk(653),mk(654),mk(622)
print("[A] 653 open")
local id=tn(sc653(U(0x100000),Z,Z,Z,Z))
print("[A] id="..id)
print("[B] 622 with arg1=id, cmds 0x100-0x104")
for c=0x100,0x104 do
    memory.write_dword(p,0xdeadbeef)
    local r=tn(sc622(U(c),U(id),U(p),U(0x1000),Z,Z))
    print(string.format("  cmd %03X ret=%s buf0=%08X",c,r,tn(memory.read_dword(p))))
end
print("[C] 622 arg1=0 control")
memory.write_dword(p,0xdeadbeef)
print(string.format("  cmd 100 ret=%s buf0=%08X",tn(sc622(U(0x100),Z,U(p),U(0x1000),Z,Z)),tn(memory.read_dword(p))))
print("[D] 654 with id in slot 4")
for off=0,0x30000,0x10000 do
    memory.write_dword(p,0xdeadbeef)
    print(string.format("  off %X ret=%s",off,tn(sc654(U(off),U(0x10000),U(0),U(id),U(p)))))
end
print("[E] 654 no id")
print("  ret="..tn(sc654(U(0),U(0x10000),U(0),Z,U(p))))
print("[F] alive")
