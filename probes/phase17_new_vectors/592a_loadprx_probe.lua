-- CRASH_CLASS: MODERATE
-- PROBE 592a: does 594 dynlib_load_prx reachable? plus 622 with a blockpool id
print("=== PROBE 592a ===")
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
local function W(addr,s)
    for i=1,#s do memory.write_byte(addr+i-1, string.byte(s,i)) end
    memory.write_byte(addr+#s,0)
end
local p=tn(memory.alloc(0x2000))
for i=0,0x1FF do memory.write_dword(p+i*4,0) end
local path=tn(memory.alloc(0x200))
W(path,"/system/common/lib/libkernel.sprx")
local sc594,sc653,sc622=mk(594),mk(653),mk(622)
print("[A] 594(NULL) start")
print("[A] ret="..tn(sc594(Z,Z,Z,Z)))
print("[B] 594(badpath) start")
local bogus=tn(memory.alloc(0x40))
W(bogus,"/nope/nothing.sprx")
print("[B] ret="..tn(sc594(U(bogus),Z,Z,Z)))
print("[C] 594(realpath) start")
print("[C] ret="..tn(sc594(U(path),Z,Z,Z)))
print("[D] 653 flags start")
local d=tn(sc653(U(0x100000),Z,Z,Z,Z))
print("[D] ret="..d)
print("[E] 622 cmd 0x100 with arg1=id")
if d==0 then
    memory.write_dword(p,0)
    print("[E] ret="..tn(sc622(U(0x100),U(d),U(p),U(0x1000),Z,Z)).." p0="..string.format("%08X",tn(memory.read_dword(p))))
else
    print("[E] skipped (no id)")
end
print("[F] alive")
