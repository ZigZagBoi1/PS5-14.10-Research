-- CRASH_CLASS: HIGH
-- PROBE 596a: 13.60 body copies 4 bytes to arg1 -> arg1 is a pointer, not a command
print("=== PROBE 596a ===")
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
local p=tn(memory.alloc(0x1000))
local sc=mk(622)
local function reset() for i=0,0x3FF do memory.write_dword(p+i*4,0x11223344) end end
local function show(tag,r)
    print(string.format("  %s ret=%s p0=%08X p4=%08X",tag,r,tn(memory.read_dword(p)),tn(memory.read_dword(p+4))))
end
reset()
print("[A] 622(p,0,0,0,0,0)")
show("A",tn(sc(U(p),Z,Z,Z,Z,Z)))
reset()
print("[B] 622(p,0x100,0,0,0,0)")
show("B",tn(sc(U(p),U(0x100),Z,Z,Z,Z)))
reset()
print("[C] 622(p,0,0x100,0,0,0)")
show("C",tn(sc(U(p),Z,U(0x100),Z,Z,Z)))
reset()
print("[D] 622(p,p,0x100,0x1000,0,0)")
show("D",tn(sc(U(p),U(p),U(0x100),U(0x1000),Z,Z)))
reset()
print("[E] 622(0,p,0,0,0,0)")
show("E",tn(sc(Z,U(p),Z,Z,Z,Z)))
print("[F] alive")
