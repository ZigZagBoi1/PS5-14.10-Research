-- CRASH_CLASS: MODERATE
-- PROBE 595a: does 653 unlock 622? measure the same commands before and after
print("=== PROBE 595a ===")
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
local sc653,sc622=mk(653),mk(622)
local function call(c,arg1)
    for i=0,0x3FF do memory.write_dword(p+i*4,0x11223344) end
    local r=tn(sc622(U(c),arg1,U(p),U(0x1000),Z,Z))
    local nz=0
    for i=0,0x3FF do if tn(memory.read_dword(p+i*4))~=0x11223344 then nz=nz+1 end end
    return r,nz,tn(memory.read_dword(p))
end
print("[A] BEFORE 653")
for _,c in ipairs({0x100,0x101,0x104,0x110}) do
    local r,nz,b0=call(c,Z)
    print(string.format("  cmd %03X ret=%s nz=%d b0=%08X",c,r,nz,b0))
end
print("[B] 653")
local id=tn(sc653(U(0x100000),Z,Z,Z,Z))
print("[B] ret="..id)
print("[C] AFTER 653, arg1=0")
for _,c in ipairs({0x100,0x101,0x104,0x110}) do
    local r,nz,b0=call(c,Z)
    print(string.format("  cmd %03X ret=%s nz=%d b0=%08X",c,r,nz,b0))
end
print("[D] AFTER 653, arg1=id")
for _,c in ipairs({0x100,0x101,0x104,0x110}) do
    local r,nz,b0=call(c,U(id))
    print(string.format("  cmd %03X ret=%s nz=%d b0=%08X",c,r,nz,b0))
end
print("[E] alive")
