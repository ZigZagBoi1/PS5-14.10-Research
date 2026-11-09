-- CRASH_CLASS: HIGH
-- PROBE 594a: 653 seems to install the device context that 622 demanded; sweep 622 cmds
print("=== PROBE 594a ===")
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
local sc653,sc622=mk(653),mk(622)
print("[A] 653 first")
local id=tn(sc653(U(0x100000),Z,Z,Z,Z))
print("[A] id="..id)
local function clear() for i=0,0x7FF do memory.write_dword(p+i*4,0x11223344) end end
local function scan()
    local nz,kern=0,0
    for i=0,0x7FF do
        local v=tn(memory.read_dword(p+i*4))
        if v~=0x11223344 then
            nz=nz+1
            local hi=math.floor(v/65536)
            if v>0xFFFF8000 and v<=0xFFFFFFFF then kern=kern+1 end
        end
    end
    return nz,kern
end
print("[B] sweep 622 cmds 0x100-0x11F")
for c=0x100,0x11F do
    clear()
    print(string.format("  cmd %03X start",c))
    local r=tn(sc622(U(c),U(id),U(p),U(0x1000),Z,Z))
    local nz,kern=scan()
    print(string.format("  cmd %03X ret=%s written=%d kernhi=%d b0=%08X b4=%08X",c,r,nz,kern,
        tn(memory.read_dword(p)),tn(memory.read_dword(p+4))))
end
print("[C] alive")
