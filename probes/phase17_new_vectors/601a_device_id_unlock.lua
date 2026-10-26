-- CRASH_CLASS: HIGH
-- PROBE 601a: 605 workaround8849 takes a device id; does it unlock 622/654?
print("=== PROBE 601a ===")
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
local sc605,sc622,sc654=mk(605),mk(622),mk(654)
local function probe(tag)
    for i=0,0xFF do memory.write_dword(p+i*4,0x11223344) end
    local r=tn(sc622(U(0x100),Z,U(p),U(0x400),Z,Z))
    local b0=tn(memory.read_dword(p))
    local r2=tn(sc654(U(0),U(0x10000),U(0),Z,U(p)))
    print(string.format("  %s 622ret=%s b0=%08X 654ret=%s",tag,r,b0,r2))
end
probe("baseline")
for _,id in ipairs({0x78026400,0x78028a00,0x78028300,0x19810000,0x3cc80700,0x780263ff,0x78026401}) do
    local r=tn(sc605(U(id),Z,Z,Z,Z,Z))
    print(string.format("[605] id=%08X ret=%s",id,r))
    probe(string.format("after %08X",id))
end
print("[Z] alive")
