-- CRASH_CLASS: HIGH
-- PROBE 598a: raw ioctl command sweep on the openable devices; tally return codes
print("=== PROBE 598a ===")
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
local sc_open,sc_close,sc_ioctl=mk(5),mk(6),mk(54)
local path=tn(memory.alloc(0x100))
local buf=tn(memory.alloc(0x1000))
local function put(s) for i=1,#s do memory.write_byte(path+i-1,string.byte(s,i)) end memory.write_byte(path+#s,0) end
local function open_dev(p)
    put(p)
    local fd=tn(sc_open(U(path),U(2),Z,Z,Z,Z))
    if fd<0 then fd=tn(sc_open(U(path),U(0),Z,Z,Z,Z)) end
    return fd
end
local function sweep(p,lo,hi)
    local fd=open_dev(p)
    print(string.format("[%s] fd=%d",p,fd))
    if fd<0 then return end
    local tally={}
    for c=lo,hi do
        for i=0,0x1F do memory.write_dword(buf+i*4,0x11223344) end
        local r=tn(sc_ioctl(U(fd),U(c),U(buf),Z,Z,Z))
        tally[r]=(tally[r] or 0)+1
        if c%0x40==0 then print(string.format("  .. %X ret=%s",c,r)) end
    end
    for k,v in pairs(tally) do
        print(string.format("  TALLY ret=%s count=%d",k,v))
    end
    sc_close(U(fd),Z,Z,Z,Z,Z)
end
sweep("/dev/gc",0,0xFF)
sweep("/dev/dce",0,0xFF)
sweep("/dev/hid",0,0xFF)
sweep("/dev/dmem0",0,0xFF)
print("[Z] alive")
