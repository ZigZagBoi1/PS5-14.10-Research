-- CRASH_CLASS: HIGH
-- PROBE 600a: dump the first page of the /dev/gc and /dev/dmem0 mappings
print("=== PROBE 600a ===")
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
local sc_open,sc_close,sc_mmap,sc_munmap=mk(5),mk(6),mk(477),mk(73)
local path=tn(memory.alloc(0x100))
local function put(s) for i=1,#s do memory.write_byte(path+i-1,string.byte(s,i)) end memory.write_byte(path+#s,0) end
local function open_dev(p)
    put(p)
    local fd=tn(sc_open(U(path),U(2),Z,Z,Z,Z))
    if fd<0 then fd=tn(sc_open(U(path),U(0),Z,Z,Z,Z)) end
    return fd
end
local function rdq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if not ok then return "FAULT" end
    local h,l=0,0
    if type(v)=="table" and v.h then h,l=v.h,v.l else
        local n=tn(v); h=math.floor(n/4294967296); l=n%4294967296 end
    return string.format("%08X%08X",h,l)
end
local function dump(dev,off,n)
    local fd=open_dev(dev)
    print(string.format("[%s] fd=%d off=%X",dev,fd,off))
    if fd<0 then return end
    local r=tn(sc_mmap(Z,U(0x1000),U(3),U(1),U(fd),U(off)))
    if r==0 or r==-1 or r>0xFFFF000000000000 then
        print("  mmap failed ret="..r); sc_close(U(fd),Z,Z,Z,Z,Z); return
    end
    for i=0,n-1 do
        print(string.format("  +%03X %s",i*8,rdq(r+i*8)))
    end
    sc_munmap(U(r),U(0x1000),Z,Z,Z,Z)
    sc_close(U(fd),Z,Z,Z,Z,Z)
end
dump("/dev/gc",0,16)
dump("/dev/dce",0,8)
dump("/dev/dmem0",0,16)
dump("/dev/dmem0",0x1000,8)
print("[Z] alive")
