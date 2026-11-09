-- CRASH_CLASS: HIGH
-- PROBE 599a: how far does the dmem0 physical window reach? and do gc/dce mmap?
print("=== PROBE 599a ===")
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
    if not ok then return nil end
    local h,l=0,0
    if type(v)=="table" and v.h then h,l=v.h,v.l else
        local n=tn(v); h=math.floor(n/4294967296); l=n%4294967296 end
    return string.format("%08X%08X",h,l)
end
local function try_map(fd,off,label)
    local r=tn(sc_mmap(Z,U(0x4000),U(3),U(1),U(fd),U(off)))
    if r==0 or r==-1 or r>0xFFFF000000000000 then
        print(string.format("  %-22s off=%X mmap ret=%s",label,off,r))
        return
    end
    local q0,q1=rdq(r),rdq(r+8)
    print(string.format("  %-22s off=%X va=%X q0=%s q1=%s",label,off,r,tostring(q0),tostring(q1)))
    sc_munmap(U(r),U(0x4000),Z,Z,Z,Z)
end
local dmem=open_dev("/dev/dmem0")
print("[A] dmem0 fd="..dmem)
if dmem>=0 then
    for _,off in ipairs({0x0,0x1000,0x100000,0x1000000,0x4000000,0x10000000,0x20000000,0x40000000,0x80000000,0xC0000000}) do
        try_map(dmem,off,"dmem0")
    end
end
local dm1=open_dev("/dev/dmem1")
print("[B] dmem1 fd="..dm1)
if dm1>=0 then
    for _,off in ipairs({0x0,0x1000,0x1000000,0x40000000}) do try_map(dm1,off,"dmem1") end
end
for _,dev in ipairs({"/dev/gc","/dev/dce","/dev/hid"}) do
    local fd=open_dev(dev)
    print("["..dev.."] fd="..fd)
    if fd>=0 then
        for _,off in ipairs({0x0,0x1000,0x10000}) do try_map(fd,off,dev) end
        sc_close(U(fd),Z,Z,Z,Z,Z)
    end
end
print("[Z] alive")
