-- CRASH_CLASS: LOW
-- PROBE 597a: which /dev nodes will open for this process? ioctl surface hunt
print("=== PROBE 597a ===")
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
local sc_open,sc_close=mk(5),mk(6)
local buf=tn(memory.alloc(0x100))
local function put(s) for i=1,#s do memory.write_byte(buf+i-1,string.byte(s,i)) end memory.write_byte(buf+#s,0) end
local paths={
 "/dev/mem","/dev/kmem","/dev/io","/dev/pci","/dev/dtb","/dev/cpu0",
 "/dev/console","/dev/tty","/dev/ptmx","/dev/null","/dev/zero","/dev/random","/dev/urandom",
 "/dev/dce","/dev/gc","/dev/vce","/dev/icc","/dev/ajm","/dev/audio","/dev/vid","/dev/rmem",
 "/dev/sflash0","/dev/ssd0","/dev/da0","/dev/ada0","/dev/dmem0","/dev/dmem1","/dev/d3d","/dev/uvd",
 "/dev/sce_keymgr","/dev/umtx","/dev/rkncid","/dev/klog","/dev/ipcdev","/dev/hid",
 "/dev/uhid","/dev/sbl","/dev/usb","/dev/pfs","/dev/nvme0",
}
print("[A] open(O_RDWR)")
for _,pth in ipairs(paths) do
    put(pth)
    local fd=tn(sc_open(U(buf),U(2),Z,Z,Z,Z))
    if fd>=0 then
        print(string.format("  OPEN %-20s fd=%d",pth,fd))
        sc_close(U(fd),Z,Z,Z,Z,Z)
    else
        print(string.format("  no   %-20s ret=%d",pth,fd))
    end
end
print("[B] open(O_RDONLY) on the failures that matter")
for _,pth in ipairs({"/dev/mem","/dev/kmem","/dev/dce","/dev/gc","/dev/vce","/dev/icc","/dev/sflash0","/dev/ssd0"}) do
    put(pth)
    local fd=tn(sc_open(U(buf),U(0),Z,Z,Z,Z))
    print(string.format("  %-14s fd=%d",pth,fd))
    if fd>=0 then sc_close(U(fd),Z,Z,Z,Z,Z) end
end
print("[C] alive")
