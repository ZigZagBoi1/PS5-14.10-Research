-- CRASH_CLASS: LOW
-- PROBE 1200b: 1200a showed the return code is *uniform* across 17 first-dwords for all 256
-- commands on dmem0/gc/dce/hid, and that no command wrote a byte. This probe prints the actual
-- constant, per device, and adds /dev/null and /dev/zero as controls: if syscall 54 answers
-- "not supported" for a device that certainly has no ioctl, then a uniform error across the
-- Sony device nodes says nothing about the drivers and everything about syscall 54.
print("=== PROBE 1200b: IOCTL RETURN CONSTANT ===")
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
local function H(v)
    v=tn(v)
    if v<0 then v=v+18446744073709551616 end
    local lo=v%4294967296
    return string.format("%08X",lo)
end
local Z=uint64(0)
local sc_open,sc_close,sc_ioctl=mk(5),mk(6),mk(54)
local path=tn(memory.alloc(0x100))
local buf=tn(memory.alloc(0x200))
local function put(s) for i=1,#s do memory.write_byte(path+i-1,string.byte(s,i)) end memory.write_byte(path+#s,0) end
local cmds={0,1,2,3,4,8,0x10,0x20,0x40,0x80,0xC0,0xFF}
local devs={"/dev/null","/dev/zero","/dev/dmem0","/dev/gc","/dev/dce","/dev/hid"}
for _,d in ipairs(devs) do
    put(d)
    local fd=tn(sc_open(U(path),U(2),Z,Z,Z,Z))
    if fd<0 then fd=tn(sc_open(U(path),U(0),Z,Z,Z,Z)) end
    local parts={}
    for _,c in ipairs(cmds) do
        for i=0,0x200-1,4 do memory.write_dword(buf+i,0xA5A5A5A5) end
        local ok,r=pcall(function() return sc_ioctl(U(fd),U(c),U(buf),Z,Z,Z) end)
        parts[#parts+1]=string.format("%02X:%s",c, ok and H(r) or "TRAP")
    end
    print(string.format("%-16s fd=%d  %s",d,fd,table.concat(parts," ")))
    sc_close(U(fd),Z,Z,Z,Z,Z)
end
-- control: the loader's own stdin/stdout, which are real vnode fds
for _,fdv in ipairs({0,1,2}) do
    local parts={}
    for _,c in ipairs({0x5413,0x5401,0x5409,0x1,0x8}) do
        local ok,r=pcall(function() return sc_ioctl(U(fdv),U(c),U(buf),Z,Z,Z) end)
        parts[#parts+1]=string.format("%X:%s",c, ok and H(r) or "TRAP")
    end
    print(string.format("fd=%-16d %s",fdv,table.concat(parts," ")))
end
print("[Z] alive")
print("=== DONE")
