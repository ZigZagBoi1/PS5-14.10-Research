-- CRASH_CLASS: MODERATE
-- PROBE 1200a: the 674 lesson applied to devfs ioctls. For every command in 0..0xFF and a
-- ladder of candidate "magic" dwords placed at buffer offset 0, record the return code and
-- whether the kernel wrote anything back. A command that behaves differently for different
-- first dwords is a gated command: the sweeps that came before this one always supplied the
-- same filler (0xA5 or 0x11223344), which is exactly how 674 looked dead for weeks.
print("=== PROBE 1200a: IOCTL MAGIC DIFFERENTIAL ===")
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
local BUFSZ=0x200
local path=tn(memory.alloc(0x100))
local buf=tn(memory.alloc(BUFSZ))
local function put(s) for i=1,#s do memory.write_byte(path+i-1,string.byte(s,i)) end memory.write_byte(path+#s,0) end
local function open_dev(p)
    put(p)
    local fd=tn(sc_open(U(path),U(2),Z,Z,Z,Z))
    if fd<0 then fd=tn(sc_open(U(path),U(0),Z,Z,Z,Z)) end
    return fd
end
local magics={0x00000000,0x00000001,0x00000002,0x00000010,0x00000100,0x00001000,0x00010000,
              0x00040000,0x00100000,0x00400000,0x01000000,0x10000000,0x40000000,0x80000000,
              0xDEADBEEF,0x13371337,0xFFFFFFFF}
local sample={0,4,8,0x20,0x40,0x80,0x100,0x180}
local function sweep(dev,lo,hi)
    local fd=open_dev(dev)
    print(string.format("[%s] fd=%d",dev,fd))
    if fd<0 then return 0 end
    local gated=0
    for c=lo,hi do
        local sig={}
        local rvs={}
        local wrote=false
        for _,m in ipairs(magics) do
            for i=0,BUFSZ-1,4 do memory.write_dword(buf+i,0xA5A5A5A5) end
            memory.write_dword(buf,m)
            local ok,r=pcall(function() return tn(sc_ioctl(U(fd),U(c),U(buf),Z,Z,Z)) end)
            if not ok then r=-999 end
            rvs[#rvs+1]=r
            local diff=false
            local ok0,v0=pcall(function() return tn(memory.read_dword(buf)) end)
            if ok0 and v0~=m then diff=true end
            for _,o in ipairs(sample) do
                if o~=0 then
                local ok2,v=pcall(function() return tn(memory.read_dword(buf+o)) end)
                if ok2 and v~=0xA5A5A5A5 then diff=true end
                end
            end
            if diff then wrote=true end
            sig[#sig+1]=string.format("%X:%s%s",m,r,diff and "*" or "")
        end
        local uniform=true
        for i=2,#rvs do if rvs[i]~=rvs[1] then uniform=false end end
        if (not uniform) or wrote then
            gated=gated+1
            print(string.format("  [G] cmd=%02X %s",c,table.concat(sig," ")))
        end
        if c%0x40==0 then print(string.format("  .. %02X",c)) end
    end
    sc_close(U(fd),Z,Z,Z,Z,Z)
    print(string.format("[%s] differing-or-writing commands=%d",dev,gated))
    return gated
end
sweep("/dev/dmem0",0,0xFF)
sweep("/dev/gc",0,0xFF)
sweep("/dev/dce",0,0xFF)
sweep("/dev/hid",0,0xFF)
print(string.format("[Z] alive=%d",tn(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("=== DONE")
