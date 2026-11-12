-- CRASH_CLASS: LOW
-- PROBE 1200e: the devfs ioctl surface, measured with the only channel that works.
-- 1200d proved the numeric return is not rax (close(9999) reads 0 and sets EBADF), so every
-- earlier "rv" judgement about an ioctl is a judgement about a constant. This repeats the
-- sweep and records get_error_string() per command, with /dev/ugen0.2 as a positive control:
-- 1165a already saw EPERM and ENXIO there, so if the instrument works those must reappear.
print("=== PROBE 1200e: DEVFS IOCTL BY ERRNO ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function ES() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "<no-es>" end
local function NUM(s) local n=tostring(s):match("^(%d+)"); return n and tonumber(n) or -1 end
local Z=uint64(0)
local sc_open,sc_close,sc_ioctl=mk(5),mk(6),mk(54)
local pb=tn(memory.alloc(0x100)); local buf=tn(memory.alloc(0x200))
local function put(s) for i=1,#s do memory.write_byte(pb+i-1,string.byte(s,i)) end memory.write_byte(pb+#s,0) end
local devs={"/dev/null","/dev/dmem0","/dev/gc","/dev/dce","/dev/hid","/dev/usbctl","/dev/ugen0.2"}
for _,d in ipairs(devs) do
    put(d)
    local fd=tn(sc_open(U(pb),U(2),Z,Z,Z,Z))
    local e0=ES()
    if fd==0 then fd=tn(sc_open(U(pb),U(0),Z,Z,Z,Z)); e0=ES() end
    if fd<=0 then
        print(string.format("%-14s OPEN FAILED err=%s",d,e0))
    else
        local modal, mc = nil,0
        local seen={}
        local order={}
        for c=0,0xFF do
            for i=0,0x200-1,4 do memory.write_dword(buf+i,0xA5A5A5A5) end
            pcall(function() sc_ioctl(U(fd),U(c),U(buf),Z,Z,Z) end)
            local e=ES()
            if seen[e]==nil then seen[e]=0; order[#order+1]=e end
            seen[e]=seen[e]+1
        end
        local parts={}
        for _,e in ipairs(order) do parts[#parts+1]=string.format("%s x%d",e,seen[e]) end
        print(string.format("%-14s fd=%d  %s",d,fd,table.concat(parts," | ")))
        sc_close(U(fd),Z,Z,Z,Z,Z)
    end
end
print("[Z] alive")
print("=== DONE")
