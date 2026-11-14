-- CRASH_CLASS: SAFE
-- PROBE 1200d: calibrate how this loader reports syscall failure. 1200c saw ioctl(9999)=0 and
-- close(9999)=0, which cannot both be true if the return value is the kernel's rax, so before
-- concluding anything about syscall 54 this probe measures the *reporting*: for a set of calls
-- whose failure mode is not in doubt, print both the returned value and get_error_string().
print("=== PROBE 1200d: FAILURE REPORTING CALIBRATION ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function H(v) v=tn(v) if v<0 then v=v+18446744073709551616 end return string.format("%08X",v%4294967296) end
local function ES() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "<no-es>" end
local Z=uint64(0)
local sc_open,sc_close,sc_ioctl,sc_fcntl,sc_read=mk(5),mk(6),mk(54),mk(92),mk(3)
local pb=tn(memory.alloc(0x100)); local buf=tn(memory.alloc(0x200))
local function put(s) for i=1,#s do memory.write_byte(pb+i-1,string.byte(s,i)) end memory.write_byte(pb+#s,0) end
local function trial(label,fn)
    local ok,r=pcall(fn)
    local rv = ok and H(r) or "TRAP"
    print(string.format("  %-40s rv=%-10s err=%s",label,rv,ES()))
end
trial("open(/nonexistent)",function() return sc_open(U(pb),U(0),Z,Z,Z,Z) end)
put("/no/such/path")
trial("open(/no/such/path)",function() return sc_open(U(pb),U(0),Z,Z,Z,Z) end)
trial("close(9999)",function() return sc_close(U(9999),Z,Z,Z,Z,Z) end)
trial("fcntl(9999,F_GETFL)",function() return sc_fcntl(U(9999),U(3),U(0),Z,Z,Z) end)
trial("read(9999,buf,4)",function() return sc_read(U(9999),U(buf),U(4),Z,Z,Z) end)
trial("ioctl(9999,TCGETS,buf)",function() return sc_ioctl(U(9999),U(0x5413),U(buf),Z,Z,Z) end)
put("/dev/null")
local fdn=tn(sc_open(U(pb),U(2),Z,Z,Z,Z))
put("/dev/dmem0")
local fdd=tn(sc_open(U(pb),U(2),Z,Z,Z,Z))
print(string.format("[A] /dev/null fd=%d  /dev/dmem0 fd=%d",fdn,fdd))
trial("ioctl(null,TCGETS,buf)",function() return sc_ioctl(U(fdn),U(0x5413),U(buf),Z,Z,Z) end)
trial("ioctl(null,0xDEAD,buf)",function() return sc_ioctl(U(fdn),U(0xDEAD),U(buf),Z,Z,Z) end)
trial("ioctl(dmem0,TCGETS,buf)",function() return sc_ioctl(U(fdd),U(0x5413),U(buf),Z,Z,Z) end)
trial("fcntl(null,F_GETFL)",function() return sc_fcntl(U(fdn),U(3),U(0),Z,Z,Z) end)
trial("fcntl(null,F_SETFL 0)",function() return sc_fcntl(U(fdn),U(4),U(0),Z,Z,Z) end)
trial("read(null,buf,4)",function() return sc_read(U(fdn),U(buf),U(4),Z,Z,Z) end)
print(string.format("[Z] alive"))
print("=== DONE")
