-- CRASH_CLASS: LOW
-- PROBE 1200c: is syscall 54 a real ioctl on 14.10? 1200b found rv=0 for every command on
-- every device, including TCGETS on a tty fd, which is the signature of a stub. This probe
-- removes the ambiguity: a real ioctl must (a) reject a bad descriptor, (b) touch the
-- argument buffer for TCGETS, and (c) reject an unreadable/writable buffer for a command that
-- copies in or out.
print("=== PROBE 1200c: IS IOCTL 54 REAL ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function H(v) v=tn(v) if v<0 then v=v+18446744073709551616 end return string.format("%08X",v%4294967296) end
local Z=uint64(0)
local sc_open,sc_close,sc_ioctl,sc_fcntl=mk(5),mk(6),mk(54),mk(92)
local path=tn(memory.alloc(0x100))
local buf=tn(memory.alloc(0x200))
local function put(s) for i=1,#s do memory.write_byte(path+i-1,string.byte(s,i)) end memory.write_byte(path+#s,0) end
local function fill() for i=0,0x200-1,4 do memory.write_dword(buf+i,0xA5A5A5A5) end end
local function changed()
    local n=0
    for i=0,0x200-1,4 do local ok,v=pcall(function() return tn(memory.read_dword(buf+i)) end) if ok and v~=0xA5A5A5A5 then n=n+1 end end
    return n
end
local function call(label,fd,cmd,ptr)
    fill()
    local ok,r=pcall(function() return sc_ioctl(U(fd),U(cmd),U(ptr),Z,Z,Z) end)
    print(string.format("  %-34s rv=%s written-dwords=%d",label, ok and H(r) or "TRAP", changed()))
end
put("/dev/null")
local fdnull=tn(sc_open(U(path),U(2),Z,Z,Z,Z))
put("/dev/dmem0")
local fddmem=tn(sc_open(U(path),U(2),Z,Z,Z,Z))
print(string.format("[A] fds null=%d dmem0=%d",fdnull,fddmem))
call("null  TCGETS   0x5413",fdnull,0x5413,buf)
call("null  TIOCGWINSZ 0x5413/0x5414",fdnull,0x5414,buf)
call("null  cmd 0",fdnull,0,buf)
call("dmem0 cmd 0",fddmem,0,buf)
call("dmem0 cmd 0x5413",fddmem,0x5413,buf)
call("BADFD 9999 TCGETS",9999,0x5413,buf)
call("BADFD -1   cmd 0", -1,0,buf)
call("null  TCGETS ptr=0",fdnull,0x5413,0)
call("null  TCGETS ptr=kernel",fdnull,0x5413,0xFFFF800000000000)
call("dmem0 TCGETS ptr=0",fddmem,0x5413,0)
-- control: fcntl on the same descriptors, which must produce a real answer
local okf,rf=pcall(function() return sc_fcntl(U(fdnull),U(3),U(0),Z,Z,Z) end)   -- F_GETFL
print(string.format("[B] fcntl(null,F_GETFL)=%s", okf and H(rf) or "TRAP"))
local okg,rg=pcall(function() return sc_fcntl(U(fddmem),U(3),U(0),Z,Z,Z) end)
print(string.format("[B] fcntl(dmem0,F_GETFL)=%s", okg and H(rg) or "TRAP"))
-- control: a syscall we know is real, with a bad fd
local okr,rr=pcall(function() return mk(6)(U(9999),Z,Z,Z,Z,Z) end)                  -- close(9999)
print(string.format("[C] close(9999)=%s", okr and H(rr) or "TRAP"))
print("[Z] alive")
print("=== DONE")
