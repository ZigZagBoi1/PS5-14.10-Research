-- CRASH_CLASS: MODERATE
-- PROBE 1202a: if syscall 54 answers ENOTTY even for fd 9999 then it is not the FreeBSD ioctl
-- path at all, and the device drivers have never been reachable through it. Sony has its own
-- descriptor-based calls in the 6xx range; 615 was probed before for a stack leak but never
-- used as an fd oracle. A real descriptor-taking call must answer EBADF (9) for fd 9999, and
-- ENOTTY (25) or something else for a live node. Print per call so a death costs one line.
print("=== PROBE 1202a: WHICH SYSCALL TAKES (fd, cmd, arg) ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function ES() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "<no-es>" end
local Z=uint64(0)
local sc_open=mk(5)
local pb=tn(memory.alloc(0x100)); local buf=tn(memory.alloc(0x200))
local function put(s) for i=1,#s do memory.write_byte(pb+i-1,string.byte(s,i)) end memory.write_byte(pb+#s,0) end
put("/dev/dmem0")
local fd=tn(sc_open(U(pb),U(2),Z,Z,Z,Z))
print(string.format("[A] /dev/dmem0 fd=%d err=%s",fd,ES()))
for _,n in ipairs({615,616,617,618,619,620,614,621}) do
    for i=0,0x200-1,4 do memory.write_dword(buf+i,0xA5A5A5A5) end
    local sb=mk(n)
    pcall(function() return sb(U(9999),U(0x5413),U(buf),Z,Z,Z) end)
    local ebad=ES()
    for i=0,0x200-1,4 do memory.write_dword(buf+i,0xA5A5A5A5) end
    pcall(function() return sb(U(fd),U(0x5413),U(buf),Z,Z,Z) end)
    local edev=ES()
    local nz=false
    for i=0,0x200-1,4 do local ok,v=pcall(function() return tn(memory.read_dword(buf+i)) end) if ok and v~=0xA5A5A5A5 then nz=true end end
    print(string.format("  %d: badfd -> %s | dmem0 -> %s | wrote=%s",n,ebad,edev,tostring(nz)))
end
print("[Z] alive")
print("=== DONE")
