-- CRASH_CLASS: MEDIUM
-- PROBE 1209a: syscall 636 writes a caller-supplied array into a static kernel array.
-- Static (13.60 body 0x6be4d0): rbx=uap; gate call 0x608f90([td+0x140]) tests bit 62 of
-- [rdi+0x60] and returns eax; eax==0 -> return 1 (EPERM). Then
--   ecx = uap[8] - 0x201 ; if (u32)ecx < 0xfffffe00 -> EINVAL   (i.e. count must be 1..0x200)
--   r15 = uap[8]<<4 ; r14 = uap[0] ; copyin(r14 -> global 0x3915920, r15)
--   global_count = uap[8]
-- So the array size is 0x200 entries x 16. This probe asks two things: does the bit-62 gate
-- let us through, and if it does, can we observe our own bytes via 638's table search.
print("=== PROBE 1209a: sys 636 timezone table load ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function H(v) v=tn(v) if v<0 then v=v+18446744073709551616 end return string.format("%08X",v%4294967296) end
local function ES() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "<no-es>" end
local Z=uint64(0)
local sc636,sc638=mk(636),mk(638)
local tab=tn(memory.alloc(0x2000))
for i=0,0x1FF do
    memory.write_qword(tab+i*16,uint64(string.format("0x%08X",i)))
    memory.write_dword(tab+i*16+12,0xAAAA0000+i)
end
local o8=tn(memory.alloc(0x40)); local o16=tn(memory.alloc(0x40)); local o4=tn(memory.alloc(0x40))
local function trial(label,fn)
    local ok,r=pcall(fn)
    print(string.format("  %-34s rv=%-10s err=%s",label,ok and H(r) or "TRAP",ES()))
end
print("[P0] 636(1, tab)")
trial("636 count=1",function() return sc636(U(1),U(tab),Z,Z,Z,Z) end)
print("[P1] 636(0x200, tab) full load")
trial("636 count=0x200",function() return sc636(U(0x200),U(tab),Z,Z,Z,Z) end)
print("[P2] 636(0x201, tab) expect EINVAL")
trial("636 count=0x201",function() return sc636(U(0x201),U(tab),Z,Z,Z,Z) end)
print("[P3] 636(0, tab) expect EINVAL")
trial("636 count=0",function() return sc636(U(0),U(tab),Z,Z,Z,Z) end)
print("[P4] 638 read-back key=3")
trial("638 key=3",function() return sc638(U(3),U(o8),U(o16),U(o4),Z,Z) end)
local function dw(p) return memory.read_dword(p):tonumber() end
local function qw(p) local h=memory.read_dword(p+4):tonumber() local l=memory.read_dword(p):tonumber() return string.format("%08X%08X",h,l) end
print(string.format("  o8=%s o16[0]=%s o16[1]=%s o4=%08X",qw(o8),qw(o16),qw(o16+8),dw(o4)))
print("[P5] 638 key=0x100")
trial("638 key=0x100",function() return sc638(U(0x100),U(o8),U(o16),U(o4),Z,Z) end)
print(string.format("  o8=%s o16[0]=%s o16[1]=%s o4=%08X",qw(o8),qw(o16),qw(o16+8),dw(o4)))
print("[Z] alive")
print("=== DONE")
