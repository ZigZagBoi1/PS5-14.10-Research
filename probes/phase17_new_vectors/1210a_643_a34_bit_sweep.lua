-- CRASH_CLASS: MEDIUM
-- PROBE 1210a: syscall 643 ORs a caller-supplied 32-bit mask into proc+0xa34 with no gate.
-- Static 13.60: body 0xa37660 = mov rbx,rsi; mov esi,[rsi]; mov r14,rdi; lea rdi,[name];
-- call 0x8ac1d410 (log); mov eax,[rbx]; mov rcx,[r14+8]; or dword [rcx+0xa34],eax; xor eax,eax; ret
-- Readers found in the image: only bits 0,1,2 are ever consumed
--   0x2cc0c0 mov eax,[proc+0xa34]; test al,1 -> jne error ; test al,2 -> path switch
--   0x3cb8ec test byte [proc+0xa34],1 -> jne skip ; 0x3cb94d bit1 and 0x3cb963 bit2 copied into an object
-- This probe accumulates one bit per round and re-runs a fixed oracle battery, printing any
-- observable difference. OR-only, so a change is attributable to the bit just added.
print("=== PROBE 1210a: sys 643 proc+0xa34 bit sweep ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function H(v) v=tn(v) if v<0 then v=v+18446744073709551616 end return string.format("%08X",v%4294967296) end
local function ES() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "<no-es>" end
local Z=uint64(0)
local sc643,sc608,sc674,sc547,sc638,sc605,sc602,sc607=mk(643),mk(608),mk(674),mk(547),mk(638),mk(605),mk(602),mk(607)
local rec=tn(memory.alloc(0x1A8)); local vq=tn(memory.alloc(0x100)); local m47=tn(memory.alloc(0x40))
local tz8=tn(memory.alloc(0x20)); local tz16=tn(memory.alloc(0x20)); local tz4=tn(memory.alloc(0x20))
local pb=tn(memory.alloc(0x40)); local mag=tn(memory.alloc(0x10))
local path="/tmp/xx"
for i=1,#path do memory.write_byte(pb+i-1,string.byte(path,i)) end
memory.write_byte(pb+#path,0)
memory.write_dword(mag,0x78026400)
memory.write_qword(vq,uint64("0x0000000310DC4000"))
local function put(page,tag,f,...)
    local ok,r=pcall(f)
    page[#page+1]=string.format("%s=%s/%s",tag,ok and H(r) or "TRAP",ES())
end
local function battery()
    local r={}
    put(r,"608",function() memory.write_qword(rec,uint64("0x1A8")) memory.write_dword(rec+8,0x13) return sc608(U(0x13),U(1),U(rec),Z,Z,Z) end)
    put(r,"674",function() return sc674(U(vq),U(0x1000),U(0),Z,Z,Z) end)
    put(r,"547",function() return sc547(U(0x310DC4000),U(m47),Z,Z,Z,Z) end)
    put(r,"638",function() return sc638(U(3),U(tz8),U(tz16),U(tz4),Z,Z) end)
    put(r,"605",function() return sc605(U(mag),Z,Z,Z,Z,Z) end)
    put(r,"602",function() return sc602(U(1),Z,Z,Z,Z,Z) end)
    put(r,"607",function() return sc607(U(pb),Z,Z,Z,Z,Z) end)
    return table.concat(r," ")
end
local base=battery()
print("[base] "..base)
local function key(s) return s end
for b=0,31 do
    local mask=2^b
    local ok,r=pcall(function() return sc643(U(mask),Z,Z,Z,Z,Z) end)
    if not ok then print(string.format("[bit%02d] 643 TRAP",b)) break end
    local now=battery()
    local mark = (now==base) and "same" or "DIFF"
    print(string.format("[bit%02d] 643 rv=%s err=%s -> %s",b,H(r),ES(),mark))
    if mark=="DIFF" then print("        "..now) end
end
print("[Z] alive")
print("=== DONE")
