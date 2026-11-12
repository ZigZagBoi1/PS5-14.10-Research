-- CRASH_CLASS: MODERATE
-- PROBE 1152a: the errno behind 622's 0x271 refusal.
-- 1150a/1151a showed the loader's syscall path does maintain TLS errno, which turns every "-1" in
-- the corpus into a readable answer. The 622 arm command 0x271 is the one command in the
-- 0x201-0x271 block that reaches a gate (status 0x8002004E), and until now the wire carried only
-- the status word. EACCES from a *credential* check and EACCES from a *Sony SCE* check look the
-- same in the status register but differ in errno: the devfs work showed SCE rejections come back
-- as 0x8A72xxxx through strerror. Print both.
-- Shape copied from 1079a (control command first, risky command second) so a broken context is
-- visible before the gated call.
print("=== PROBE 1152a: 622 0x271 ERRNO ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function make_syscall(num) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=num setmetatable(t,getmetatable(syscall.pipe)) return t end
local function call(num,a1,a2,a3,a4,a5,a6)
  local sc=make_syscall(num)
  local ok,rv=pcall(function() return sc(uint64(a1 or 0),uint64(a2 or 0),uint64(a3 or 0),uint64(a4 or 0),uint64(a5 or 0),uint64(a6 or 0)) end)
  if not ok then return -999 end
  if type(rv)=="table" and rv.h then
    local h,l=to_num(rv.h),to_num(rv.l)
    if h>=2147483648 then h=h-4294967296 end
    if l>=2147483648 then l=l-4294967296 end
    if h==-1 and l==-1 then return -1 end
    return h*4294967296+l
  end
  local n=to_num(rv)
  if n>=9223372036854775808 then n=n-18446744073709551616 end
  return n
end
local function errstr() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "?" end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end

-- SIGSYS ignore: 622 has never raised one, but the probe costs one syscall and the loader dies
-- with the game on an unhandled absent slot (1151a run 1).
local act=memory.alloc(0x28); local aa=tonumber(tostring(act):match("0x(%x+)"),16)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
pcall(function() make_syscall(416)(uint64(12),uint64(aa),uint64(0)) end)

local page=call(477,0,0x1000,7,0x1002,0xFFFFFFFF,0)
if page<=0 then print("no page") return end
local i=0
while i<0x400 do memory.write_qword(uint64(page+i),uint64(0)); i=i+8 end
local OUT=page+0x100
local function outd() local o,v=pcall(function() return memory.read_dword(uint64(OUT)) end) if o then return to_num(v) or 0 end return -1 end

wd(OUT,0xA5A5A5A5)
local rvc=call(622,0x300,0,OUT,0,0,0)
print(string.format("[A] control 0x300 rv=%d out=0x%08X errno=%s",rvc,outd(),errstr()))

wd(OUT,0xA5A5A5A5)
print(string.format("[B] 0x271 handle=0 out=a5a5a5a5"))
local rv=call(622,0x271,0,OUT,0,0,0)
print(string.format("    rv=%d out=0x%08X errno=%s",rv,outd(),errstr()))

wd(OUT,0xA5A5A5A5)
print(string.format("[C] 0x271 again, out pre-zeroed, second read of errno"))
local rv2=call(622,0x271,0,OUT,0,0,0)
print(string.format("    rv=%d out=0x%08X errno=%s",rv2,outd(),errstr()))

print("")
print("=== DONE ===")