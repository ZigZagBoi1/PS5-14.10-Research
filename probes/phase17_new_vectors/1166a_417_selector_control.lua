-- CRASH_CLASS: MODERATE
-- PROBE 1166a: does syscall 417 sanitize the trapframe's SELECTORS?
--
-- 816a established the mechanics: 417 copies 0xC0 bytes of user data into the
-- live trapframe at [td+0x460], and 421 reads that record back, with RIP at
-- +0xE0, CS at +0xE8, RFLAGS at +0xF0, RSP at +0xF8, SS at +0x100. 816a changed
-- RFLAGS and found that IOPL does not survive, i.e. some field checking exists.
-- Nobody ever changed CS or SS. Those are the two fields that decide the
-- privilege level of the iretq that returns from 417.
--
-- The question: is the selector copied from our buffer, or forced?
--   copied  -> the frame is attacker-shaped and CS=0x08 is the next question;
--   forced / refused -> the frame is normalized and this class is closed.
--
-- What this probe does NOT do, on purpose: it never writes a selector whose
-- DPL is not 3 (no 0x08, no 0x20, no 0x10). A ring-0 selector in this frame
-- would iretq to CPL0 at a user RIP and take the console down if SMEP is on.
-- That test needs its own landing site and its own authorization.
--
-- Every mutation keeps RIP, RSP and RFLAGS exactly as 421 just returned them,
-- so the return from 417 lands on the ordinary return address with the ordinary
-- stack. A rejected selector shows up as 417 = -1; a bad selector that iretq
-- itself rejects kills this process, not the console.
--
-- Order matters: the harmless selectors go first, and each section marks the
-- wire before it acts, so a process death is attributable to one line.

print("=== PROBE 1166a: 417 FRAME SELECTOR CONTROL ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end); if ok then return to_num(v) end return nil end
local function wr(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rq(a)
  local lo=rd(a); local hi=rd(a+4)
  if lo==nil or hi==nil then return 0 end
  return hi*0x100000000+lo
end
local function wq(a,v)
  local lo=v%0x100000000
  local hi=math.floor(v/0x100000000)%0x100000000
  wr(a,lo); wr(a+4,hi)
end

local function band(a,b)
  local r=0 local bit=1
  for i=1,32 do
    local x=a%2 local y=b%2
    if x==1 and y==1 then r=r+bit end
    a=math.floor(a/2) b=math.floor(b/2) bit=bit*2
  end
  return r
end
local sc417=mk(417)
local sc421=mk(421)
local buf=0
do
  local a=memory.alloc(0x200)
  local m=tostring(a):match("0x(%x+)")
  buf=m and tonumber(m,16) or to_num(a)
end

print(string.format("[0] pid=%s buf=0x%08X", tostring(to_num(syscall.getpid())), buf))

local function readframe(tag)
  local ok,r=pcall(function() return sc421(uint64(buf)) end)
  local t={}
  t.rip=rq(buf+0xE0); t.cs=rq(buf+0xE8); t.fl=rq(buf+0xF0); t.rsp=rq(buf+0xF8); t.ss=rq(buf+0x100)
  print(string.format("    %s 421 ok=%s ret=%s RIP=%08X%08X CS=%04X FLAGS=%08X%08X RSP=%08X%08X SS=%04X",
    tag,tostring(ok),tostring(r),math.floor(t.rip/0x100000000),t.rip%0x100000000,
    t.cs,math.floor(t.fl/0x100000000),t.fl%0x100000000,t.rsp%0x100000000,math.floor(t.rsp/0x100000000),t.ss))
  return t
end

local function install(tag)
  print(string.format("    %s 417 ...",tag))
  local ok,r=pcall(function() return sc417(uint64(buf)) end)
  if not ok then print("    "..tag.." 417 RAISED: "..tostring(r):sub(1,80)); return -999 end
  print(string.format("    %s 417 ret=%s",tag,tostring(r)))
  return to_num(r)
end

-- [A] baseline
local b=readframe("[A]")
if b.rip==0 or b.cs~=0x43 then
  print("[A] unexpected baseline (CS is not 0x43 or RIP is 0); continuing anyway, results are still attributable")
end
if b.rip==0 then print("[A] ABORT: no usable frame"); print(""); print("=== DONE ==="); return end

-- save the kernel's own values so every subsequent mutation restores them
local RIP0, CS0, FL0, RSP0, SS0 = b.rip, b.cs, b.fl, b.rsp, b.ss
local function restore() wq(buf+0xE0,RIP0); wq(buf+0xE8,CS0); wq(buf+0xF0,FL0); wq(buf+0xF8,RSP0); wq(buf+0x100,SS0) end

-- [B] control: hand back the kernel's own frame untouched
restore()
local rB=install("[B]")
local bB=readframe("[B]")
print(string.format("    [B] VERDICT control: ret=%d cs=%04X ss=%04X %s",rB,bB.cs,bB.ss,
  (rB==0 and bB.cs==CS0 and bB.ss==SS0) and "ROUND-TRIP OK" or "CONTROL NOT CLEAN - later verdicts unreliable"))

-- [C] SS = 0x33 (a different DPL-3 data selector)
restore(); wq(buf+0x100,0x33)
local rC=install("[C]")
local cC=readframe("[C]")
print(string.format("    [C] SS sent 0x33 -> read back %04X ; 417 ret=%d ; %s",cC.ss,rC,
  (cC.ss==0x33) and "SELECTOR KEPT" or ((cC.ss==SS0) and "SELECTOR NORMALIZED" or "SELECTOR CHANGED TO SOMETHING ELSE")))

-- [D] CS = 0x4B (DPL-3 code, different descriptor index; RIP untouched)
restore(); wq(buf+0xE8,0x4B)
local rD=install("[D]")
local dD=readframe("[D]")
print(string.format("    [D] CS sent 0x4B -> read back %04X ; 417 ret=%d ; %s",dD.cs,rD,
  (dD.cs==0x4B) and "CS KEPT (frame is attacker-shaped)" or ((dD.cs==CS0) and "CS NORMALIZED (forced back to 0x43)" or "CS CHANGED TO SOMETHING ELSE")))

-- [E] RFLAGS TF, to re-establish that non-selector bits are accepted at all
restore(); wq(buf+0xF0, band(FL0, 0xFFFFFFFFFFFFFEFF) + 0x100)
local rE=install("[E]")
local eE=readframe("[E]")
print(string.format("    [E] FLAGS+TF -> read back %08X%08X ; 417 ret=%d ; TF=%s",math.floor(eE.fl/0x100000000),eE.fl%0x100000000,rE,
  (((eE.fl%0x10000)>=0x100) and "KEPT" or "DROPPED")))

restore()
print("")
print("[SUM] selectors: SS="..string.format("%04X",cC.ss).." CS="..string.format("%04X",dD.cs)..
  " (baseline SS="..string.format("%04X",SS0).." CS="..string.format("%04X",CS0)..")")
print("")
print("=== DONE ===")
