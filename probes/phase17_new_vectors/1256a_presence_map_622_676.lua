-- CRASH_CLASS: MODERATE
-- PROBE 1256a: finish the presence map, 622-676, with fault-proof pointer arguments.
--
-- Context: 1255a mapped 538-621 in one connection and then DIED at 622, where it had passed
-- arg2 = 0 as the output-buffer pointer. 622 is a real handler (55b/55c: cmd 0 returns 0 and
-- writes 0x800E0001 into a caller buffer), so a NULL buffer makes it fault even under SIG_IGN.
-- That is itself a result: 622 dereferences its output pointer in a way that is fatal.
--
-- This probe resumes at 622 and passes a valid zeroed 0x4000 buffer as ALL SIX arguments, so
-- no argument can be a NULL pointer. Where a slot wants a scalar, an address is a large
-- integer that fails validation cleanly; where it wants a pointer, the buffer is mapped.
-- 643 and 675 keep their side effects last.
print("=== PROBE 1256a: presence map 622-676, fault-proof args ===")
print("")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return N(x) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function SL(v) local lo
  if type(v)=="table" and v.l then lo=v.l else lo = N(v) % 4294967296 end
  if lo >= 2147483648 then return lo - 4294967296 end
  return lo
end

local sa = memory.alloc(0x28); local saa = as_addr(sa)
for o=0,0x20,8 do wq(saa+o,0) end
wq(saa, 1); wq(saa+0x20, 4)
local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[0] pid=%d SIG_IGN ok=%s rv=%d", N(mk(20)()), tostring(ok), ok and SL(rv) or -999))
if not ok or SL(rv) ~= 0 then print("[!] install failed"); print("=== DONE 1256a ===") return end

local buf = memory.alloc(0x4000)
local ba = as_addr(buf)
for o=0,0x3FF8,8 do wq(ba+o, 0) end
print(string.format("[0] scratch buf=0x%X", ba))

-- 622 retest first: cmd 0 with a valid output buffer (the 55b/55c shape).
local o622, v622 = pcall(function() return mk(622)(uint64(0), uint64(ba), uint64(0), uint64(0), uint64(0), uint64(0)) end)
if o622 then
  print(string.format("n=622 ret=%d err=%s buf0=0x%X", SL(v622), ES(), N(memory.read_dword(uint64(ba)))))
else
  print("n=622 PCALL-FAIL")
end
print(string.format("-- alive pid=%d", N(mk(20)())))

local absent, present = 0, 0
for n = 623, 676 do
  if n ~= 643 and n ~= 675 then
    local o, v = pcall(function() return mk(n)(uint64(ba),uint64(ba),uint64(ba),uint64(ba),uint64(ba),uint64(ba)) end)
    if not o then
      print(string.format("n=%d PCALL-FAIL", n))
    else
      local r = SL(v)
      local e = ES()
      print(string.format("n=%d ret=%d err=%s", n, r, e))
      if r == -1 and e:find("not implemented") then absent = absent + 1 else present = present + 1 end
    end
  end
end
print(string.format("-- pass: present=%d absent=%d pid=%d", present, absent, N(mk(20)())))
for _, n in ipairs({643, 675}) do
  local o, v = pcall(function() return mk(n)(uint64(ba),uint64(ba),uint64(ba),uint64(ba),uint64(ba),uint64(ba)) end)
  if o then print(string.format("B n=%d ret=%d err=%s", n, SL(v), ES())) else print(string.format("B n=%d PCALL-FAIL", n)) end
end
print(string.format("[9] final pid=%d", N(mk(20)())))
print("=== DONE 1256a ===")
