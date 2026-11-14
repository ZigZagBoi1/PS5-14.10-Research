-- CRASH_CLASS: MODERATE
-- PROBE 1254a: presence oracle for the numbers the 2026-10-20 sweep recorded as "kills".
--
-- Context: 1253a proved that with SIG_IGN installed for SIGSYS(12) an ABSENT slot returns
-- -1/ENOSYS and the process survives, while the old kill-based classification could not tell
-- absent from present-and-faulting. This probe applies that oracle to the ambiguous middle:
-- 661 aio_submit, 665 aio_get_data, 668 aio_create (the AIO reachability question -- the
-- aio_multi_delete TOCTOU is the Lapse/Prolapse bug, patched in 14.20, so 14.10 would still
-- carry it IF 661 can be made to work), 627-631, and finally 677/678, the two numbers that
-- crashed the whole game on 2026-10-20 without SIG_IGN.
--
-- Each call prints a step marker BEFORE it runs, so a death localises itself. Order is by
-- expected information per unit of risk; the two game-crashers are last.
print("=== PROBE 1254a: SIG_IGN presence oracle over the kill list ===")
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

print(string.format("[0] pid=%d", N(mk(20)())))

local sa = memory.alloc(0x28); local saa = as_addr(sa)
local old = memory.alloc(0x28)
for o=0,0x20,8 do wq(saa+o,0) end
wq(saa, 1); wq(saa+0x20, 4)
local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[1] SIG_IGN install ok=%s rv=%d", tostring(ok), ok and SL(rv) or -999))
if not ok or SL(rv) ~= 0 then print("[!] install failed"); print("=== DONE 1254a ===") return end

local okc, rc = pcall(function() return mk(4095)() end)
print(string.format("[2] control 4095 -> ret=%d err=%s", okc and SL(rc) or -999, ES()))
if not okc or SL(rc) ~= -1 then print("[!] control failed, stop"); print("=== DONE 1254a ===") return end
print("[2] step 2 ok")

local function step(num, name, fn)
  print(string.format("[%d] %s", num, name))
  local o, v = pcall(fn)
  if o then
    print(string.format("  -> ok ret=%d err=%s", SL(v), ES()))
  else
    print("  -> PCALL-FAIL " .. tostring(v):sub(1,60))
  end
  print(string.format("  -> alive pid=%d", N(mk(20)())))
end

step(661, "aio_submit()", function() return mk(661)() end)
step(665, "aio_get_data()", function() return mk(665)() end)
step(668, "aio_create()", function() return mk(668)() end)
step(627, "627(0...)", function() return mk(627)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
step(628, "628(0...)", function() return mk(628)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
step(629, "629(0...)", function() return mk(629)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
step(630, "630(0...)", function() return mk(630)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
step(631, "631()", function() return mk(631)() end)
step(677, "677 wait6()", function() return mk(677)() end)
step(678, "678 cap_rights_limit()", function() return mk(678)() end)

print(string.format("[9] final pid=%d", N(mk(20)())))
print("=== DONE 1254a ===")
