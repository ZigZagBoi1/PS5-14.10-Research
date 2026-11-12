-- CRASH_CLASS: LOW
-- PROBE 1255a: the authoritative sysent presence map for the Sony block, 538-676.
--
-- Context: 1253a/1254a established the oracle -- with SIG_IGN for SIGSYS(12), an absent slot
-- returns -1/ENOSYS and the process survives, so presence can be read directly instead of
-- inferred from kills. The existing table in docs/SYSENT_PRESENCE_14_10.md was built from
-- per-number connections and a kill/no-kill column, so several rows are ambiguous or stale.
-- This probe walks the whole Sony block in one connection with zeroed arguments and records
-- ret + errno for each number, which is the first uniform map of the range.
--
-- Safety: the call-aware direct-deref census found ZERO bodies that dereference a uap-derived
-- value, so zeroed arguments cannot produce a kernel-mode fault; every handler either
-- validates through copyin/copyout or rejects early. None of 538-676 is exit/thr_exit/fork.
-- The seven numbers with known process-local side effects (563-566 opmc, 585 sandbox flag,
-- 643 chicken switches, 675 global reset) are called last so they cannot perturb the map.
print("=== PROBE 1255a: sysent presence map 538-676 ===")
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
if not ok or SL(rv) ~= 0 then print("[!] install failed"); print("=== DONE 1255a ===") return end
local okc, rc = pcall(function() return mk(4095)() end)
print(string.format("[0] control 4095 ret=%d err=%s", okc and SL(rc) or -999, ES()))
if not okc or SL(rc) ~= -1 then print("[!] control failed"); print("=== DONE 1255a ===") return end

-- pass A: the map. pass B: process-local side effects, last.
local B = {563,564,565,566,585,643,675}
local isB = {}
for i=1,7 do isB[B[i]] = true end

local absent, present, failed = 0, 0, 0
for n = 538, 676 do
  if not isB[n] then
    local o, v = pcall(function() return mk(n)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    if not o then
      print(string.format("n=%d PCALL-FAIL", n)); failed = failed + 1
    else
      local r = SL(v)
      local e = ES()
      print(string.format("n=%d ret=%d err=%s", n, r, e))
      if r == -1 and e:find("not implemented") then absent = absent + 1 else present = present + 1 end
    end
  end
end
print(string.format("-- pass A: present=%d absent=%d pcallfail=%d pid=%d", present, absent, failed, N(mk(20)())))

for i = 1, 7 do
  local n = B[i]
  local o, v = pcall(function() return mk(n)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  if o then print(string.format("B n=%d ret=%d err=%s", n, SL(v), ES())) else print(string.format("B n=%d PCALL-FAIL", n)) end
end
print(string.format("[9] final pid=%d", N(mk(20)())))
print("=== DONE 1255a ===")
