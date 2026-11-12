-- CRASH_CLASS: MODERATE
-- PROBE 1244a: 663 aio_multi_wait - does the mode guard cover modes >= 3?
-- Lifetime census (docs/KERNEL_LIFETIME_CENSUS_14_10.md) survivor 1: in 13.60 the shared-node
-- link at 0x3b0969/0x3b096d is taken by every mode except 1 and 2, the cleanup unlinks only from
-- the last owner, and the node array is freed at 0x3b0f9e. On 14.10 mode 0 at count>1 returns
-- EINVAL (1219a/1221a), but modes 3+ were never sent. This probe sends them with ids {0,0}: id 0
-- is skipped with status 0x80020003, so nothing is ever waited on and the call returns.
-- Reading: -1 EINVAL for every M = the guard covers the whole shared path (class closed).
--          0 with two 0x80020003 words = the guard only tests mode 0 and mode 3 reaches the link.
print("=== PROBE 1244a: aio_multi_wait mode guard coverage ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,hi,lo) pcall(function() memory.write_qword(a,uint64(string.format("0x%X%08X",hi,lo))) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end

print(string.format("[0] pid=%d", N(mk(20)())))
local ids = memory.alloc(0x20)
local out = memory.alloc(0x100)
local tim = memory.alloc(8)
wq(ids,0,0); wq(ids+8,0,0)
wd(tim, 50)
local function clr() for i=0,0xFC,4 do wd(out+i,0xCDCDCDCD) end end
local function stat()
  local s = ""
  for i=0,0x2C,4 do s = s .. string.format(" %08X", rd(out+i)) end
  return s
end
local function call663(tag, cnt, mode, tptr)
  clr()
  print(string.format("  -- %s: count=%d mode=0x%X", tag, cnt, mode))
  local ok, rv = pcall(function() return mk(663)(uint64(ids), uint64(cnt), uint64(out), uint64(mode), uint64(tptr)) end)
  if not ok then print("     PCALL-FAIL") return end
  local h,l = hilo(rv)
  local err = ""
  if h == 0xFFFFFFFF and l == 0xFFFFFFFF then err = " err=" .. ES() end
  print(string.format("     ret=0x%08X_%08X%s out:%s", h, l, err, stat()))
end

print("[A] controls")
call663("mode 1 count 2 (per-mode path, known good)", 2, 1, 0)
call663("mode 0 count 2 (guard, known EINVAL)", 2, 0, 0)
print("[B] the unmeasured modes, invalid ids so nothing is waited on")
for _, m in ipairs({3,4,5,6,7,8,0x10,0x40,0xFF}) do
  call663(string.format("mode 0x%X count 2", m), 2, m, 0)
end
print("[C] one unmeasured mode with a timeout pointer")
call663("mode 3 count 2 timeout=50ms", 2, 3, N(tim))
print("[D] mode 2 and 1 at count 2 again, to confirm the loader is still healthy")
call663("mode 2 count 2", 2, 2, 0)
call663("mode 1 count 2", 2, 1, 0)
print("=== DONE ===")