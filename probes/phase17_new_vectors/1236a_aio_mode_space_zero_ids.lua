-- CRASH_CLASS: LOW
-- PROBE 1236a: does the 14.10 aio guard refuse mode 0, or the mode-0 code path?
--
-- Zero ids never sleep: the validation loop skips them with status 0x80020003 and returns
-- (1219a rows for modes 1 and 2). So this sweep needs no thread and cannot wedge the loader.
--   mode 0      -> -1 EINVAL (measured, control)
--   mode 1, 2   -> 0 with one status word per id (measured)
--   mode >= 3   -> if 0: the guard is a value test and 0x3b08e5 (shared node[0]) is reachable
print("=== PROBE 1236a: 663 mode space with zero ids ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function alive() local ok,v=pcall(function() return N(mk(20)()) end) if ok then return v end return -1 end
local lk = N(libkernel_base)
local TR = lk + 0x3B7
print(string.format("[0] pid=%d trampoline=0x%X", alive(), TR))
local ids = memory.alloc(64)
local out = memory.alloc(64)
local MODES = {0,1,2,3,4,5,6,7,8,0x10,0x40,0xFF}
for k=1,#MODES do
  local m = MODES[k]
  wd(ids,0) wd(ids+4,0) wd(ids+8,0)
  wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA) wd(out+8,0xAAAAAAAA)
  local ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, 2, out, m, 0, 0) end)
  if not ok then print(string.format("  mode=0x%02X PCALL-FAIL", m)) else
    local h,l = hilo(rv)
    print(string.format("  mode=0x%02X n=2 ret=0x%08X_%08X err=%-24s out=%08X %08X %08X pid=%d",
      m, h, l, ES(), rd(out), rd(out+4), rd(out+8), alive()))
  end
end
print("[B] count 3 on the modes that accepted count 2")
for _, m in ipairs({3,4,5,0x10,0xFF}) do
  wd(ids,0) wd(ids+4,0) wd(ids+8,0)
  wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA) wd(out+8,0xAAAAAAAA) wd(out+12,0xAAAAAAAA)
  local ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, 3, out, m, 0, 0) end)
  if not ok then print(string.format("  mode=0x%02X PCALL-FAIL", m)) else
    local h,l = hilo(rv)
    print(string.format("  mode=0x%02X n=3 ret=0x%08X_%08X err=%-24s out=%08X %08X %08X %08X pid=%d",
      m, h, l, ES(), rd(out), rd(out+4), rd(out+8), rd(out+12), alive()))
  end
end
print(string.format("[Z] pid_end=%d", alive()))
print("=== DONE ===")
