-- CRASH_CLASS: LOW
-- PROBE 1238a: the thread-id space and the process filter in the thr_* family.
-- Static reading of 0xb92420 (the shared resolver behind 632/633/634):
--   arg1 -> hash bucket (masked), chain walked on [thread+0x9c] == arg1, then
--   [thread->td_proc + 0xbc] must equal arg2, which the handlers pass as
--   [curproc + 0xbc]. If that reading is right, a tid belonging to another
--   process resolves but is filtered, so 634 must look exactly like a
--   nonexistent tid. If it is wrong, 634 copies a foreign thread's context -
--   and for a kernel thread that context holds supervisor pointers.
print("=== PROBE 1238a: tid space and pid filter ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return N(v) end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end

print(string.format("[0] pid=%d", N(mk(20)())))
local tb = memory.alloc(8) wd(tb, 0)
local rok = pcall(function() mk(432)(tb) end)
local self_tid = rd(tb)
print(string.format("    432 thr_self -> %d (ok=%s) tid=0x%X", self_tid, tostring(rok), self_tid))

local buf = memory.alloc(0x600)
local function probe(tag, tid)
  pcall(function() for i=0,0x5F8,8 do memory.write_qword(buf+i,uint64(0xA5A5A5A5A5A5A5A5)) end end)
  local ok, rv = pcall(function() return mk(634)(uint64(tid), uint64(buf), uint64(0), uint64(0), uint64(0), uint64(0)) end)
  if not ok then print(string.format("  %-18s PCALL-FAIL", tag)) return end
  local h,l = hilo(rv)
  local e = ES()
  local touched, sup, hi = 0, 0, 0
  local first = ""
  for i=0,0x4B8,8 do
    local v = rq(buf+i)
    if v ~= 0xA5A5A5A5A5A5A5A5 then
      touched = touched + 1
      if i < 0x40 then first = first .. string.format(" +%X=%X", i, v) end
      local sh = math.floor(v / 4294967296)
      if sh >= 4294901760 then sup = sup + 1 end
    end
  end
  print(string.format("  %-18s ret=0x%08X_%08X err=%s touched=%d sup=%d%s", tag, h, l, e, touched, sup, first))
end

print("[A] the caller's own tid (state gate should refuse a running thread)")
probe("self", self_tid)
probe("self+2^32", self_tid + 4294967296)
print("[B] low tids, where kernel and system processes live")
for _, t in ipairs({1,2,3,4,5,6,7,8,9,10,11,12,16,20,24,32,40,48,64,80,96,128,160,192,256,512,1024,4096}) do
  probe(string.format("tid %d", t), t)
end
print("[C] boundaries")
probe("0x7FFFFFFF", 2147483647)
probe("0xFFFFFFFF", 4294967295)
probe("0x1_0000_0000", 4294967296)
print("=== DONE ===")
