-- CRASH_CLASS: LOW
-- PROBE 1245a: uninitialised-copyout, dynamic test
-- The static census (docs/UNINIT_COPYOUT_SCAN_14_10.md) cannot distinguish a stack buffer that is
-- fully filled from one that is filled only in part, because the fill may happen inside a callee.
-- The decisive test is dynamic: call the same syscall twice with the same buffer and compare the
-- output byte for byte. Bytes that differ were never written by the kernel, i.e. the buffer is a
-- partial fill and the untouched bytes come from whatever the kernel stack held before.
print("=== PROBE 1245a: uninitialised copyout, dynamic diff ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,hi,lo) pcall(function() memory.write_qword(a,uint64(string.format("0x%X%08X",hi,lo))) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end

local pid = N(mk(20)())
print(string.format("[0] pid=%d", pid))
local LEN = 0x100
local buf = memory.alloc(0x400)
local function clr() for i=0,0x3FC,4 do wd(buf+i,0xA5A5A5A5) end end
local function snap() local t={} for i=0,LEN-1 do t[i+1]=rb(buf+i) end return t end
local function diff(a,b)
  local out, n = {}, 0
  for i=1,LEN do
    if a[i] ~= b[i] then
      n = n + 1
      if n <= 12 then
        local off = i - 1
        out[#out+1] = string.format("+0x%02X %02X->%02X", off, a[i] % 256, b[i] % 256)
      end
    end
  end
  return n, table.concat(out, " ")
end
local function trial(tag, fn)
  clr()
  local ok1, rv1 = pcall(fn)
  if not ok1 then print("  -- " .. tag .. ": PCALL-FAIL on run 1") return end
  local s1 = snap()
  local ok2, rv2 = pcall(fn)
  if not ok2 then print("  -- " .. tag .. ": PCALL-FAIL on run 2") return end
  local s2 = snap()
  local h,l = hilo(rv1)
  local n, ex = diff(s1, s2)
  print(string.format("  -- %-34s run1=0x%08X_%08X differing bytes=%d", tag, h, l, n))
  if n > 0 then print("       " .. ex) end
  local dirty = 0
  for i=0,LEN-1 do if rb(buf+i) ~= 0xA5 then dirty = dirty + 1 end end
  print(string.format("       bytes written by the call: %d/%d", dirty, LEN))
end

print("[A] fstat on a fresh socketpair member")
local fds = memory.alloc(8)
local rv = mk(135)(uint64(1), uint64(1), uint64(0), uint64(fds))
local fd0 = rd(fds)
print(string.format("    socketpair rv=%s fd0=%d", tostring(type(rv)=="table" and "ok" or rv), fd0))
trial("fstat(189) fd0", function() return mk(189)(uint64(fd0), uint64(buf)) end)

print("[B] gettimeofday(116)")
trial("gettimeofday(116)", function() return mk(116)(uint64(buf), uint64(0)) end)

print("[C] module record 593(1, buf) - 0x160-byte output")
wq(buf,0,0x160)
trial("sys593(1,buf) size=0x160", function() wq(buf,0,0x160); return mk(593)(uint64(1), uint64(buf)) end)

print("[D] getdirentries(196) on /dev")
local dev = nil
local okopen, ofd = pcall(function() return mk(5)(uint64("/dev"), uint64(0), uint64(0)) end)
if okopen then
  local h,l = hilo(ofd)
  dev = l
  print(string.format("    open(/dev)=%d", dev))
  if dev ~= -1 and dev ~= 0xFFFFFFFF then
    trial("getdirentries(196) /dev", function() return mk(196)(uint64(dev), uint64(buf), uint64(0x80), uint64(0)) end)
    pcall(function() mk(6)(uint64(dev)) end)
  end
else
  print("    open(/dev) PCALL-FAIL")
end
print("=== DONE ===")