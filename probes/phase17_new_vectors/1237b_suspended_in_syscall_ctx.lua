-- CRASH_CLASS: MODERATE
-- PROBE 1237b: does a thread suspended INSIDE a kernel syscall report any kernel state through
-- thr_get_ucontext (634)? 1229a mapped the layout for an idle thread and found no supervisor-range
-- qword, but that was measured while the thread was at the user-return boundary. The unresolved
-- claim in docs/UCONTEXT_FAMILY_14_10.md is that suspension "takes effect at the user-return
-- boundary" and therefore can never surface an in-kernel frame. That is a reasoned claim, not a
-- measured one. This probe parks exactly one child inside poll(), suspends it, copies its context,
-- and scans the whole copy for supervisor-range values.
print("=== PROBE 1237b: suspend a child blocked in a syscall, scan its context ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
local function scan(tag, addr, len)
    local kp, n, first = 0, 0, nil
    for i = 0, len - 8, 8 do
        local v = rq(addr + i)
        if v then
            n = n + 1
            if v >= 0xFFFF800000000000 then
                kp = kp + 1
                if not first then first = string.format("+0x%X=0x%X", i, v) end
            end
        end
    end
    print(string.format("    scan %s: %d qwords, %d supervisor-range %s", tag, n, kp, first or ""))
    return kp, first
end
local eb = N(eboot_base)
print(string.format("[0] pid=%d eboot=0x%X", N(mk(20)()), eb))
local STUB = N(syscall.pipe.fn_addr)
print(string.format("    syscall stub = 0x%X", STUB))
local function spawn(rax, rdi, rsi, rdx, tag)
  local stk = N(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
  if stk == 0 then return nil end
  local top = stk + 0x10000 - 0x100
  wq(top, uint64(1))            -- return to an unmapped address: the loader chain runs thr_exit(431)
  local ctx = memory.alloc(0x500)
  for i = 0, 0x4F8, 8 do wq(ctx + i, 0) end
  wq(ctx + 0x48, uint64(rdi))
  wq(ctx + 0x50, uint64(rsi))
  wq(ctx + 0x58, uint64(rdx))
  wq(ctx + 0x78, uint64(rax))
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
  print(string.format("    spawn %s rax=%d rdi=%s -> rv=%s tid=0x%X", tag, rax, tostring(rdi), tostring(ok and N(rv) or "err"), tid))
  return tid
end
local ts = memory.alloc(16)
local function nap(ms)
  wq(ts, math.floor(ms/1000)); wq(ts+8, (ms % 1000) * 1000000)
  pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
end
local buf = memory.alloc(0x600)
local function scan_ctx(tag, tid)
  for i=0,0x5FC,4 do wd(buf+i,0xA5A5A5A5) end
  local r = call(tag.." 634", function() return mk(634)(uint64(tid),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  local kp, first = scan(tag, buf, 0x500)
  if kp == 0 then
    print(string.format("    %s: non-zero qwords after the copy:", tag))
    local nz = 0
    for i = 0, 0x4B8, 8 do
      local v = rq(buf + i)
      if v and v ~= 0 then
        nz = nz + 1
        if nz <= 24 then print(string.format("      +0x%03X = 0x%X", i, v)) end
      end
    end
    print(string.format("      (%d non-zero qwords total)", nz))
  end
  return kp, first
end

print("[A] control: idle child, no suspend yet - does 634 refuse a running thread")
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("    fds %d %d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); print("=== DONE ===") return end
local fds = memory.alloc(16)
wd(fds, fd0) wd(fds+4, 1) wd(fds+8, 0) wd(fds+12, 0)
local tid = spawn(209, N(uint64(fds)), 1, 5000, "poll")
if not tid then print("no thread"); print("=== DONE ===") return end
print("[B] the child is now inside poll(); suspend it and copy its context")
nap(120)
call("632 suspend", function() return mk(632)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
scan_ctx("parked", tid)
print("[C] release: close both ends so poll returns, child then faults at address 1 and exits")
call("633 resume", function() return mk(633)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("close fd0", function() return mk(6)(uint64(fd0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("close fd1", function() return mk(6)(uint64(fd1),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
nap(300)
print("[D] second sample after release, from a different socketpair, to catch a suspend that only lands at the boundary")
local sv2 = memory.alloc(8) wd(sv2,0) wd(sv2+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv2))
local g0, g1 = rd(sv2), rd(sv2+4)
local fds2 = memory.alloc(16)
wd(fds2, g0) wd(fds2+4, 1) wd(fds2+8, 0) wd(fds2+12, 0)
local tid2 = spawn(209, N(uint64(fds2)), 1, 8000, "poll2")
if tid2 then
  nap(150)
  call("632b suspend", function() return mk(632)(uint64(tid2),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  nap(60)
  scan_ctx("parked2", tid2)
  call("633b resume", function() return mk(633)(uint64(tid2),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  call("close g0", function() return mk(6)(uint64(g0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  call("close g1", function() return mk(6)(uint64(g1),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
end
nap(300)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
