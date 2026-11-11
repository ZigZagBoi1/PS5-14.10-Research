-- CRASH_CLASS: MODERATE
-- PROBE 1237c: corrected tid plumbing for the suspend-in-syscall measurement.
-- 1237b passed the ADDRESS of the tid buffer to 632/634 instead of the tid value (uint64(tb) on a
-- memory handle yields the handle's address, not the qword written into it), so both calls returned
-- ESRCH and the loader died shortly after. This version reads the tid with read_qword, confirms the
-- thread exists with 433(tid,0), then suspends it while it is inside poll(2) and copies its context.
print("=== PROBE 1237c: suspend a child inside poll(), scan the context copy ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return N(rv) end
local function scan(tag, addr, len)
    local kp, n, first, hi = 0, 0, nil, 0
    for i = 0, len - 8, 8 do
        local v = rq(addr + i)
        if v then
            n = n + 1
            if v >= 0xFFFF800000000000 then kp = kp + 1 if not first then first = string.format("+0x%X=0x%X", i, v) end end
            local h2 = math.floor(v / 4294967296)
            if h2 >= 0xFFFF0000 then hi = hi + 1 end
        end
    end
    print(string.format("    scan %s: %d qwords, %d supervisor-range %s, %d with hi32>=0xFFFF0000", tag, n, kp, first or "", hi))
    return kp
end
local eb = N(eboot_base)
local STUB = N(syscall.pipe.fn_addr)
print(string.format("[0] pid=%d eboot=0x%X stub=0x%X", N(mk(20)()), eb, STUB))
local jmp_self = nil
for off = 0, 0x40000 do
  local b0,b1
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off)) end) if ok then b0=v end end
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off+1)) end) if ok then b1=v end end
  if b0 == 0xEB and b1 == 0xFE then jmp_self = eb+off break end
end
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("[1] socketpair fds %d %d, jmp_self=%s", fd0, fd1, jmp_self and string.format("0x%X",jmp_self) or "nil"))
if fd0 <= 0 then print("no socketpair"); print("=== DONE ===") return end
local fds = memory.alloc(16)
wd(fds, fd0) wd(fds+4, 1) wd(fds+8, 0) wd(fds+12, 0)
local POLLMS = 6000
local stk = N(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
if stk == 0 then print("no stack"); print("=== DONE ===") return end
local top = stk + 0x10000 - 0x100
wq(top, uint64(1))
local ctx = memory.alloc(0x500)
for i = 0, 0x4F8, 8 do wq(ctx + i, 0) end
wq(ctx + 0x48, uint64(N(uint64(fds))))          -- rdi = struct pollfd *
wq(ctx + 0x50, uint64(1))                        -- rsi = nfds
wq(ctx + 0x58, uint64(POLLMS))                   -- rdx = timeout ms
wq(ctx + 0x78, uint64(209))                      -- rax = poll
wq(ctx + 0x0c0, uint64(0x43))
wq(ctx + 0x0e0, uint64(STUB))
wq(ctx + 0x0f8, uint64(top))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0d0, 0)
wq(ctx + 0x110, uint64(0x10000))
local tb = memory.alloc(8) wq(tb, uint64(0xDEADDEAD))
local rv = call("430 thr_create", function() return mk(430)(uint64(ctx),uint64(tb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local tid = rq(tb)
print(string.format("    tid = %s", tid and string.format("0x%X", tid) or "nil"))
if not tid or tid == 0xDEADDEAD then print("no thread"); print("=== DONE ===") return end
local ts = memory.alloc(16)
local function nap(ms) wq(ts, math.floor(ms/1000)); wq(ts+8, (ms%1000)*1000000) pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end) end
nap(150)
print("[2] the child should now be inside poll(); does the tid still resolve?")
call("433(tid,0)", function() return mk(433)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[3] suspend it there and copy its context")
local sr = call("632 suspend", function() return mk(632)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local buf = memory.alloc(0x600)
if sr == 0 then
  for i=0,0x5FC,4 do wd(buf+i,0xA5A5A5A5) end
  call("634 get_ucontext", function() return mk(634)(uint64(tid),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  scan("parked", buf, 0x500)
  print("    first 32 qwords:")
  for i = 0, 0xF8, 8 do
    local v = rq(buf + i)
    if v then print(string.format("      +0x%03X = 0x%X", i, v)) end
  end
  call("633 resume", function() return mk(633)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
else
  print("    suspend refused - the measurement is that an in-syscall thread cannot be suspended")
  for i=0,0x5FC,4 do wd(buf+i,0xA5A5A5A5) end
  call("634 without suspend", function() return mk(634)(uint64(tid),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  print(string.format("    buf[0] after the refused path = 0x%X", rq(buf+0) or 0))
end
print("[4] let the poll timeout expire so the child returns, faults at address 1 and exits")
nap(POLLMS + 800)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
