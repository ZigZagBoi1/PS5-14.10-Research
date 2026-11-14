-- CRASH_CLASS: MODERATE
-- PROBE 1253a: does the 14.10 sysent extend past 676? SIG_IGN + fault-proof arguments.
--
-- Context: docs/SYSENT_PRESENCE_14_10.md measured 677-707 all killing the process when
-- called with zeroed arguments, and concluded the table ends at 676. The repo's own rule is
-- that a kill is a result about the call, never about the handler, and upstream row O5 asks
-- for fault-proof calls with real arguments on exactly these numbers.
--
-- Method: install SIG_IGN for SIGSYS(12) and prove it by read-back; then call 4095 (known
-- absent, probe 173a) as a control. If 4095 returns -1 with the process alive, an absent
-- slot is survivable and any non -1 return from the tail proves the handler EXISTS. Then
-- call the 13.60-named tail slots with valid, non-faulting arguments, printing "step N ok"
-- after each so a death localises itself.
--
-- 705 get_phys_page_size takes no arguments; if present it should answer 0x4000 (this
-- firmware has 16 KB pages) -- an unmistakable result.
print("=== PROBE 1253a: sysent tail, SIG_IGN + fault-proof args ===")
print("")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return N(x) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rdw(a) local o,v=pcall(function() return N(memory.read_dword(uint64(a))) end) if o then return v end return -1 end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then local h,l=0,0 if type(v)=="table" and v.h then h=v.h l=v.l else l=N(v) end return string.format("0x%08X_%08X",h,l) end return "?" end
-- signed 32-bit view of a syscall return, robust to uint64 table / double representations
local function SL(v) local lo
  if type(v)=="table" and v.l then lo=v.l else lo = N(v) % 4294967296 end
  if lo >= 2147483648 then return lo - 4294967296 end
  return lo
end

local pid = N(mk(20)())
print(string.format("[0] pid=%d", pid))

-- [1] SIG_IGN for SIGSYS(12)
local sa = memory.alloc(0x28); local saa = as_addr(sa)
local old = memory.alloc(0x28); local oa = as_addr(old)
for o=0,0x20,8 do wq(saa+o,0) end
wq(saa, 1)        -- sa_handler = SIG_IGN
wq(saa+0x20, 4)   -- sa_flags
local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[1] install ok=%s rv=%s", tostring(ok), ok and tostring(SL(rv)) or "ERR"))
if not ok or SL(rv) ~= 0 then print("[!] install failed, abort"); print("=== DONE ===") return end
local ok2 = pcall(function() return syscall.sigaction(12, 0, old) end)
print(string.format("[1] readback ok=%s handler=%s", tostring(ok2), rq(oa)))

-- [2] control: 4095 cannot have a handler (173a). With SIG_IGN it must return -1.
print("[2] control 4095")
local okc, rc = pcall(function() return mk(4095)() end)
print(string.format("[2] ok=%s ret=%d err=%s alive_pid=%d", tostring(okc), okc and SL(rc) or -999, ES(), N(mk(20)())))
if not okc or SL(rc) ~= -1 then print("[!] control failed: SIG_IGN does not cover an absent slot; stopping"); print("=== DONE ===") return end
print("[2] step 2 ok")

-- [3] 705 get_phys_page_size, no arguments
print("[3] 705 get_phys_page_size()")
local ok3, r3 = pcall(function() return mk(705)() end)
print(string.format("[3] ok=%s ret=%d err=%s", tostring(ok3), ok3 and SL(r3) or -999, ES()))
print("[3] step 3 ok")

-- [4] 687 pipe2(fds, 0)
print("[4] 687 pipe2(fds,0)")
local fds = memory.alloc(16); wd(fds,0); wd(fds+4,0)
local ok4, r4 = pcall(function() return mk(687)(uint64(as_addr(fds)), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[4] ok=%s ret=%d err=%s fds=%d,%d", tostring(ok4), ok4 and SL(r4) or -999, ES(), rdw(as_addr(fds)), rdw(as_addr(fds)+4)))
print("[4] step 4 ok")

-- [5] 690 ppoll(pfd, 1, zero timespec, 0, 0)
print("[5] 690 ppoll(pfd,1,ts0)")
local pfd = memory.alloc(16); wd(pfd, 0); wd(pfd+4, 1); wd(pfd+8, 0); wd(pfd+12, 0)
local ts = memory.alloc(16); wq(ts, 0); wq(ts+8, 0)
local ok5, r5 = pcall(function() return mk(690)(uint64(as_addr(pfd)), uint64(1), uint64(as_addr(ts)), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[5] ok=%s ret=%d err=%s revents=0x%X", tostring(ok5), ok5 and SL(r5) or -999, ES(), rdw(as_addr(pfd)+8)))
print("[5] step 5 ok")

-- [6] 728 virtual_query_by_pid(pid, addr, buf)
print("[6] 728 virtual_query_by_pid(self, heap, buf)")
local vq = memory.alloc(0x100); wq(vq, 0x4141414141414141)
local ok6, r6 = pcall(function() return mk(728)(uint64(pid), uint64(as_addr(fds)), uint64(as_addr(vq)), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[6] ok=%s ret=%d err=%s buf0=%s", tostring(ok6), ok6 and SL(r6) or -999, ES(), rq(vq)))
print("[6] step 6 ok")

-- [7] 725 mmap2(0, 0x4000, PROT_READ|WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
print("[7] 725 mmap2(...)")
local ok7, r7 = pcall(function() return mk(725)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
print(string.format("[7] ok=%s ret=%d err=%s", tostring(ok7), ok7 and SL(r7) or -999, ES()))
print("[7] step 7 ok")

-- [8] 715 ioreq, zeros (expected to reject if present)
print("[8] 715 ioreq(0...)")
local ok8, r8 = pcall(function() return mk(715)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[8] ok=%s ret=%d err=%s", tostring(ok8), ok8 and SL(r8) or -999, ES()))
print("[8] step 8 ok")

print(string.format("[9] alive pid=%d", N(mk(20)())))
print("=== DONE 1253a ===")
