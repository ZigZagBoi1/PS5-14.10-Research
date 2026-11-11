-- CRASH_CLASS: MODERATE
-- PROBE 1229a: map the ucontext layout empirically with the newly working 632/634 pair.
-- Each GPR slot at ctx+0x48..0xB8 gets a unique marker; after suspend+get, the copied buffer shows
-- which slot became which GPR, and which fields the kernel actually preserves.
print("=== PROBE 1229a: ucontext layout map ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
local eb = N(eboot_base)
print(string.format("[0] pid=%d eboot=0x%X", N(mk(20)()), eb))
local jmp_self = nil
for off = 0, 0x40000, 1 do
  local b0,b1 = nil,nil
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off)) end) if ok then b0=v end end
  do local ok,v = pcall(function() return N(memory.read_byte(eb+off+1)) end) if ok then b1=v end end
  if b0 == 0xEB and b1 == 0xFE then jmp_self = eb+off break end
end
if not jmp_self then print("no gadget"); print("=== DONE ===") return end
local stk = N(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
if stk == 0 then print("no stack"); print("=== DONE ===") return end
local stktop = stk + 0x10000 - 0x100
wq(stktop, uint64(jmp_self))
local ctx = memory.alloc(0x500)
for i = 0, 0x4F8, 8 do wq(ctx + i, 0) end
local MARK = 0x1111000000000000
for i = 0, 14 do wq(ctx + 0x48 + i*8, MARK + i) end
wq(ctx + 0x0c0, uint64(0x43))
wq(ctx + 0x0e0, uint64(jmp_self))
wq(ctx + 0x0f8, uint64(stktop))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0d0, 0)
wq(ctx + 0x110, uint64(0x10000))
local tids = memory.alloc(8) wq(tids, uint64(0xDEADDEAD))
call("430", function() return mk(430)(uint64(ctx),uint64(tids),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local tid = rq(tids)
print(string.format("    tid = %s", tid and string.format("0x%X", tid) or "nil"))
if not tid or tid == 0xDEADDEAD then print("=== DONE ===") return end
call("433(tid,0)", function() return mk(433)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("632", function() return mk(632)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local buf = memory.alloc(0x600)
for i=0,0x5FC,4 do wd(buf+i,0xA5A5A5A5) end
call("634", function() return mk(634)(uint64(tid),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[1] copied context, qword per line, non-zero only:")
for i = 0, 0x4B8, 8 do
  local v = rq(buf + i)
  if v and v ~= 0 then print(string.format("    +0x%03X = 0x%X", i, v)) end
end
call("633", function() return mk(633)(uint64(tid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")