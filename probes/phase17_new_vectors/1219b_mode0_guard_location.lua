-- CRASH_CLASS: MODERATE
-- PROBE 1219b: is "mode 0 with count >= 2 -> EINVAL" a 14.10 guard, or an artefact of one stub
-- or one argument shape?
--
-- 1219a: through libkernel+0x3B7 (proven trampoline), 663(id=0) gives out=0x80020003 for
-- count 1 mode 0, and out=0x80020003 twice for count 2 modes 1 and 2, but EINVAL and an
-- untouched status for count 2 mode 0. The status array is written by the cleanup loop, so the
-- count-2-mode-0 call bails before the loop. EINVAL has only two producers in the 13.60 body
-- (count bound 0x3b03a3, mode bound 0x3b041c) and count 2 mode 1 passes both, which points at a
-- 14.10-specific guard rather than at the bounds.
--
-- This probe repeats the same call through four different verified stubs, with a NULL ids
-- pointer, with a NULL timeout pointer, and with count 0x80, to locate the guard.

print("=== PROBE 1219b: locating the count-2-mode-0 guard ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local lk = N(libkernel_base)
print(string.format("[0] pid=%d libkernel=0x%X", N(mk(20)()), lk))
local ids = memory.alloc(32)
local out = memory.alloc(32)
local tb  = memory.alloc(8)
for i=0,7 do wd(ids+i*4,0) end
wd(tb,0)

local function go(tag, stuboff, idptr, n, mode, tmoptr)
    wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA) wd(out+8,0xAAAAAAAA) wd(out+12,0xAAAAAAAA)
    local ok, rv = pcall(function() return native.fcall_with_rax(lk+stuboff+7, 663, idptr, n, out, mode, tmoptr, 0) end)
    local h,l = hilo(rv)
    print(string.format("  %-30s stub=%X n=%d mode=%d ret=0x%08X_%08X err=%-22s out=%08X %08X",
        tag, stuboff, n, mode, h, l, ES(), rd(out), rd(out+4)))
end

print("[A] same call through four different verified stubs")
go("count2 mode0", 0x3B0, ids, 2, 0, tb)
go("count2 mode0", 0x3F0, ids, 2, 0, tb)
go("count2 mode0", 0x410, ids, 2, 0, tb)
go("count2 mode0", 0xB70, ids, 2, 0, tb)
print("[B] controls through the same stubs")
go("count1 mode0", 0x3B0, ids, 1, 0, tb)
go("count2 mode1", 0x3B0, ids, 2, 1, tb)
go("count2 mode2", 0x3B0, ids, 2, 2, tb)
print("[C] argument shapes")
go("count2 mode0 ids=NULL", 0x3B0, 0, 2, 0, tb)
go("count2 mode0 tmo=NULL", 0x3B0, ids, 2, 0, 0)
go("count2 mode0 both NULL", 0x3B0, 0, 2, 0, 0)
go("count0x80 mode0", 0x3B0, ids, 0x80, 0, tb)
go("count0x80 mode1", 0x3B0, ids, 0x80, 1, tb)
go("count3 mode0", 0x3B0, ids, 3, 0, tb)
go("count2 mode3", 0x3B0, ids, 2, 3, tb)
go("count2 mode0 again", 0x3B0, ids, 2, 0, tb)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
