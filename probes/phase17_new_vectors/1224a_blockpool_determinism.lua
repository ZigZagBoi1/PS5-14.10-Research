-- CRASH_CLASS: LOW
-- PROBE 1224a: does blockpool_open(653) depend on process vm state?
--
-- 1223a/b/c returned 0x17, 0x18, 0x19 for 653(0,0); 1223d returned -1 for the same call. The only
-- structural difference is that 1223d never mapped an anonymous page first (1223a/b/c all did).
-- Four calls in one process separate "needs a prior mapping" from "allocation-dependent".
print("=== PROBE 1224a: 653 determinism ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
print(string.format("[0] pid=%d", N(mk(20)())))
call("653 #1", function() return mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("653 #2", function() return mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[1] now map one anonymous page")
local va = N(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    mmap -> 0x%X err=%s", va, ES()))
call("653 #3", function() return mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("653 #4", function() return mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[2] and one with flags/word2 variants")
for _, f in ipairs({1, 0x10, 0x100, 0x10000000}) do
    call(string.format("653 flags=0x%X", f), function() return mk(653)(uint64(f),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
