-- CRASH_CLASS: LOW
-- PROBE 1225a: four first-contact calls from routes R9, R8, R7 and R5, in ascending risk.
--   604 dl_get_metadata   - five args behind the tag test [ctx+0x58] == 0x4800000000000007
--   572 virtual_query     - flag mask 1 when proc+0xc81 == 0, 0xfffcfffe when it is not
--   656 dynlib_get_info_for_libdbg - gate is the debug-unit predicates 0xacce10/0xacce50
--   560 debug_init        - one-shot caller-chosen dword into a kernel global, last because it writes
print("=== PROBE 1225a: 604 / 572 / 656 / 560 first contact ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
local pid = N(mk(20)())
print(string.format("[0] pid=%d libkernel=0x%X", pid, N(libkernel_base)))
local buf = memory.alloc(0x400)
local function zero(n) for i=0,n-4,4 do wd(buf+i,0) end end

print("[A] 604 dl_get_metadata")
zero(0x100)
call("604 zeros", function() return mk(604)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
zero(0x100)
call("604 pid,buf", function() return mk(604)(uint64(pid),uint64(buf),uint64(0x100),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    buf[0..3]=%08X %08X", rd(buf), rd(buf+4)))

print("[B] 572 virtual_query on a page we own")
local va = N(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    owned va=0x%X err=%s", va, ES()))
if va > 0x10000 then
    for _, fl in ipairs({0,1,2,0x10000,0x10002}) do
        zero(0x100)
        call(string.format("572 flags=0x%X", fl), function() return mk(572)(uint64(va),uint64(fl),uint64(buf),uint64(0),uint64(0),uint64(0)) end)
        print(string.format("      out=%08X %08X %08X %08X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
    end
end

print("[C] 656 dynlib_get_info_for_libdbg")
zero(0x200)
wd(buf, 0x160)
call("656 id=0", function() return mk(656)(uint64(0),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    buf=%08X %08X %08X %08X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
zero(0x200)
wd(buf, 0x160)
call("656 id=1", function() return mk(656)(uint64(1),uint64(buf),uint64(0),uint64(0),uint64(0),uint64(0)) end)

print("[D] 560 debug_init: write-once oracle")
call("560(0x41)", function() return mk(560)(uint64(0x41),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("560(0x41) again", function() return mk(560)(uint64(0x41),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("560(0x42)", function() return mk(560)(uint64(0x42),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
