-- CRASH_CLASS: HIGH -- 601 cmd 0x11 killed the process for an all-zero page; this fills the
-- page with a mapped user address and asks whether the kill was a NULL dereference.
-- PROBE 1476a: does 601 cmd 0x11 dereference a pointer taken out of the caller's page?
--
-- Context:
--   1393a measured the argument shape of 601 cmd 0x11: arg1 must be NULL (any non-null arg1 gives
--   EINVAL(22)) and arg2 is range-checked as a user pointer (a kernel address gives EFAULT(14)).
--   1394a then filled the page with 0xFFFFFFFFC1000000 and the process died on the first call.
--   1400a repeated it with an ALL-ZERO page and the process died again.
--
--   A kill on an all-zero page is the interesting half.  If the handler read a field, copied it
--   to a register and dereferenced it, then a zero page means a NULL dereference -- and a page
--   full of a valid user address would survive.  That would make 601 cmd 0x11 a kernel
--   dereference of a caller-chosen pointer, which is the primitive this project has been hunting:
--   the kernel would then read from (or write through) an address we choose.  If the dereference
--   is a raw load rather than copyin/copyout, SMAP still refuses a USER address, so this run also
--   tells the two apart:
--       [A] page qword-filled with a mapped user VA   -> survives only if the field goes through
--                                                          copyin/copyout or the raw-deref path
--                                                          does not exist
--       [B] page dword-filled with the low 32 bits of that VA (the field may be truncated)
--       [C] page qword-filled with the kernel image base (control: must die if the field is
--           dereferenced at all, because the image is supervisor-only)
--   Every call is preceded by its own print, and the 601(0x00) control runs before the risky
--   calls, so a death names its phase.  A surviving call also reports the marker page's contents
--   afterwards, because a write through our pointer would land there.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1393a_sys601_cmd11_kernel_arg2_20261109_141450.txt (arg shape)
--   results/phase35_dead_end_reruns/1394a_sys601_cmd11_field_deref_20261109_141535.txt (K1 fill dies)
--   results/phase36_realargs/1400a_sys601_cmd11_struct_20261109_144119.txt (zero page dies)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (command map; 0x11 is not in the 13.60 table)

print("=== PROBE 1476a: 601 CMD 0x11, POINTER FIELD ===")
print("")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return N(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),v) end) end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(uint64(a)) end) if ok then local h,l=0,N(v)%4294967296 if type(v)=="table" and v.h then h=v.h end return h*4294967296+l end return nil end
local function hx(v) if v==nil then return "????????????????" end return string.format("%016X", (v % 0x10000000000000000)) end

local pid0 = N(mk(20)())
print(string.format("canary getpid=%d", pid0))

local sa = memory.alloc(0x80)
for i=0,0x7C,8 do pcall(function() memory.write_qword(sa+i,uint64(0)) end) end
pcall(function() memory.write_qword(sa,uint64(1)) end)
for _,s in ipairs({5,6,7,8,12,24,25,26,30,31}) do
    pcall(function() return mk(416)(uint64(s),uint64(sa),uint64(0)) end)
end

local BUF = memory.alloc(0x400)
local PAGE = as_addr(BUF)
for i=0,0x3FC,4 do wd(PAGE+i, 0) end

-- a marker page the handler would write into if it followed our pointer
local MB = memory.alloc(0x400)
local MARK = as_addr(MB)
for i=0,0x3FC,8 do wq(MARK+i, 0x1111111111111111) end

local function fill_qword(v)
    for i=0,0x3FC,8 do wq(PAGE+i, v) end
end
local function fill_dword(v)
    for i=0,0x3FC,4 do wd(PAGE+i, v % 4294967296) end
end
local function marker_state()
    local changed, first = 0, nil
    for i=0,0x3FC,8 do
        local v = rq(MARK+i)
        if v ~= 0x1111111111111111 then
            changed = changed + 1
            if first == nil then first = v end
        end
    end
    return changed, first
end

local function ctl(tag)
    local out = memory.alloc(0x200)
    local oa = as_addr(out)
    for i=0,0x1FC,4 do wd(oa+i, 0) end
    local rv = N(mk(601)(uint64(0x00), uint64(oa), uint64(0), uint64(0x100), uint64(0), uint64(0)))
    print(string.format("   %s control 601(0x00) -> rv=%d out[0]=%08X", tag, rv, (function() local ok,v=pcall(function() return memory.read_dword(uint64(oa)) end) if ok then return N(v)%4294967296 end return 0 end)()))
    return rv
end

local function call11(tag)
    print(string.format("   %s: 601(0x11, 0, page=0x%X, 0, 0x100)", tag, PAGE))
    local ok, rv = pcall(function() return mk(601)(uint64(0x11), uint64(0), uint64(PAGE), uint64(0), uint64(0x100), uint64(0)) end)
    if not ok then print(string.format("   %s -> EXC", tag)) return nil end
    local n = N(rv)
    if n == -1 then
        print(string.format("   %s -> -1 errno=%s", tag, es()))
    else
        print(string.format("   %s -> %d", tag, n))
    end
    local ch, first = marker_state()
    print(string.format("   %s marker changed=%d first=%s", tag, ch, hx(first)))
    return n
end

ctl("pre")
print("")

print("[A] qword fill = mapped user page 0x" .. string.format("%X", MARK))
fill_qword(MARK)
call11("A")

print("")
print("[B] dword fill = low 32 bits of that page")
fill_dword(MARK)
call11("B")

print("")
print("[C] qword fill = kernel image base (control)")
fill_qword(0xFFFFFFFFC1000000)
call11("C")

print("")
fill_qword(0)
call11("D-zero")
ctl("post")

print("")
print(string.format("[Z] alive pid=%d (was %d)", N(mk(20)()), pid0))
print("")
print("=== PROBE 1476a COMPLETE ===")
