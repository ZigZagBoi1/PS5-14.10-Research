-- CRASH_CLASS: LOW
-- PROBE 1224c: fresh session - blockpool slot, then the mmap matrix on that exact descriptor.
--
-- 1224a/b showed blockpool handles are slots in a small consumable table and 1223a-c's mmap
-- matrix ran against slots 23-25 with EINVAL everywhere. This run takes the first slot of a fresh
-- session and immediately tries every prot/flags shape against it, then opens one more slot to see
-- whether the numbers are consecutive.
print("=== PROBE 1224c: fresh blockpool slot and mmap ===")
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
print(string.format("[0] pid=%d libkernel=0x%X", N(mk(20)()), N(libkernel_base)))
local h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[1] 653 slot = 0x%X (%d) err=%s", h, h, ES()))
if h < 0 or h >= 0x10000 then print("[1] no slot"); print("=== DONE ===") return end
print("[2] mmap matrix on this slot")
local va = 0
local shapes = {{3,1},{3,2},{3,0x1002},{3,0x11},{3,0x12},{0x33,1},{0x33,0x1002},{0,1}}
for i=1,#shapes do
    local pr, fl = shapes[i][1], shapes[i][2]
    local rv = N(mk(477)(uint64(0),uint64(0x10000),uint64(pr),uint64(fl),uint64(h),uint64(0)))
    print(string.format("    prot=0x%X flags=0x%X -> 0x%X err=%s", pr, fl, rv, ES()))
    if rv > 0x10000 and rv < 0x7FFFFFFFFF then va = rv break end
end
if va ~= 0 then
    print(string.format("[3] mapped 0x%X", va))
    local ob = memory.alloc(0x40)
    for i=0,0x3C,4 do wd(ob+i,0xDEADBEEF) end
    call("547", function() return mk(547)(uint64(va),uint64(ob),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    local s={} for i=0,5 do s[#s+1]=string.format("%08X",rd(ob+i*4)) end
    print("    547 record: " .. table.concat(s," "))
    wd(va, 0x41424344)
    print(string.format("    write/read: 0x%08X", rd(va)))
    call("654 on it", function() return mk(654)(uint64(va),uint64(0x10000),uint64(3),uint64(0),uint64(0),uint64(0)) end)
else
    print("[3] no mapping")
end
print("[4] one more slot, to see if the numbers are consecutive")
local h2 = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("    653 second slot = 0x%X err=%s", h2, ES()))
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
