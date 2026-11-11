-- CRASH_CLASS: LOW
-- PROBE 1224b: 653 allocates a file descriptor and the process table is nearly full.
--
-- 1224a: 653(0,0) returned -1 with errno 24 EMFILE ("Too many open files") on the FIRST call of a
-- fresh process, and 1223a-c returned 0x17/0x18/0x19 - numbers that look exactly like descriptors.
-- So blockpool_open opens something, and the earlier mmap EINVAL may have been an exhausted or
-- wrong-slot descriptor rather than a missing pager. Raise RLIMIT_NOFILE first, then retry.
print("=== PROBE 1224b: fd limit, then blockpool_open and mmap matrix ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq64(a) local lo=rd(a) local hi=rd(a+4) return hi*4294967296 + (lo % 4294967296) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
print(string.format("[0] pid=%d", N(mk(20)())))
local rl = memory.alloc(16)
for i=0,12,4 do wd(rl+i,0) end
call("getrlimit NOFILE(8)", function() return mk(194)(uint64(8),uint64(rl),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    cur=%d max=%d", rq64(rl), rq64(rl+8)))
local cur, mx = rq64(rl), rq64(rl+8)
if mx > cur then
    wd(rl, mx % 4294967296) wd(rl+4, math.floor(mx/4294967296))
    wd(rl+8, mx % 4294967296) wd(rl+12, math.floor(mx/4294967296))
    call("setrlimit NOFILE=max", function() return mk(195)(uint64(8),uint64(rl),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    for i=0,12,4 do wd(rl+i,0) end
    call("getrlimit again", function() return mk(194)(uint64(8),uint64(rl),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("    now cur=%d max=%d", rq64(rl), rq64(rl+8)))
end
print("[1] blockpool_open")
local h = -1
for i = 1, 3 do
    h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
    print(string.format("    653 #%d = 0x%X err=%s", i, h, ES()))
    if h >= 0 and h < 0x10000 then break end
end
if h < 0 or h >= 0x10000 then print("[1] no descriptor"); print("=== DONE ===") return end
print("[2] mmap matrix with fd = that descriptor")
local va = 0
local prots = {3, 0x33, 0}
local flags = {1, 2, 0x1002, 0x11, 0x12, 0x1001}
for i = 1, #prots do
    for j = 1, #flags do
        local rv = N(mk(477)(uint64(0),uint64(0x10000),uint64(prots[i]),uint64(flags[j]),uint64(h),uint64(0)))
        print(string.format("    prot=0x%X flags=0x%X -> 0x%X err=%s", prots[i], flags[j], rv, ES()))
        if rv > 0x10000 and rv < 0x7FFFFFFFFF then va = rv break end
    end
    if va ~= 0 then break end
end
if va ~= 0 then
    print(string.format("[3] mapped 0x%X; 547 follows", va))
    local ob = memory.alloc(0x40)
    for i=0,0x3C,4 do wd(ob+i,0xDEADBEEF) end
    call("547", function() return mk(547)(uint64(va),uint64(ob),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    local s={} for i=0,5 do s[#s+1]=string.format("%08X",rd(ob+i*4)) end
    print("    547 record: " .. table.concat(s," "))
else
    print("[3] no mapping from any prot/flags shape")
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
