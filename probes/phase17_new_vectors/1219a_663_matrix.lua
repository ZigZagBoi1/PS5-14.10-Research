-- CRASH_CLASS: MODERATE
-- PROBE 1219a: which argument combination makes 663 return EINVAL once argument 4 works.
--
-- 1218a proved libkernel+0x3B0+7 is a real "mov r10, rcx ; syscall" trampoline by a differential
-- test (mode 0 -> status written, mode 4 -> EINVAL and status untouched). 1217a then produced
-- EINVAL for count 2 with two real pending ids, while count 1 with a real id only timed out.
-- This probe separates count, mode, timeout and id validity.

print("=== PROBE 1219a: 663 matrix through the trampoline ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local pid0 = N(mk(20)())
local lk = N(libkernel_base)
local TR = lk + 0x3B7
print(string.format("[0] pid=%d trampoline=0x%X", pid0, TR))

local ids = memory.alloc(32)
local out = memory.alloc(32)
local tb  = memory.alloc(8)
local function zero_ids() for i=0,7 do wd(ids+i*4,0) end end
local function show(tag, n, mode, tmo)
    zero_ids()
    if n == 2 then wd(ids, 0) wd(ids+4, 0) end
    wd(tb, tmo)
    wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA) wd(out+8,0xAAAAAAAA)
    local ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, n, out, mode, tb, 0) end)
    local h,l = hilo(rv)
    print(string.format("  %-22s n=%d mode=%d tmo=%-5d ret=0x%08X_%08X err=%s out=%08X %08X %08X",
        tag, n, mode, tmo, h, l, ES(), rd(out), rd(out+4), rd(out+8)))
end

print("[A] invalid ids (0) - isolates count, mode and timeout from real objects")
show("zero id, n=1, m=0", 1, 0, 0)
show("zero ids, n=2, m=0", 2, 0, 0)
show("zero ids, n=2, m=0, tmo", 2, 0, 2000)
show("zero ids, n=2, m=1", 2, 1, 0)
show("zero ids, n=2, m=2", 2, 2, 0)
show("zero ids, n=3, m=0", 3, 0, 0)

print("[B] two real pending aio reads")
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  socketpair %d,%d", fd0, fd1))
if fd0 > 0 then
    local buf = memory.alloc(0x100)
    local ba = 0
    do local ok,v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
    local reqs = memory.alloc(0x28*2)
    for i=0,0x28*2-1,4 do wd(reqs+i,0) end
    for i=0,1 do
        local r = reqs + i*0x28
        wd(r+0x08,0x10)
        wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
        wd(r+0x20, fd0)
    end
    wd(ids,0) wd(ids+4,0)
    mk(669)(uint64(0x1001),uint64(reqs),uint64(2),uint64(3),uint64(ids))
    local id0, id1 = rd(ids), rd(ids+4)
    print(string.format("  id0=0x%08X id1=0x%08X  (slot=%04X gens %d/%d)", id0, id1, id0 % 0x10000, math.floor(id0/0x10000), math.floor(id1/0x10000)))
    local keep0, keep1 = id0, id1
    wd(ids, keep0) wd(ids+4, keep1)
    wd(tb, 0) wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA)
    local ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, 2, out, 0, tb, 0) end)
    local h,l = hilo(rv)
    print(string.format("  real ids n=2 m=0 tmo=0 ret=0x%08X_%08X err=%s out=%08X %08X", h,l,ES(),rd(out),rd(out+4)))
    wd(ids, keep0) wd(ids+4, keep1)
    wd(tb, 2000) wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA)
    ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, 2, out, 0, tb, 0) end)
    h,l = hilo(rv)
    print(string.format("  real ids n=2 m=0 tmo=2000 ret=0x%08X_%08X err=%s out=%08X %08X", h,l,ES(),rd(out),rd(out+4)))
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
