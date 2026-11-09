-- CRASH_CLASS: MODERATE (the same call shapes 1343a just ran without a death;
--               adds only a canary scan of the three pages afterwards)
-- PROBE 1343b: do the 0x4141-shaped calls write into the pages they are given
--
-- prior art:
--   probes/phase35_dead_end_reruns/1343a_arg23_classes.lua
--   results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt
--       (U1,U2,U3) returns 0 for 547, 588, 592, 598, 638, 639, 640 -- seven calls
--       that accepted three garbage pointers; 20 numbers read arg2, 10 read arg3
--   docs/ARG1_CLASSES_14_10.md   no handler copies anything back from a
--       supervisor pointer, but that only tested arg1 and only compared returns
--   docs/SYS_611_613_615_STATS_FAMILY_13_60.md  615's out-pointer on the self path
--   probes/phase17_new_vectors/1194b_601_arg2_write_leak.lua   601 arg2 as a write target
--
-- 1343a compared return values. A handler that copies a struct into arg2 and
-- returns 0 looks exactly like a handler that ignores arg2, so the only way to
-- tell them apart is to look at the memory afterwards. Every page is filled with
-- 0x4141414141414141 first; a qword that is no longer that value was written by
-- the kernel. A value in the 0xFFFF8xxx_xxxxxxxx range would be a kernel pointer
-- in a user buffer, which is the actual prize; anything else is a write channel.
--
-- The scan covers the first 0x400 bytes of each page plus one checkpoint qword at
-- the end, which is where a struct copy with a wrong size would show up.

print("=== PROBE 1343b: DO THESE CALLS WRITE INTO THEIR POINTER ARGUMENTS ===")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local o,e=pcall(function() return get_error_string() end) if o then return tostring(e) end return "?" end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end) if ok then return to_num(v) % 4294967296 end return nil end
local function page(n)
    local o,a=pcall(function() return mk(477)(uint64(0), uint64(n), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    if not o then return 0 end
    local v=to_num(a)
    if v==0 or v>=0x800000000000 then return 0 end
    return v
end
local SZ = 0x4000
local POISON = 0x41414141
local CHECK  = 0x42424242
local function poison(p)
    for x=0,SZ-8,4 do wd(p+x, POISON) end
    wd(p+SZ-8, CHECK); wd(p+SZ-4, CHECK)
end

local U1, U2, U3 = page(SZ), page(SZ), page(SZ)
if U1==0 or U2==0 or U3==0 then print("[!] mmap failed"); return end
local N = 0x00007FFF00000000
print(string.format("[0] U1=0x%X U2=0x%X U3=0x%X absent=0x%X", U1, U2, U3, N))

local sa = memory.alloc(0x80)
for i = 0, 0x70, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local okI, rvI = pcall(function() return mk(416)(uint64(12), uint64(sa), uint64(0)) end)
if not (okI and to_num(rvI) == 0) then
    print("[!] SIGSYS could not be ignored; not spending the console")
    print("=== PROBE 1343b STOPPED ===")
    return
end
print("[0] sigaction(12, SIG_IGN) -> 0")

-- scan the first 0x400 bytes plus the end checkpoint; returns the number of
-- dwords the kernel changed and up to four "offset=value" pairs
local function scan(p, tag, n)
    local cnt, hits = 0, {}
    for x=0,0x3FC,4 do
        local v = rd(p+x)
        if v == nil then break end
        if v ~= POISON then
            cnt = cnt + 1
            if #hits < 4 then hits[#hits+1] = string.format("%x=%x", x, v) end
        end
    end
    local e1, e2 = rd(p+SZ-8), rd(p+SZ-4)
    local endbad = (e1 ~= CHECK) or (e2 ~= CHECK)
    if cnt > 0 or endbad then
        print(string.format("W %d %s cnt=%d end=%s,%s %s", n, tag, cnt,
            e1 and string.format("%x", e1) or "?", e2 and string.format("%x", e2) or "?",
            table.concat(hits, " ")))
        return 1
    end
    return 0
end

local SKIP = {[561]=1,[562]=1,[570]=1,[571]=1,[573]=1,[609]=1,[614]=1,[621]=1,[622]=1,[631]=1,[650]=1,[651]=1,[668]=1,[673]=1}
local Z = uint64(0)

local total = 0
for n = 532, 676 do
    if not SKIP[n] then
        poison(U1); poison(U2); poison(U3)
        local ok, rv = pcall(function() return mk(n)(uint64(U1), uint64(U2), uint64(U3), Z, Z, Z) end)
        local rvv = "EXC"
        if ok then rvv = tostring(to_num(rv)) end
        local a = scan(U1, "a1", n)
        local b = scan(U2, "a2", n)
        local c = scan(U3, "a3", n)
        if a + b + c == 0 then
            if n % 20 == 0 then print(string.format("clean %d rv=%s", n, rvv)) end
        else
            print(string.format("     %d rv=%s err=%s", n, rvv, ES()))
            total = total + 1
        end
    end
end

print("")
print(string.format("[E] numbers with a write: %d", total))
print("[E] alive pid=" .. tostring(to_num(mk(20)())))
print("=== PROBE 1343b COMPLETE ===")
