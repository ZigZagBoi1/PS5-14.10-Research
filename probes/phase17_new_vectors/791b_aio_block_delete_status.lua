-- CRASH_CLASS: LOW
-- PROBE 791b: what a block delete actually returns, and where it stops
--
-- Context: 791a deleted the first item of 24 two-item blocks in one call and
-- every status came back non-zero (zeros=0/24) even though 727d returned 0 for
-- both ids of a block. 791a printed only a count, so the value is unknown, and
-- the run died afterwards. This probe isolates:
--   [A] one block of two: poll both ids, delete the first, delete the last.
--   [B] 24 blocks: print every base id, poll all 48, delete the 24 first ids in
--       one call and print all 24 statuses.
-- No threads, no wake calls, nothing left in flight.

print("=== PROBE 791b: block delete statuses ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local data = mmap(page)
wd(data+0x20, 0x2A)   -- fd, never submitted

local function create(n)
    local o = mmap(page)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(n), uint64(1), uint64(o)) end)
    return ok, to_num(rv), rd(o) or 0
end
local function poll(ids, n)
    local o = mmap(page)
    local ok, rv = pcall(function() return mk(664)(uint64(ids), uint64(n), uint64(o)) end)
    return ok, to_num(rv), o
end
local function del(ids, n)
    local o = mmap(page)
    for i=0,n-1 do wd(o+i*4, 0xDEADBEEF) end
    local ok, rv = pcall(function() return mk(662)(uint64(ids), uint64(n), uint64(o)) end)
    return ok, to_num(rv), o
end

-- [A] one block of two
local ok1, rv1, base = create(2)
print(string.format("[A] create ok=%s rv=%s base=%08X", tostring(ok1), tostring(rv1), base))
if not (ok1 and rv1 == 0) then print("=== PROBE 791b ABORT ===") return end
local two = mmap(page)
wd(two, base); wd(two+4, base + 0x10000)
local okp, rvp, pp = poll(two, 2)
print(string.format("[A] poll ok=%s rv=%s states=%08X %08X",
    tostring(okp), tostring(rvp), rd(pp) or 0, rd(pp+4) or 0))

local one = mmap(page)
wd(one, base)
local okA1, rvA1, stA1 = del(one, 1)
print(string.format("[A] delete first: ok=%s rv=%s status=%08X", tostring(okA1), tostring(rvA1), rd(stA1) or 0))

local last = mmap(page)
wd(last, base + 0x10000)
local okA2, rvA2, stA2 = del(last, 1)
print(string.format("[A] delete last : ok=%s rv=%s status=%08X", tostring(okA2), tostring(rvA2), rd(stA2) or 0))

-- [B] 24 blocks, first items deleted in one call
local M = 24
local first, allids = {}, mmap(page)
local bases = {}
local made = 0
for k=1,M do
    local okc, rvc, b = create(2)
    if okc and rvc == 0 then
        made = made + 1
        first[made] = b
        bases[#bases+1] = string.format("%08X", b)
    end
end
print(string.format("[B] blocks=%d/%d bases=%s", made, M, table.concat(bases, " ")))
if made ~= M then print("=== PROBE 791b ABORT ===") return end

local firsts = mmap(page)
for k=1,M do
    wd(allids + (k-1)*4, first[k])
    wd(firsts + (k-1)*4, first[k])
end
for k=1,M do
    wd(allids + (M + k-1)*4, first[k] + 0x10000)
end
local okp2, rvp2, pp2 = poll(allids, M*2)
local s = {}
for k=1,M*2 do s[#s+1] = string.format("%d:%08X", k-1, rd(pp2 + (k-1)*4) or 0) end
print(string.format("[B] poll all ok=%s rv=%s states=%s", tostring(okp2), tostring(rvp2), table.concat(s, " ")))

local okB, rvB, stB = del(firsts, M)
local d = {}
local zeroct = 0
for k=1,M do
    local v = rd(stB + (k-1)*4) or 0
    if v == 0 then zeroct = zeroct + 1 end
    d[#d+1] = string.format("%d:%08X", k-1, v)
end
print(string.format("[B] delete firsts rv=%s zeros=%d/%d", tostring(rvB), zeroct, M))
print("[B] statuses: " .. table.concat(d, " "))

print("=== PROBE 791b DONE ===")
