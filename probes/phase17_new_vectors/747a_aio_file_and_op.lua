-- CRASH_CLASS: HIGH
-- PROBE 747a: aio against a file descriptor, and the operation field
--
-- 744b showed the socket worker validates the buffer. A vnode read may go
-- through a different completion path. This also tries the descriptor's second
-- dword at +0x24, which no probe has set yet, as an operation selector.
--
-- A: open a few paths, print the fds
-- B: block read from a file with a valid buffer, then with 0x1000
-- C: op field 0..3 on the socket: which direction does each take

print("=== PROBE 747a: AIO FILE AND OP ===")
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
local sc_open = mk(5); local sc_write = mk(4); local sc_pair = mk(135)
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
print("[A] pid="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))

local paths = {"/savedata0/thread.lua", "/app0/sce_sys/param.sfo", "/dev/zero", "/dev/random"}
local fds = {}
for i=1,#paths do
    local p = path(paths[i])
    local fd = call(sc_open, p, 0, 0, 0, 0, 0)
    print(string.format("[A] open %s -> %s", paths[i], tostring(fd)))
    if type(fd) == "number" and fd > 2 then fds[#fds+1] = {paths[i], fd} end
end

local D = to_num(memory.alloc(0x4000)); local buf = to_num(memory.alloc(0x4000)); local res = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x4000); zero(buf,0x4000); zero(res,0x4000); zero(st,0x400); zero(ds,0x400)

local function attempt(tag, fd, b, op)
    zero(D,0x100); zero(res,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(res))
    wd(D+0x20, fd); wd(D+0x24, op or 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return end
    sleep_ms(30)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state=%08X res=%X %X %X %X buf=%X", tag, rd(st), rd(res), rd(res+4), rd(res+8), rd(res+12), rd(b)))
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete=%08X", tag, rd(ds)))
end

for i=1,#fds do
    attempt(string.format("[B] file %s valid buf", fds[i][1]), fds[i][2], buf, 0)
end
if #fds > 0 then
    attempt(string.format("[B] file %s buf=0x1000", fds[1][1]), fds[1][2], 0x1000, 0)
end
print("[B] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))

local pairfds = to_num(memory.alloc(64)); wq(pairfds, uint64(0))
print("[C] socketpair -> "..tostring(call(sc_pair, 1, 1, 0, pairfds, 0, 0)))
local s0 = rd(pairfds); local s1 = rd(pairfds+4)
local w = to_num(memory.alloc(64))
for k=0,3 do wd(w+k*4, 0x4B4B4B4B) end
for op=0,3 do
    attempt(string.format("[C] socket op=%d", op), s0, buf, op)
end
print("[C] peer write -> "..tostring(call(sc_write, s1, w, 16, 0, 0, 0)))
sleep_ms(50)
print(string.format("[C] buf after peer write: %X %X %X %X", rd(buf), rd(buf+4), rd(buf+8), rd(buf+12)))
print("[D] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 747a DONE ===")
