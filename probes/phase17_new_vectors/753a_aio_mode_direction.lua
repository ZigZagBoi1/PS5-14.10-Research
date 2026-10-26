-- CRASH_CLASS: LOW
-- PROBE 753a: which direction does each aio mode take?
--
-- 752a: with no peer feed, op 0 and op 1 stay in flight (state 2) and op 2/3
-- never start (state 1). In 744b a peer feed completed the op-0 request and
-- the buffer received the socket bytes. So +0x24 is not a direction selector.
--
-- The create call's fourth argument (mode) is 1..3 and has only ever been 1.
-- A write would complete without any peer input and the peer would become
-- readable. A read stays pending until the peer is fed.
--
-- For each mode: fill the buffer with a known pattern, create, sleep, poll the
-- peer (readable => the request wrote to the socket), then feed the peer and
-- poll the request and the buffer. Delete each object once it is complete.

print("=== PROBE 753a: AIO MODE DIRECTION ===")
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
local sc_pair = mk(135); local sc_read = mk(3); local sc_write = mk(4); local sc_poll = mk(209)
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
    zero(pfd, 32); wd(pfd, s1); wd(pfd+4, 1)
    call(sc_poll, pfd, 1, 0, 0, 0, 0)
    return rd(pfd+6)
end

local D = to_num(memory.alloc(0x2000)); local buf = to_num(memory.alloc(0x2000)); local res = to_num(memory.alloc(0x2000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local ds = to_num(memory.alloc(0x400))
local feed = to_num(memory.alloc(64)); zero(feed, 64)
for k=0,3 do wd(feed+k*4, 0x5A5A5A5A) end
zero(D,0x2000); zero(buf,0x2000); zero(res,0x2000); zero(st,0x400); zero(ds,0x400)

local function poll_state(id)
    wd(ids, id); zero(st,0x40)
    call(mk(664), ids, 1, st, 0, 0, 0)
    return rd(st)
end

for mode=1,3 do
    zero(D,0x100); zero(res,0x40); zero(st,0x40); zero(ds,0x40); zero(buf,0x40)
    for k=0,3 do wd(buf+k*4, 0x41414141) end
    wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
    wq(D+0x10, uint64(buf)); wq(D+0x18, uint64(res))
    wd(D+0x20, s0); wd(D+0x24, 0)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, mode, ids, 0)
    local id = rd(ids)
    print(string.format("[M%d] create ret=%s id=%08X", mode, tostring(cr), id))
    if id ~= 0 and id ~= -1 then
        sleep_ms(40)
        print(string.format("[M%d] before feed: state=%08X peer_revents=%s", mode, poll_state(id), tostring(peer_ready())))
        local rev = peer_ready()
        if type(rev) == "number" and (rev % 2) == 1 then
            zero(rbuf, 0x40)
            local n = call(sc_read, s1, rbuf, 16, 0, 0, 0)
            print(string.format("[M%d]   peer read=%s bytes=%X %X %X %X", mode, tostring(n), rd(rbuf), rd(rbuf+4), rd(rbuf+8), rd(rbuf+12)))
        end
        print(string.format("[M%d] feed -> %s", mode, tostring(call(sc_write, s1, feed, 16, 0, 0, 0))))
        sleep_ms(60)
        print(string.format("[M%d] after feed: state=%08X buf=%X %X res=%X %X", mode, poll_state(id), rd(buf), rd(buf+4), rd(res), rd(res+4)))
        wd(ids, id); zero(ds,0x40); call(mk(662), ids, 1, ds, 0, 0, 0)
        print(string.format("[M%d] delete=%08X", mode, rd(ds)))
    end
    print(string.format("[M%d] health=%s", mode, tostring(call(syscall.pipe, 20,0,0,0,0,0,0))))
end
print("=== 753a DONE ===")
