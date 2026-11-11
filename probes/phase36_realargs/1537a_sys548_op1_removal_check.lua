-- CRASH_CLASS: LOW
-- PROBE 1537a: what does 548 op 1 do to a range, and does op 4 remove one?
-- Answered from the 674 map table and the 547 record, never from a load.
--
-- Context: this is the last unresolved branch of the 548 contract.
--
--   1534c: op 1 returned rv=0 processed=1 on a range created by 548 op 3, and
--          the NEXT READ of that range faulted and killed the loader.
--   1480b: has NO op-1 observation at all. Its capture prints a line labelled
--          'op=1 prot=0 len=0x4000 on D', but the probe never called set_entry
--          before it: the last write to the entry buffer was
--          set_entry(A, 0, 0x4000, 3, 2). That rung therefore re-ran op 2 on A,
--          which is exactly what the capture shows (A still prot 3, D
--          untouched, D still holding 33334444). It was cited for weeks as
--          evidence that op 1 leaves a range alone; it is not evidence of
--          anything about op 1.
--
-- So there is exactly ONE op-1 datum in the corpus, and it is a fault. Three
-- readings survive it:
--   (a) op 1 removes the range and the read faulted on an unmapped page;
--   (b) op 1 leaves the range present but unusable - unbacked, or at a
--       protection without READ - so the page is still described by the map;
--   (c) op 1 did nothing and the fault came from something else 1534c did.
--
-- 674 (the whole VM map as 72-byte records) and 547 (a per-range record) answer
-- (a) against (b) without touching the memory: if the record is gone, the range
-- is gone; if the record is there with a different span or protection, the
-- range exists in a state the previous run never looked at. No load is
-- performed on any range after a 548 call, so no outcome can turn a fault into
-- a false 'removed' reading.
--
-- STATIC READING of the five cases (13.60 body 0xffffffff8b47be60). The bodies
-- sit at strictly ascending addresses and the two measured ops pin the order:
--   op 0 @0x8b47bff3  four gates, then the elevated helper 0x8b47d540, else the
--                     descriptor path at 0x8b47c1c5
--   op 2 @0x8b47c0b0  alignment, then vm_map_protect 0x8ac8bdb0   (measured)
--   op 3 @0x8b47c11e  alignment, builds {start,len,prot,flags|0x1000,fd=-1,0},
--                     then maps                                      (measured)
--   the remaining two cases are 0x8b47c088 and 0x8b47c185. 0x8b47c088 does not
--   touch the map at all: it normalises the protection byte (WRITE implies
--   READ) and appends the entry to a pending list via 0x8b47bf1a (malloc
--   0x8adfb880, copy 0x8ac19be0, link at [rbp-0x70]). 0x8b47c185 does alignment
--   checks and calls the munmap helper 0x8b478bb0 in line.
-- Which of those two is op 1 is NOT settled statically, so this probe runs op 1
-- on both a 477 range and an op-3 range.
--
-- If op 1 is the queue, the entry is applied by the flush 0x8b47c3b0 at end of
-- loop, through the bulk applier 0x8ac8dc10 - a different validator from op 2's
-- vm_map_protect. The flush is not privilege-gated for a game process (its two
-- capability tests return 0 when [td+0x140] bits are clear), so the apply
-- should happen. [H] asks whether it does, and [I] asks whether it accepts a
-- protection that op 2 refuses.
--
-- -- prior art:
--   results/phase36_realargs/1534c_sys548_op0_on_live_range_20261110_142452.txt
--       op 1 on an op-3 range: rv=0 processed=1, next read faulted
--   results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt
--       ops 0/3/4 on a 477 range all rv=0 with the range unchanged; the
--       'op=1' line in it actually re-ran op 2 on A (see the header above)
--   results/phase36_realargs/1479d_sys548_map_unmap_20261109_195406.txt
--       ops 0-4 all EINVAL: every rung used len=0x1000, i.e. died at the
--       16 KiB alignment gate before dispatch. No op-1 information.
--   results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt
--       op 2 contract, the 16 KiB gate, 547 protection at +0x10
--   results/phase36_realargs/1478a_dev_mmap_wrap_ftruncate_20261109_192453.txt
--       547 record fields {start, end, prot, flags}
--   docs/VM_LAYER_14_10.md sections 8-13

print("=== PROBE 1537a: 548 OP 1 / OP 4 - REMOVAL, SHAPE, OR GATE ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

local sc477, sc73, sc547, sc548, sc674 = mk(477), mk(73), mk(547), mk(548), mk(674)

local sa = memory.alloc(0x20)
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))
print("")

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x20)
local cnt = memory.alloc(0x10)

local function set_entry(start, offset, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", offset))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

-- the tag is printed BEFORE the call: a fatal op leaves the capture naming the
-- shape that killed it, which is the only record of the experiment
local function v548(tag, arg2)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("   -> %-46s", tag))
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(arg2 or 0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    local proc = N(memory.read_dword(cnt))
    print(string.format("      rv=%-16s processed=%d", tostring(r), proc))
    return r, proc
end

-- 547 record: {start lo@0x00 hi@0x04, end lo@0x08 hi@0x0C, prot@0x10, flags@0x14}
local function rec547(addr)
    for i = 0, 0x1C do pcall(function() memory.write_byte(rec + i, 0) end) end
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    local sl = N(memory.read_dword(rec + 0x00))
    local sh = N(memory.read_dword(rec + 0x04))
    local el = N(memory.read_dword(rec + 0x08))
    local eh = N(memory.read_dword(rec + 0x0C))
    return sl + sh * 4294967296, el + eh * 4294967296, N(memory.read_dword(rec + 0x10))
end

-- the interlock that makes every later phase safe: the 547 record must describe
-- exactly the 16 KiB range this probe created. The map coalesces neighbours, so
-- '547 answered at U' does not mean U is still ours.
local function own(addr, len)
    if addr == nil then return false, "no address" end
    local s, e, p = rec547(addr)
    if s == nil then return false, "547 fails" end
    if s ~= addr or e ~= addr + len then
        return false, string.format("record covers 0x%X-0x%X, not 0x%X-0x%X", s, e, addr, addr + len)
    end
    return true, string.format("prot=0x%X", p)
end

-- 674: the whole map, 72-byte records {start@0x00, end@0x08, prot@0x18, name@0x21}
local mbuf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(mbuf + i, uint64(0)) end) end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

local function scan674()
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local ok, rv = pcall(function()
        return sc674(uint64(mbuf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000), uint64(0))
    end)
    if not ok or N(rv) ~= 0 then return nil, nil, {} end
    local n = 0
    pcall(function() n = N(memory.read_dword(cnt)) end)
    -- a real map on this console is ~320 records; zero means the call wrote
    -- nothing, which must never be read as an empty map
    if n <= 0 then return nil, nil, {} end
    if n > 400 then n = 400 end
    local rows = {}
    for i = 0, n - 1 do
        local b = mbuf + i * 72
        local s = u64at(b, 0x00)
        local e = u64at(b, 0x08)
        local pr = 0
        pcall(function() pr = N(memory.read_dword(b + 0x18)) end)
        local name = ""
        for k = 0, 27 do
            local ch = 0
            pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
            if ch == 0 or ch < 32 or ch >= 127 then break end
            name = name .. string.char(ch)
        end
        rows[#rows + 1] = { s = s, e = e, pr = pr, name = name }
    end
    return N(rv), n, rows
end

local function find_in(rows, addr)
    for i = 1, #rows do
        local r = rows[i]
        if addr >= r.s and addr < r.e then return r end
    end
    return nil
end

local function describe(rows, addr)
    local r = find_in(rows, addr)
    if r == nil then return "absent from 674" end
    return string.format("674 has 0x%X-0x%X prot=0x%X %s", r.s, r.e, r.pr, r.name)
end

-- prints the exact 547 record and the covering 674 record, returns both
local function state(tag, addr)
    local s, e, p = rec547(addr)
    local _, n, rows = scan674()
    if n == nil then
        print(string.format("   %-26s 674 FAILED (do not read this as absent)", tag))
        return p, nil
    end
    local rng = "547 has no record"
    if s ~= nil then rng = string.format("547 0x%X-0x%X prot=0x%X", s, e, p) end
    print(string.format("   %-26s n=%-4d %-44s | %s", tag, n, rng, describe(rows, addr)))
    return p, rows
end

-- one verdict routine, used everywhere, so no phase invents its own taxonomy
local function verdict(tag, addr, len, rv, proc)
    if rv == nil then
        print(string.format("   VERDICT %s: not run", tag))
        return
    end
    if rv == -999 then
        print(string.format("   VERDICT %s: EXCEPTION (pcall failed) - not a kernel refusal", tag))
        return
    end
    if rv ~= 0 then
        print(string.format("   VERDICT %s: REFUSED rv=%s - nothing was applied, question stays open", tag, tostring(rv)))
        return
    end
    if proc ~= nil and proc ~= 1 then
        print(string.format("   VERDICT %s: NOT DISPATCHED (rv=0 but processed=%d) - the entry never reached the op body", tag, proc))
        return
    end
    local s, e, p = rec547(addr)
    local _, n, rows = scan674()
    if n == nil and s == nil then
        print(string.format("   VERDICT %s: neither 547 nor 674 answered, no verdict", tag))
        return
    end
    local inmap = (n ~= nil) and (find_in(rows, addr) ~= nil)
    if s == nil and n ~= nil and not inmap then
        print(string.format("   VERDICT %s: REMOVED (547 has no record and 674 has no record)", tag))
    elseif s == nil and n ~= nil then
        print(string.format("   VERDICT %s: INCONSISTENT - 674 still lists the range, 547 cannot describe it", tag))
    elseif s == addr and e == addr + len then
        print(string.format("   VERDICT %s: PRESENT, exact span, prot=0x%X", tag, p))
    else
        print(string.format("   VERDICT %s: RESHAPED to 0x%X-0x%X prot=0x%X (split or merged)", tag, s, e, p))
    end
end

-- ---------------------------------------------------------------- [A] ranges
print("--- [A] build the ranges ---")
local pv = sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local U1 = N(pv)
print(string.format("[A] 477 rv=%d", U1))
local ok1, why1 = own(U1, 0x4000)
if not ok1 then
    print(string.format("[A] no usable U1 (%s), aborting", why1))
    return
end
print(string.format("[A] U1=0x%X (%s)", U1, why1))

local _, n0, rows0 = scan674()
if n0 == nil then
    print("[A] 674 does not enumerate; the two-table join is unavailable, aborting")
    return
end
print(string.format("[A] 674 enumerates %d records", n0))

local U2 = nil
for _, cand in ipairs({0x500000000, 0x600000000, 0x400000000, 0x700000000, 0x300000000}) do
    if find_in(rows0, cand) == nil and math.abs(cand - U1) > 0x1000000 then U2 = cand break end
end
if U2 == nil then
    print("[A] no free slot among the candidates; the op-3 range is skipped")
else
    set_entry(U2, 0, 0x4000, 3, 3)
    local r3 = v548("op 3 map at 0x" .. string.format("%X", U2), 0)
    -- op 3 answers the address it actually mapped (1534c: rv=0x500004000, and
    -- 0x311400000 when the hint was not honoured), so the return value, not the
    -- hint, is where the range lives
    local a3 = N(r3)
    if a3 > 0x1000 and a3 <= 549755813888 then U2 = a3 end
    local ok2, why2 = own(U2, 0x4000)
    print(string.format("[A] op 3 rv=%s -> own=%s %s", tostring(r3), tostring(ok2), why2))
    if not ok2 then
        print("[A] no live range at U2, continuing without it")
        U2 = nil
    end
end
print("")

print("--- [B] baseline ---")
state("U1 before", U1)
if U2 then state("U2 before", U2) end
print("")

-- ---------------------------------------------------------------- [C] op 1 on a 477 range
print("--- [C] op 1 prot 3 len 0x4000 on the 477 range U1 ---")
set_entry(U1, 0, 0x4000, 3, 1)
local rC, pC1 = v548("op 1 U1", 0)
state("U1 after op 1", U1)
verdict("U1", U1, 0x4000, rC, pC1)
print("")

-- ---------------------------------------------------------------- [E] 1534c reproduction
print("--- [E] 1534c exact call: op 1 prot 3 len 0x4000 on the op-3 range U2 ---")
if U2 and own(U2, 0x4000) then
    set_entry(U2, 0, 0x4000, 3, 1)
    local rE, pE = v548("op 1 U2", 0)
    state("U2 after op 1", U2)
    verdict("U2", U2, 0x4000, rE, pE)
else
    print("   skipped: no live op-3 range")
end
print("")

-- ---------------------------------------------------------------- [F] a fresh 477 range
print("--- [F] a fresh 477 range, op 1 straight after, no op-3 involvement ---")
local pv3 = sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local U3 = N(pv3)
local ok3, why3 = own(U3, 0x4000)
if ok3 then
    print(string.format("[F] U3=0x%X (%s)", U3, why3))
    set_entry(U3, 0, 0x4000, 3, 1)
    local rF, pF = v548("op 1 U3", 0)
    state("U3 after op 1", U3)
    verdict("U3", U3, 0x4000, rF, pF)
else
    print(string.format("[F] 477 did not give a usable range (%s)", why3))
end
print("")

-- ---------------------------------------------------------------- [D] arg2 (secondary)
print("--- [D] does arg2 change op 1? (only if U1 is still exactly ours) ---")
do
    local ok, why = own(U1, 0x4000)
    if not ok then
        print(string.format("   skipped: %s", why))
    else
        set_entry(U1, 0, 0x4000, 3, 1)
        local rD, pD = v548("op 1 U1 arg2=0x10000000", 0x10000000)
        state("U1 after", U1)
        verdict("U1 arg2", U1, 0x4000, rD, pD)
    end
end
print("")

-- ---------------------------------------------------------------- [E2] op 4 (secondary)
print("--- [E2] op 4 prot 3 on whatever still exists ---")
local function op4test(tag, addr)
    if addr == nil then print(string.format("   %-22s skipped: no range", tag)) return end
    local ok, why = own(addr, 0x4000)
    if not ok then print(string.format("   %-22s skipped: %s", tag, why)) return end
    set_entry(addr, 0, 0x4000, 3, 4)
    local r4, p4 = v548(tag .. " op 4", 0)
    state(tag .. " after op 4", addr)
    verdict(tag, addr, 0x4000, r4, p4)
end
op4test("U2", U2)
op4test("U1", U1)
print("")

-- ---------------------------------------------------------------- [G] the offset field
print("--- [G] op 1 with a nonzero offset field, on its own fresh range ---")
local pv4 = sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local U4 = N(pv4)
local ok4, why4 = own(U4, 0x4000)
if ok4 then
    print(string.format("[G] U4=0x%X (%s)", U4, why4))
    set_entry(U4, 0x1000, 0x4000, 3, 1)
    local rG, pG = v548("op 1 U4 offset=0x1000", 0)
    state("U4 after", U4)
    verdict("U4", U4, 0x4000, rG, pG)
    print("    note: no prior probe exercised an aligned entry with a nonzero")
    print("    offset. 1479d EINVAL rows were unaligned entries, so they do not")
    print("    cover this shape.")
else
    print(string.format("[G] 477 did not give a usable range (%s)", why4))
end
print("")

-- ---------------------------------------------------------------- [H] does the deferred apply run?
print("--- [H] op 1 with prot 0: if the deferred applier runs, 547 must show 0 ---")
local function applytest(tag, addr, pr)
    local ok, why = own(addr, 0x4000)
    if not ok then print(string.format("   %-24s skipped: %s", tag, why)) return end
    local s0, e0, p0 = rec547(addr)
    if p0 ~= 3 then
        print(string.format("   %-24s skipped: baseline prot is 0x%X, not 3", tag, p0))
        return
    end
    set_entry(addr, 0, 0x4000, pr, 1)
    local rq, pq = v548(string.format("%s op 1 prot=%d", tag, pr), 0)
    if rq == -999 then
        print(string.format("   %s EXCEPTION in the wrapper, not a kernel answer", tag))
        return
    end
    if rq ~= 0 then
        print(string.format("   %s REFUSED rv=%s - not a gate, a refusal", tag, tostring(rq)))
        return
    end
    local s1, e1, p1 = rec547(addr)
    if s1 == nil then
        print(string.format("   %s: 547 has no record after op 1", tag))
        return
    end
    print(string.format("   %s after prot=%d: 547 0x%X-0x%X prot=0x%X (processed=%d)", tag, pr, s1, e1, p1, pq))
    if p1 == pr then
        print(string.format("   >>> DEFERRED APPLY RAN: prot %d became visible", pr))
    elseif pq ~= 1 then
        print(string.format("   >>> prot %d never became visible AND processed=%d, so the entry never reached an op body", pr, pq))
    else
        print(string.format("   >>> prot %d never became visible (still 0x%X). Consistent with the applier", pr, p1))
        print("       dropping it, with op 1 not being the queueing case at all, or with")
        print("       the deferred path applying map-shaped entries only.")
    end
end
if U3 ~= nil then
    state("U3 before [H]", U3)
    applytest("U3 prot 0", U3, 0)
    applytest("U3 prot 1", U3, 1)
else
    print("   skipped: no U3")
end
print("")

-- ---------------------------------------------------------------- [I] does the deferred path accept EXEC?
print("--- [I] op 1 with prot 5 and 7, which op 2 refuses with EACCES(13) ---")
print("    A 16 KiB anonymous page carrying an executable protection is inert: no")
print("    register in this process points at it and the loader has no JIT. The")
print("    answer is read from 547, nothing is executed.")
if U3 ~= nil then
    for _, pr in ipairs({5, 7}) do
        local ok, why = own(U3, 0x4000)
        if not ok then
            print(string.format("   prot %d skipped: %s", pr, why))
        else
            set_entry(U3, 0, 0x4000, pr, 1)
            local rI, pI = v548(string.format("op 1 U3 prot=%d", pr), 0)
            if rI ~= 0 then
                print(string.format("   prot %d REFUSED rv=%s (processed=%d)", pr, tostring(rI), pI))
            else
                local sI, eI, pv = rec547(U3)
                if sI == nil then
                    print(string.format("   prot %d: 547 has no record (processed=%d)", pr, pI))
                else
                    print(string.format("   prot %d -> 547 0x%X-0x%X prot=0x%X (processed=%d)", pr, sI, eI, pv, pI))
                    if pv == pr then
                        print(string.format("   *** DEFERRED PATH TOOK prot=%d WHERE op 2 REFUSES IT ***", pr))
                    end
                end
            end
        end
    end
else
    print("   skipped: no U3")
end
print("")

-- ---------------------------------------------------------------- [J] teardown
print("--- [J] teardown, only ranges 547 still reports as exactly ours ---")
for _, pair in ipairs({{"U1", U1}, {"U2", U2 or 0}, {"U3", U3}, {"U4", U4}}) do
    local a = pair[2]
    if a ~= nil and a >= 0x1000 then
        local ok, why = own(a, 0x4000)
        if ok then
            local okm, rv = pcall(function()
                return sc73(uint64(a), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0))
            end)
            print(string.format("   73 %s 0x%X rv=%s", pair[1], a, tostring(okm and N(rv) or "EXC")))
        else
            print(string.format("   %s 0x%X not ours (%s), not unmapping it", pair[1], a, why))
        end
    else
        print(string.format("   %s never created", pair[1]))
    end
end
print("")
print(string.format("final canary: pid=%d (started %d)", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), PID))
print("=== PROBE 1537a COMPLETE ===")
