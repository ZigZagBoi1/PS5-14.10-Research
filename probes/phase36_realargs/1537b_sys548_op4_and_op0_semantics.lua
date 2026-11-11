-- CRASH_CLASS: HIGH -- [D] hands the physhm descriptor to op 0, and every read of a physhm
-- range has killed the loader (321a, 318a: the captures end in the fault dump right after the
-- mmap line). [D] performs NO read: it judges the call from 547 and 674 only. [C] reads one
-- dword after op 0 took the dmem0 descriptor, which is the readable device (0xC0012800 at
-- offset 0, 1480c), and prints before the read so a death still names the address.
-- PROBE 1537b: the two 548 cases that have never been exercised - op 4, and op 0's semantics.
--
-- Context. 1537a settled op 1: it is munmap. Four ranges, four different creation paths,
-- every call rv=0 processed=1, and afterwards 547 had no record and a fresh 674 sweep had no
-- record - including a call whose entry carried offset=0x1000, so op 1 ignores the offset
-- field. That leaves two of the five cases unmeasured:
--
--   op 4 - never called successfully. 1537a's [E2] intended to test it and skipped, because
--          [C] and [E] had already removed both candidate ranges. So the corpus has no op-4
--          datum at all.
--
--          Its body is the queueing case 0x8b47c088 by elimination: op 0, 1, 2 and 3 are
--          pinned to 0x8b47bff3, 0x8b47c185, 0x8b47c0b0 and 0x8b47c11e by measurement, and
--          0x8b47c088 is the only body left. (The ascending-address argument in
--          docs/VM_LAYER_14_10.md section 12 is unsound - op 1 sits at the highest address -
--          but the conclusion holds without it.) The deferred applier 0x8ac8dc10 rejects any
--          entry whose protection byte has bit 1, 2, 3, 5 or 7 set:
--             0x8ac8dcd9 cmp byte [rdx+0x21],0xa
--             0x8ac8dce5 test r12b,0xae
--             0x8ac8dce9 sete cl          ; cl = (prot & 0xae) == 0
--             0x8ac8dcf1 jne reject
--          so it may accept prot 1 (READ) and must refuse prot 3 (READ|WRITE). [B] therefore
--          asks for prot 3 first and prot 1 second: a refusal-then-acceptance pair is the
--          signature of the queue, and prot 1 taking effect would be the first proof that a
--          deferred apply runs on 14.10.
--
--   op 0 - called six times in 1534b and six in 1534c and never returned 0. It answers
--          EBUSY(16) at a FREE address and 0 at an EXISTING one (1480b), which is the
--          opposite of a map. The descriptor is definitely consumed: /dev/dmem0 at position
--          0x120000000 returns that device's own EACCES(13), an error no bogus descriptor
--          produced (1534c, with fd 0xFFFFFFFF as the control). 1534c tested op 0 only on
--          op-3 ranges, and 1480b only on a 477 range. Every target so far has been an
--          ANONYMOUS range, which is the one thing all twelve failures share.
--
-- So [C] asks whether op 0's EBUSY is really about the range being anonymous: it takes a
-- 477 range and hands op 0 the dmem0 descriptor at a position whose backing is known.
-- [D] does the same with the physhm descriptor from 629(1,2,0,0) - the descriptor 477 maps but
-- whose first read kills - and never reads the result.
--
-- [A] answers one thing about op 1 that 1537a could not: those four ranges were each exactly
-- one 16 KiB entry, so 'removed' and 'the whole containing entry was removed' are the same
-- observation. A 256 KiB 477 mapping is one entry, and op 1 on its middle page separates a
-- precise unmap (the entry splits, both halves survive) from a whole-entry delete (all 256 KiB
-- vanishes). The BSD munmap measured in 1450a/1446d/1469a deletes the whole containing entry,
-- so a split here would mean op 1 is NOT the munmap helper 0x8b478bb0 that the static reading
-- points at.
--
-- Every call is judged from 547 and a fresh 674 sweep. arg1 of 548 is the descriptor
-- (request+0x28 = fd, from uap[0]; 1534b/1534c both call sc548(fd, ...)), so the descriptor
-- phases pass theirs and the rest pass 0. No load follows a 548 call except the single read in
-- [C], which prints its target first, and [D] - the same experiment without the read - runs
-- before it so a death there cannot cost the read-free observation.
--
-- -- prior art:
--   results/phase36_realargs/1537a_sys548_op1_removal_check_20261110_150521.txt (op 1 = munmap, 4/4 ranges)
--   results/phase36_realargs/1534c_sys548_op0_on_live_range_20261110_142452.txt (op 0 EBUSY on op-3 ranges; dmem0 EACCES proves the fd is consumed)
--   results/phase36_realargs/1534b_sys548_op0_descriptor_map_20261110_141234.txt (op 0 EBUSY at free addresses)
--   results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt (op 0 returned 0 on an existing range; its 'op=1' line is void, see docs/VM_LAYER_14_10.md 12.4)
--   results/phase36_realargs/1450a_*.txt, 1446d, 1469a (BSD munmap removes the whole containing entry)
--   results/phase17_new_vectors/321a_physhm_ptr_20261022_122101.txt (physhm range mapped, first read faults)
--   docs/VM_LAYER_14_10.md sections 8, 10, 11, 12, 14 (the 548 contract as measured)
--   docs/DMEM_WINDOW_14_10.md (dmem0 offset 0 reads 0xC0012800 and a store sticks)

print("=== PROBE 1537b: 548 OP 4, AND WHAT OP 0 ACTUALLY DOES ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) return string.format("%08X", v % 4294967296) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- a fault inside this process must be contained, not fatal
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local sc547 = mk(547)
local sc674 = mk(674)
local sc477 = mk(477)
local sc73  = mk(73)
local sc5   = mk(5)
local sc629 = mk(629)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x20)
local cnt = memory.alloc(0x10)

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return N(b)
end

local function open_node(path, flags)
    local p = str_addr(path)
    if p == 0 then return -1 end
    local ok, v = pcall(function() return N(sc5(uint64(p), uint64(flags or 2), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if ok then return v end
    return -1
end

-- entry: {start qword@0x00, offset qword@0x08, length qword@0x10, prot dword@0x18, op byte@0x1C}
local function set_entry(start, offset, len, prot, op)
    for i = 0, 0x1F do pcall(function() memory.write_byte(ent + i, 0) end) end
    local function wq(o, v)
        pcall(function() memory.write_dword(ent + o, uint64(v % 4294967296)) end)
        pcall(function() memory.write_dword(ent + o + 4, uint64(math.floor(v / 4294967296) % 4294967296)) end)
    end
    wq(0x00, start)
    wq(0x08, offset or 0)
    wq(0x10, len)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

-- the tag is printed BEFORE the call: a fatal op leaves the capture naming the shape
local function v548(tag, fd, arg2)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("   -> %-52s", tag))
    local ok, rv = pcall(function()
        return sc548(uint64(fd or 0), uint64(arg2 or 0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    local proc = N(memory.read_dword(cnt))
    print(string.format("      rv=%-16s processed=%d %s", tostring(r), proc, (r < 0 and r ~= -999) and es() or ""))
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

-- exact-span interlock: 547 answered at 'addr' does not mean the range is still ours
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
    local rv = -999
    local ok = pcall(function() rv = N(sc674(uint64(mbuf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000), uint64(0))) end)
    if not ok or rv ~= 0 then return nil, nil, {} end
    local n = N(u64at(cnt, 0))
    if n <= 0 then return nil, nil, {} end
    local rows = {}
    for i = 0, n - 1 do
        local b = mbuf + i * 72
        rows[#rows + 1] = { s = u64at(b, 0x00), e = u64at(b, 0x08), p = N(memory.read_dword(b + 0x18)) }
    end
    return rv, n, rows
end

local function find_in(rows, addr)
    for i = 1, #rows do
        if rows[i].s <= addr and addr < rows[i].e then return rows[i] end
    end
    return nil
end

local function state(tag, addr)
    local s, e, p = rec547(addr)
    local _, n, rows = scan674()
    local r = (n ~= nil) and find_in(rows, addr) or nil
    local function half(str)
        if s == nil then return str .. "547 has no record" end
        return string.format("%s547 0x%X-0x%X prot=0x%X", str, s, e, p)
    end
    local function other()
        if r == nil then
            if n == nil then return "674 FAILED (do not read this as absent)" end
            return "absent from 674"
        end
        return string.format("674 has 0x%X-0x%X prot=0x%X", r.s, r.e, r.p)
    end
    print(string.format("   %-26s n=%-4s %s | %s", tag, tostring(n), half(""), other()))
end

-- one verdict routine, so no phase invents its own taxonomy
local function verdict(tag, addr, len, rv, proc)
    if rv == nil then print(string.format("   VERDICT %s: not run", tag)) return end
    if rv == -999 then
        print(string.format("   VERDICT %s: EXCEPTION (pcall failed) - not a kernel answer", tag))
        return
    end
    if rv ~= 0 then
        print(string.format("   VERDICT %s: REFUSED rv=%s %s", tag, tostring(rv), es()))
        return
    end
    if proc ~= nil and proc ~= 1 then
        print(string.format("   VERDICT %s: NOT DISPATCHED (rv=0 but processed=%d)", tag, proc))
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
        print(string.format("   VERDICT %s: INCONSISTENT - 674 still lists it, 547 cannot describe it", tag))
    elseif s == addr and e == addr + len then
        print(string.format("   VERDICT %s: PRESENT, exact span, prot=0x%X", tag, p))
    else
        print(string.format("   VERDICT %s: RESHAPED to 0x%X-0x%X prot=0x%X", tag, s, e, p))
    end
end

local function map_anon(len)
    local ok, rv = pcall(function()
        return sc477(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local v = N(rv)
    if v < 0x1000 or v > 549755813888 then return nil end
    return v
end

local function release(addr, len)
    if addr == nil or addr < 0x1000 then return end
    local ok, why = own(addr, len)
    if not ok then
        print(string.format("   not ours 0x%X (%s), not unmapping it", addr, why))
        return
    end
    local okm, rv = pcall(function()
        return sc73(uint64(addr), uint64(len), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("   73 0x%X len=0x%X rv=%s", addr, len, tostring(okm and N(rv) or "EXC")))
end

-- ---------------------------------------------------------------- [A] op 1 on a 256 KiB entry
print("--- [A] does op 1 remove the whole containing entry, or only the page asked for? ---")
print("    477 of 0x40000 is one entry. Removing its middle page separates the two cases.")
local BIG = map_anon(0x40000)
if BIG == nil then
    print("[A] 477 refused a 256 KiB anonymous range; the split test is unavailable")
else
    local sB, eB, pB = rec547(BIG)
    print(string.format("[A] BIG=0x%X 547 0x%X-0x%X prot=0x%X (span 0x%X)",
        BIG, sB or 0, eB or 0, pB or 0, (eB or 0) - (sB or 0)))
    local MID = BIG + 0x20000
    if sB ~= BIG or eB ~= BIG + 0x40000 then
        print("[A] the 256 KiB mapping is not one exact entry; the split test would be ambiguous")
    else
        set_entry(MID, 0, 0x4000, 3, 1)
        local rA, pA = v548("op 1 on the middle page of a 256 KiB entry", 0, 0)
        -- snapshot first: a removed 16 KiB hole can be refilled by the loader's own
        -- arena within this same probe (docs/VM_LAYER_14_10.md 14.3), which would turn
        -- a decided reading into an ambiguous one if these ran after four prints
        local midNow = rec547(MID)
        local bigNow = rec547(BIG)
        print(string.format("   before: BIG=0x%X MID=0x%X", BIG, MID))
        state("BIG (first half)", BIG)
        state("MID (the page asked)", MID)
        state("BIG+0x24000 (second half)", BIG + 0x24000)
        state("BIG+0x3C000 (last page)", BIG + 0x3C000)
        if rA == 0 then
            if midNow == nil and bigNow ~= nil then
                print("   >>> SPLIT: the page went, its neighbours survived, so op 1 is precise")
            elseif bigNow == nil and midNow == nil then
                print("   >>> WHOLE ENTRY: all 256 KiB went, so op 1 deletes the containing entry")
            else
                print("   >>> NEITHER: the page is still mapped, or its address was reused.")
                print("       Read the four state lines above; this branch decides nothing.")
            end
        end
        print(string.format("   rv=%s processed=%d", tostring(rA), pA))
    end
end
print("")

-- ---------------------------------------------------------------- [B] op 4 on a fresh range
print("--- [B] op 4 on a fresh 477 range - the one case never called successfully ---")
local B4 = map_anon(0x4000)
if B4 == nil then
    print("[B] 477 refused a 16 KiB range")
else
    print(string.format("[B] B4=0x%X", B4))
    set_entry(B4, 0, 0x4000, 3, 4)
    local rB, pB2 = v548("op 4 prot 3 on an exact 16 KiB range", 0, 0)
    state("B4 after op 4", B4)
    verdict("B4 op4", B4, 0x4000, rB, pB2)
    -- op 4 again on the same shape with a protection it might act on
    local B4b = map_anon(0x4000)
    if B4b ~= nil then
        set_entry(B4b, 0, 0x4000, 1, 4)
        local rB2, pB3 = v548("op 4 prot 1 on a fresh range", 0, 0)
        state("B4b after op 4", B4b)
        verdict("B4b op4 prot1", B4b, 0x4000, rB2, pB3)
        release(B4b, 0x4000)
    end
    if B4 ~= nil and own(B4, 0x4000) then release(B4, 0x4000) end
end
print("")

-- ---------------------------------------------------------------- [D] (was [C]) op 0, read-free
-- Runs BEFORE the reading variant: if op 0 replaces a range's backing with a device page, the
-- read in the phase below dies, and this phase - the same experiment judged from 547/674 only -
-- must already be in the capture.
print("--- [D] op 0 with the physhm descriptor - judged from 547 and 674, never read ---")
local fd_ph = -1
do
    local ok, rv = pcall(function() return sc629(uint64(1), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then fd_ph = N(rv) end
end
print(string.format("[D] 629(1,2,0,0) = %d", fd_ph))
if fd_ph < 0 then
    print("[D] no physhm descriptor; skipped")
else
    local D = map_anon(0x4000)
    if D == nil then
        print("[D] 477 refused a 16 KiB range")
    else
        print(string.format("[D] D=0x%X", D))
        set_entry(D, 0, 0x4000, 3, 0)
        local rD, pD = v548("op 0 fd=physhm pos=0 on an anon range", fd_ph, 0)
        state("D after op 0", D)
        verdict("D op0 physhm", D, 0x4000, rD, pD)
        print("   no read: every read of a physhm range has killed the loader (321a, 318a)")
        if own(D, 0x4000) then release(D, 0x4000) end
    end
end
print("")

-- ---------------------------------------------------------------- [C] op 0 with a readable device
print("--- [C] op 0 with the dmem0 descriptor on an existing anonymous range ---")
print("    All twelve earlier op-0 calls targeted anonymous ranges and all gave EBUSY.")
print("    dmem0 offset 0 is the ONE device page that reads (0xC0012800) and stores stick.")
local fd_d0 = open_node("/dev/dmem0", 2)
print(string.format("[C] /dev/dmem0 fd=%d", fd_d0))
if fd_d0 <= 0 then
    print("[C] no descriptor; op 0 cannot be tested here")
else
    local C = map_anon(0x4000)
    if C == nil then
        print("[C] 477 refused a 16 KiB range")
    else
        print(string.format("[C] C=0x%X", C))
        set_entry(C, 0, 0x4000, 3, 0)
        local rC, pC = v548("op 0 fd=dmem0 pos=0 on an anon range", fd_d0, 0)
        state("C after op 0", C)
        verdict("C op0 dmem0", C, 0x4000, rC, pC)
        -- op 0 may answer a landing address rather than 0 (the op-3 convention), so both are
        -- treated as success; the read is the only step that can die, and it names its target
        local READAT = nil
        local sC, eC, pCr = rec547(C)
        if rC == 0 and sC == C and pCr ~= nil and (pCr % 4) >= 1 then
            READAT = C
        elseif rC > 0x1000 and rC <= 549755813888 then
            local sR, _, pR = rec547(rC)
            if sR ~= nil and pR ~= nil and (pR % 4) >= 1 then READAT = rC end
        end
        if READAT ~= nil then
            print(string.format("   reading dword at 0x%X - a death here is the datum", READAT))
            local ok, v = pcall(function() return N(memory.read_dword(READAT)) end)
            print(string.format("   -> ok=%s value=0x%s  (0xC0012800 means dmem0 answered; anything else means op 0 did not back the range with dmem0)",
                tostring(ok), hex(ok and v or 0)))
        else
            print("   not reading: op 0 gave no readable range at C or at its return value")
        end
        if own(C, 0x4000) then release(C, 0x4000) end
    end
end
print("")

-- ---------------------------------------------------------------- [E] teardown
print("--- [E] teardown, only ranges 547 still reports as exactly ours ---")
if BIG ~= nil then state("BIG final", BIG) end
print("")
print(string.format("final canary: pid=%d (started %d)", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), PID))
print("=== PROBE 1537b COMPLETE ===")
