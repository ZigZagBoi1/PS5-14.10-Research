-- CRASH_CLASS: MODERATE
-- PROBE 1533a: sys 548 op 2 (protect) on ANON pages, with a device control
--
-- Context: the 13.60 sys_548 body (results/kernel_handlers/asm/sys_548.asm PART B,
-- RVA 0xabbe60) validates the range BEFORE dispatching on the opcode:
--
--   0x8b47c0b7  test esi, 0x3fff      ; start % 0x4000
--   0x8b47c0bd  jne  0x8b47c2b8       ; EINVAL
--   0x8b47c0ca  test edx, 0x3fff      ; length % 0x4000
--   0x8b47c0d0  jne  0x8b47c2b8       ; EINVAL
--   0x8b47c0d6  movzx edi, [rbp-0x80] ; prot byte
--   0x8b47c0dc  and  ecx, 8; jne EINVAL  ; prot bit 0x8 refused
--   0x8b47c0e5  add  rdx, rsi; jb EINVAL ; end = start + len
--   0x8b47c0f5  shr  ecx, 1; and ecx, 0xffffffc1; or ecx, edi  ; WRITE implies READ
--   0x8b47c10c  call 0xffffffff8ac8bdb0  ; vm_map_protect(map, start, end, prot, set_max=0)
--
-- 1481g already swept op 2 across 14 prot values on the SceGnmTrapData device
-- window with len=0x4000 and got a complete answer (0/1/3/0x10/0x20/0x33 taken,
-- 0x2 -> 3, everything with bit 0x8 refused). Its two ANON rungs never ran:
-- mmap_anon(3) and mmap_anon(7) both FAILED because that helper passed the test
-- prot as the 477 protection with mtype 0x1002. So the anon half of op 2 is
-- unmeasured, and 1479c/1479d's uniform EINVAL came from len=0x1000 (1481g's [D]
-- rung confirms that exact length still answers 22 "Invalid argument").
--
-- This probe supplies the missing half: the proven anon mmap shape
-- 477(0, 0x4000, 3, 0x1000, 0xFFFFFFFF, 0), then op 2 against those pages. Every
-- rung asks for a value the page does NOT already have, so a TAKEN rung is
-- distinguishable from a no-op. The device control runs LAST and restores the
-- window to the value it measured, so a death inside it can only cost the
-- control, never the anon measurement.
--
-- Entry layout (SceKernelBatchMapEntry, 0x20 bytes, op at +0x1C), from 1479b:
--   +0x00 start (qword, 0x4000-aligned)   +0x08 offset (qword)
--   +0x10 length (qword, 0x4000-aligned)  +0x18 protection (dword)
--   +0x1C op (byte) 0..4
-- 547 (query_memory_protection) copies 0x18 bytes: {start_lo,start_hi,end_lo,
-- end_hi,prot@0x10,flags@0x14}. The record's own start/end are echoed so a 547
-- answer about a different region cannot be mistaken for one about the target.
--
-- Every phase prints before it calls, and each op-2 call on a mapped range is
-- its own phase, so a death costs at most one rung.
--
-- -- prior art:
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202017.txt
--       device window: prot 0/1/3/0x10/0x20/0x33 TAKEN, 0x2 -> 3, bit 0x8 refused;
--       anon rungs never ran (mmap FAILED); len 0x1000 -> rv=-1 22 Invalid argument
--   results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt
--       count=1 op=2 all-zero entry -> rv=0 processed=1; ops 0/1/3/4/5 -> EINVAL(22)
--   results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt
--       single-byte sweep; +0x13=0xFF killed; entry layout derived
--   results/phase36_realargs/1479c_sys548_protect_foreign_20261109_195337.txt
--   results/phase36_realargs/1479d_sys548_map_unmap_20261109_195406.txt
--       both VOID for real ranges: len=0x1000 fails the alignment gate
--   docs/VM_LAYER_14_10.md section 6; docs/DEVICE_WINDOW_14_10.md section 12
--   docs/sysent-names-13.60.csv: 548 = batch VM operation, 5 opcodes

print("=== PROBE 1533a: SYS 548 OP 2 ON ANON PAGES ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sc548 = mk(548)
local sc477 = mk(477)
local sc547 = mk(547)
local sc674 = mk(674)
local sc73  = mk(73)

local ent = memory.alloc(0x80)
local rec = memory.alloc(0x40)
local cnt = memory.alloc(0x10)

local function zero(p, n)
    for i = 0, n - 1 do pcall(function() memory.write_byte(p + i, 0) end) end
end
local function set_entry(idx, start, offset, len, prot, op)
    local e = ent + idx * 0x20
    zero(e, 0x20)
    pcall(function() memory.write_qword(e + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(e + 0x08, uint64(string.format("0x%X", offset))) end)
    pcall(function() memory.write_qword(e + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(e + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(e + 0x1C, op) end)
end
local function v548(count, tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %s  count=%d", tag, count))
    local ok, v = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(count), uint64(cnt), uint64(0)))
    end)
    local pc = "?"
    local ok2, v2 = pcall(function() return N(memory.read_dword(cnt)) end)
    if ok2 then pc = string.format("%d", v2 % 4294967296) end
    if ok then
        print(string.format("     rv=%-5d %-18s processed=%s", v, (v == -1) and es() or "", pc))
    else
        print(string.format("     EXC processed=%s", pc))
    end
    return ok and v or -999
end
-- returns prot only when 547 succeeded; echoes the record's own range
local function prot_of(addr, tag)
    zero(rec, 0x20)
    local ok, v = pcall(function()
        return N(sc547(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not (ok and v == 0) then
        print(string.format("     547(%s) rv=%s", tag, ok and tostring(v) or "EXC"))
        return nil
    end
    local function dw(off)
        local okr, val = pcall(function() return N(memory.read_dword(rec + off)) % 4294967296 end)
        if okr then return val end
        return 0xDEAD
    end
    local pr, fl = dw(0x10), dw(0x14)
    local slo, shi = dw(0x00), dw(0x04)
    local elo, ehi = dw(0x08), dw(0x0C)
    local s = slo + shi * 4294967296
    local e = elo + ehi * 4294967296
    local mark = ""
    if s > addr or addr >= e then mark = "  <<< NOT THIS RANGE" end
    print(string.format("     547(%s) rv=0 prot=0x%X flags=0x%X range=0x%X..0x%X%s",
        tag, pr, fl, s, e, mark))
    return pr
end
local function map_anon()
    local ok, v = pcall(function()
        return N(sc477(uint64(0), uint64(0x4000), uint64(3),
                       uint64(0x1000), uint64(0xFFFFFFFF), uint64(0)))
    end)
    if not ok then return nil end
    if v < 0x1000 or v > 549755813888 then return nil end
    if (v % 0x4000) ~= 0 then return nil end
    return v
end

-- ------------------------------------------------------- [A] anon pages
print("[A] map anon pages with the proven 477 shape")
local P = map_anon()
local Q = map_anon()
print(string.format("    P=%s Q=%s", P and string.format("0x%X", P) or "nil", Q and string.format("0x%X", Q) or "nil"))
if not (P and Q) then
    print("    ABORT: no anon page")
else
    print(string.format("    P before: %s", tostring(prot_of(P, "P"))))
    print(string.format("    Q before: %s", tostring(prot_of(Q, "Q"))))
    print("")

    -- --------------------------- [C] first new rung: drop P from 3 to 1
    print("[C] op2 {P, 0, 0x4000, prot=1} - anon, 3 -> 1, the rung 1481g never ran")
    set_entry(0, P, 0, 0x4000, 1, 2)
    v548(1, "protect P prot=1")
    prot_of(P, "P")
    print("")

    -- ---------------------------------------- [D] Q: 3 -> 1
    print("[D] op2 {Q, 0, 0x4000, prot=1} - anon, 3 -> 1")
    set_entry(0, Q, 0, 0x4000, 1, 2)
    v548(1, "protect Q prot=1")
    prot_of(Q, "Q")
    print("")

    -- ---------------------------------------- [E] Q: 1 -> 2, WRITE implies READ
    print("[E] op2 {Q, 0, 0x4000, prot=2} - expect 547=0x3, not 0x2")
    set_entry(0, Q, 0, 0x4000, 2, 2)
    v548(1, "protect Q prot=2")
    prot_of(Q, "Q")
    print("")

    -- ---------------------------------------- [F] Q: X on anon
    print("[F] op2 {Q, 0, 0x4000, prot=7} - X on anon: max_prot or accepted?")
    set_entry(0, Q, 0, 0x4000, 7, 2)
    v548(1, "protect Q prot=7")
    prot_of(Q, "Q")
    print("")

    -- ------------------------------------------------------ [G/H/I] the gates
    print("[G] op2 {P+0x2000, 0, 0x4000, prot=3} - start misaligned, expect EINVAL")
    set_entry(0, P + 0x2000, 0, 0x4000, 3, 2)
    v548(1, "start misaligned")
    print("")

    print("[H] op2 {P, 0, 0x2000, prot=3} - length misaligned, expect EINVAL")
    set_entry(0, P, 0, 0x2000, 3, 2)
    v548(1, "length misaligned")
    print("")

    print("[I] op2 {P, 0, 0x4000, prot=0x18} - prot bit 0x8, expect EINVAL")
    set_entry(0, P, 0, 0x4000, 0x18, 2)
    v548(1, "prot bit 0x8")
    print("")

    -- ------------------------------------------------------- [J] two entries
    print("[J] count=2, op2 prot=3 on P then H=Q")
    set_entry(0, P, 0, 0x4000, 3, 2)
    set_entry(1, Q, 0, 0x4000, 3, 2)
    v548(2, "two protects")
    prot_of(P, "P")
    prot_of(Q, "Q")
    print("")

    -- ------------------------------------------------------- [K] drop P, last
    print("[K] op2 {P, 0, 0x4000, prot=0} - drop access to P")
    set_entry(0, P, 0, 0x4000, 0, 2)
    v548(1, "protect P prot=0")
    prot_of(P, "P")
end

-- ---------------------------------- [B] device control, LAST, restored to measured
print("")
print("[B] device control on SceGnmTrapData (already measured by 1481g) - runs last")
local DEV, DEVBEFORE = nil, nil
local dbuf = memory.alloc(0x9000)
zero(dbuf, 0x9000)
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(dbuf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("    674 rv=%d records=%d", okc and c or -999, nrec))
if nrec > 400 then nrec = 400 end
for i = 0, nrec - 1 do
    local b = dbuf + i * 72
    local name = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        name = name .. string.char(ch)
    end
    if name == "SceGnmTrapData" then
        local lo, hi = 0, 0
        pcall(function() lo = N(memory.read_dword(b + 0x00)) end)
        pcall(function() hi = N(memory.read_dword(b + 0x04)) end)
        local s = lo + hi * 4294967296
        DEV = s - (s % 0x4000)
        break
    end
end
if DEV then
    DEVBEFORE = prot_of(DEV, "DEV")
    if DEVBEFORE == nil then
        print("    547 has no entry at the window; control skipped")
    else
        local want = 1
        if DEVBEFORE == 1 then want = 3 end
        set_entry(0, DEV, 0, 0x4000, want, 2)
        v548(1, string.format("CONTROL protect DEV 0x%X -> 0x%X", DEVBEFORE, want))
        prot_of(DEV, "DEV")
        set_entry(0, DEV, 0, 0x4000, DEVBEFORE, 2)
        v548(1, string.format("restore DEV to 0x%X", DEVBEFORE))
        prot_of(DEV, "DEV")
    end
else
    print("    DEV not found in the 674 map; control skipped")
end

if P and Q then
    print("")
    print("[L] release the anon pages")
    pcall(function() sc73(uint64(string.format("0x%X", P)), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    pcall(function() sc73(uint64(string.format("0x%X", Q)), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("    done")
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1533a COMPLETE ===")
