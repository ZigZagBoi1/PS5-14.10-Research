-- CRASH_CLASS: HIGH -- [C] attempts a store into eboot text after asking 548 to make it writable.
-- If the store is refused below the vm_map the process dies; every call prints before it is made
-- and the write is only attempted when 547 confirms the protection actually moved.
-- PROBE 1480a: sys 548 op 2 is a working protection change -- can it make eboot text writable?
--
-- 1479e found the gate that made every earlier 548 attempt fail: the entry must be 16 KiB
-- aligned. The 13.60 test was `test edx,0x3fff`, i.e. 0x4000, not 0x1000. With len=0x4000 on a
-- page this process owns, op 2 returns 0 with processed=1 and 547 reports the protection
-- changed from 3 to 1. That is a real vm_map_protect, and unlike mprotect(2) it has no
-- PROT_EXEC refusal of its own -- the only limit left is the entry's max_protection.
--
-- This probe answers the three questions that decide whether that is useful:
--   [A] does it round-trip on a page we own (3 -> 1 -> 3), and does it accept 5 and 7?
--   [B] does it accept a protection on a page we do NOT own -- eboot text, prot 5, read-only.
--   [C] if 547 then reports eboot text writable, does a store actually land?
-- A store that is refused below the vm_map kills the process, which is why the write is last,
-- gated on 547, and writes back the byte pattern that is already there.
--
-- -- prior art:
--   results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195636.txt (16 KiB rule, 3 -> 1)
--   results/phase36_realargs/1479c_sys548_protect_foreign_20261109_195337.txt
--   results/phase36_realargs/1479d_sys548_map_unmap_20261109_195406.txt
--   results/kernel_handlers/asm/sys_548.asm (PART B, op 2 calls vm_map_protect at 0x8ac8bdb0)
--   docs/VM_LAYER_14_10.md section 6
--   docs/DEAD_ENDS.md (sys 588 DMEM page attribute modify: reports 0, PTE unchanged)

print("=== PROBE 1480a: SYS 548 OP 2, DOES IT REACH FOREIGN PAGES ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local sc477 = mk(477)
local sc547 = mk(547)
local sc674 = mk(674)

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

-- returns rv, processed
local function v548(tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %-46s", tag))
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    local e = ""
    if r == -1 then e = es() end
    local p = N(memory.read_dword(cnt))
    print(string.format("     rv=%-5s %-24s processed=%d", tostring(r), e, p))
    return r, p
end

-- returns prot, start, end (start/end truncated by the syscall to 32 bits)
local function prot_of(addr, tag)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then
        print(string.format("     [%s] 547 -> not mapped", tag))
        return nil, nil, nil
    end
    local sl = N(memory.read_dword(rec + 0x00))
    local s  = N(memory.read_dword(rec + 0x04))
    local el = N(memory.read_dword(rec + 0x08))
    local e  = N(memory.read_dword(rec + 0x0C))
    local pr = N(memory.read_dword(rec + 0x10))
    local fl = N(memory.read_dword(rec + 0x14))
    print(string.format("     [%s] 547 prot=%d flags=%d start=%08X%08X end=%08X%08X",
        tag, pr, fl, s, sl, e, el))
    return pr, sl + s * 4294967296, el + e * 4294967296
end

-- ---------------------------------------------------------------- [A] own page round trip
local function map_anon(len)
    local ok, rv = pcall(function()
        return sc477(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local v = rv
    if type(v) == "table" and v.tonumber then v = v:tonumber() end
    v = tonumber(v) or 0
    if v < 0x10000 then return nil end
    return v
end

print("")
print("--- [A] a page we own, 3 -> 1 -> 3, then 5 and 7 ---")
local A = map_anon(0x8000)
if not A then
    print("[A] mmap failed")
    print("=== PROBE 1480a INCOMPLETE ===")
    return
end
print(string.format("[A] A=0x%X", A))
local p = prot_of(A, "before")
if p ~= 3 then
    print("[A] the page does not report prot 3; instrument unusable")
    print("=== PROBE 1480a INCOMPLETE ===")
    return
end

-- Calibrate the store oracle on a page that is certainly writable, so the [C] marker test has a
-- known-positive reference in the same capture.
local cal0 = 0
pcall(function() memory.write_dword(A, uint64(0x5A5A1234)) end)
pcall(function() cal0 = N(memory.read_dword(A)) end)
print(string.format("[A] store calibration at prot 3: wrote 5A5A1234, read %08X -> %s",
    cal0, cal0 == 0x5A5A1234 and "store lands" or "store does NOT land"))

set_entry(A, 0, 0x4000, 1, 2); v548("A -> prot 1, len 0x4000"); prot_of(A, "after prot 1")
set_entry(A, 0, 0x4000, 3, 2); v548("A -> prot 3, len 0x4000"); prot_of(A, "after prot 3")
set_entry(A, 0, 0x4000, 5, 2); v548("A -> prot 5 (RX), len 0x4000"); prot_of(A, "after prot 5")
-- The same marker on a page the vm_map now calls read-execute. If it lands, the protection word
-- does not gate stores on a page we own, which is itself a W^X bypass on heap memory; if it does
-- not, the pmap enforces the vm_map and the [C] test on eboot text means what it says.
local cal5 = 0
pcall(function() memory.write_dword(A, uint64(0x5A5A5678)) end)
pcall(function() cal5 = N(memory.read_dword(A)) end)
print(string.format("[A] at prot 5: wrote 5A5A5678, read %08X -> %s",
    cal5, cal5 == 0x5A5A5678 and "W is NOT enforced at prot 5" or "write refused at prot 5"))
if cal5 == 0x5A5A5678 then
    print("[A] *** a page the vm_map calls RX accepted a store ***")
end
set_entry(A, 0, 0x4000, 3, 2); v548("A -> prot 3 again, len 0x4000"); prot_of(A, "after prot 3")
set_entry(A, 0, 0x8000, 7, 2); v548("A -> prot 7 (RWX), len 0x8000"); prot_of(A, "after prot 7")
set_entry(A, 0, 0x8000, 3, 2); v548("A restore prot 3, len 0x8000"); prot_of(A, "restored")
print("[A] done")

-- ---------------------------------------------------------------- [B] find an executable region
print("")
print("--- [B] locate executable mappings with 674 ---")
local buf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[B] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("[B] 674 did not enumerate the map; no page to pick")
    print("=== PROBE 1480a INCOMPLETE ===")
    return
end
if nrec > 400 then nrec = 400 end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

-- Pick the largest executable region: eboot text. Require room for a page 1 MiB in, so the page
-- we touch is not the first page of the segment where a hot entry point is most likely to live.
local best_s, best_e, best_name = 0, 0, ""
for i = 0, nrec - 1 do
    local b = buf + i * 72
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
    if pr == 5 and s >= 0x10000 then
        if (e - s) > (best_e - best_s) then
            best_s, best_e, best_name = s, e, name
        end
    end
end
if best_s == 0 then
    print("[B] no executable region found; no 548 call was made on eboot text")
    print("=== PROBE 1480a INCOMPLETE ===")
    return
end
print(string.format("[B] executable: 0x%X - 0x%X (%d KB) name=%s", best_s, best_e, (best_e - best_s) / 1024, best_name))

-- ---------------------------------------------------------------- [C] make it writable
local target = (best_s + 0x100000)
target = target - (target % 0x4000)
if target + 0x4000 > best_e then target = best_s end
print("")
print("--- [C] protect an executable page of that region ---")
print(string.format("[C] target=0x%X", target))

local pr0 = prot_of(target, "eboot before")
if pr0 ~= 5 then
    print(string.format("[C] this page is not prot 5 (got %s); not touching it", tostring(pr0)))
    print("=== PROBE 1480a INCOMPLETE ===")
    return
end

-- Read only after 547 confirms this really is the prot-5 page the walker picked.
local v0 = 0
pcall(function() v0 = N(memory.read_dword(target + 0x00)) end)
local v1 = 0
pcall(function() v1 = N(memory.read_dword(target + 0x04)) end)
print(string.format("[C] bytes before: %08X %08X", v0, v1))
if v0 == 0 and v1 == 0 then
    print("[C] the page reads as zero; it may not be text, so a write would prove nothing")
    print("=== PROBE 1480a INCOMPLETE ===")
    return
end

set_entry(target, 0, 0x4000, 7, 2)
local rv = v548("PROTECT eboot text -> prot 7 (RWX)")
if rv == -999 then
    print("[C] 548 raised inside pcall; no result")
    print("=== PROBE 1480a INCOMPLETE ===")
    return
elseif rv ~= 0 then
    print("[C] the call refused; nothing was written")
    print("=== PROBE 1480a COMPLETE ===")
    return
end

local pr1 = prot_of(target, "eboot after")
if pr1 ~= 7 then
    print(string.format("[C] 547 still reports %s -- the vm_map did not take it; not writing", tostring(pr1)))
    print("=== PROBE 1480a COMPLETE ===")
    return
end

-- 547 says the vm_map now believes the page is writable. Whether the pmap agrees is the whole
-- question. A store cannot answer it by surviving -- the loader's write path swallows a refused
-- store (381a: a store to a certainly-unmapped address reports ok and the process lives; 424a: a
-- store to a prot-5 page leaves the bytes unchanged) -- so the answer has to come from the read
-- path, which does fault. Store a DIFFERENT dword and read it back: the marker appears only if
-- the store landed. The original instruction bytes go back immediately afterwards.
print("")
print("[C] 547 reports prot 7 -- store a marker and read it back (this is the test)")
local mark = (v0 + 1) % 4294967296
pcall(function() memory.write_dword(target + 0x00, uint64(mark)) end)
local w0 = 0
pcall(function() w0 = N(memory.read_dword(target + 0x00)) end)
print(string.format("[C] readback %08X (wrote %08X) -> %s", w0, mark,
    w0 == mark and "STORE LANDED" or "store did not land"))
pcall(function() memory.write_dword(target + 0x00, uint64(v0)) end)
local w1 = 0
pcall(function() w1 = N(memory.read_dword(target + 0x00)) end)
print(string.format("[C] restored %08X (expected %08X) %s", w1, v0,
    w1 == v0 and "OK" or "NOT RESTORED"))

-- restore, so a surviving process leaves the page as it was
set_entry(target, 0, 0x4000, 5, 2)
v548("restore eboot text -> prot 5 (RX)")
prot_of(target, "eboot restored")

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1480a COMPLETE ===")
