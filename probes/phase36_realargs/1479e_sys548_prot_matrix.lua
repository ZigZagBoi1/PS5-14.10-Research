-- CRASH_CLASS: MODERATE -- op 0/1/3/4 may be MAP/UNMAP, and a MAP that overwrites a live mapping
-- would corrupt the process. Every entry here names a page this probe owns and every call is
-- printed before it is made, so a death leaves the failing shape as the last line.
-- PROBE 1479e: sys 548 -- the protection word is the blocker, not the address.
--
-- 1479c and 1479d produced one consistent negative: every op answers EINVAL(22) with processed=0
-- for a real {start, 0, 0x1000, prot} entry, while an all-zero entry with op 2 answers 0 with
-- processed=1. The difference between the accepted and the refused entry is not the address --
-- 1479b showed start=0xFF0000 with length 0 returning 0 -- it is that the accepted entry had
-- length 0 and prot 0.
--
-- The 13.60 bulk applier at 0xffffffff8ac8dc10 validates each queued node with
--     movzx r12d, byte ptr [rdx + 0x20]
--     test r12b, 0xae
--     sete cl / or cl, al / cmp cl, 1 / jne fail
-- i.e. the protection byte must have NONE of the bits 0x02, 0x04, 0x08, 0x20, 0x80. PROT_READ on
-- FreeBSD is 0x1 and PROT_WRITE is 0x2, so a Linux/FreeBSD-shaped prot of 3 sets 0x02 and is
-- rejected by that mask. That predicts the exact negative we measured: 1479c tried 0, 1, 3 and 7,
-- and only 0 and 1 are inside the mask.
--
-- This probe sweeps the protection word over every single-bit value and every plausible pairing
-- for all five ops on a page it owns. A rv of 0 for any (op, prot) pair, followed by a 547
-- readback that differs from the starting prot, is a protection primitive; a uniform EINVAL means
-- the mask is not the gate and the refusal is deeper.
--
-- -- prior art:
--   results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt (entry layout, +0x13 kill)
--   results/phase36_realargs/1479c_sys548_protect_foreign_20261109_195337.txt (prot 0/1/3/7 EINVAL)
--   results/phase36_realargs/1479d_sys548_map_unmap_20261109_195406.txt (five ops EINVAL)
--   results/kernel_handlers/asm/sys_548.asm (PART B, RVA 0xabbe60)
--   docs/VM_LAYER_14_10.md section 6

print("=== PROBE 1479e: SYS 548 PROTECTION MATRIX ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIGSYS ignored so an absent or hostile slot reports instead of terminating the thread.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local sc477 = mk(477)
local sc547 = mk(547)

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

local function v548(tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %-44s", tag))
    local ok, rv = pcall(function() return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0)) end)
    local r, p = -999, 0
    if ok then r = N(rv) end
    local e = ""
    if r == -1 then e = es() end
    p = N(memory.read_dword(cnt))
    print(string.format("     rv=%-5s %-24s processed=%d", tostring(r), e, p))
    return r, p
end

local function prot_of(addr, tag)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then
        print(string.format("     [%s] 547 -> not mapped", tag))
        return nil, nil
    end
    local s  = N(memory.read_dword(rec + 0x00))
    local sl = N(memory.read_dword(rec + 0x04))
    local en = N(memory.read_dword(rec + 0x08))
    local eh = N(memory.read_dword(rec + 0x0C))
    local pr = N(memory.read_dword(rec + 0x10))
    print(string.format("     [%s] 547 prot=%d start=%08X%08X end=%08X%08X", tag, pr, sl, s, eh, en))
    return pr, s
end

local MAPFAIL = "0xFFFFFFFFFFFFFFFF"
local function map_anon(len)
    local ok, rv = pcall(function() return sc477(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64(MAPFAIL), uint64(0)) end)
    if not ok then return nil end
    local v = rv
    if type(v) == "table" and v.tonumber then v = v:tonumber() end
    v = tonumber(v) or 0
    if v < 0x10000 then return nil end
    return v
end

-- ---------------------------------------------------------------- [A] two pages
local A = map_anon(0x4000)
local B = map_anon(0x4000)
if not A or not B then
    print("[A] mmap failed; nothing can be measured")
    print("=== PROBE 1479e INCOMPLETE ===")
    return
end
print(string.format("[A] A=0x%X B=0x%X", A, B))
local pA = prot_of(A, "A before")
if pA ~= 3 then
    print("[A] the mapped page does not report prot 3; instrument unusable")
    print("=== PROBE 1479e INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] the matrix
-- 0xae mask: allowed single bits are 0x01, 0x10, 0x40, 0x80 is forbidden, so 0x01/0x10/0x40
-- first, then their pairings, then the ordinary 1/2/3/5 values for contrast.
local PROTS = {0x00, 0x01, 0x10, 0x40, 0x11, 0x41, 0x51, 0x10 + 0x40 + 0x01, 0x02, 0x03, 0x05, 0x07}
local OPS   = {2, 0, 1, 3, 4}

print("")
print("--- [B] op x prot on the page this probe owns ---")
local hits = 0
for oi = 1, #OPS do
    local op = OPS[oi]
    for pi = 1, #PROTS do
        local prot = PROTS[pi]
        set_entry(A, 0, 0x1000, prot, op)
        local rv = v548(string.format("op=%d prot=0x%02X len=0x1000", op, prot))
        if rv == 0 then
            hits = hits + 1
            prot_of(A, string.format("A after op=%d prot=0x%02X", op, prot))
        end
    end
end
print(string.format("[B] rv=0 count=%d of %d", hits, #OPS * #PROTS))

-- ---------------------------------------------------------------- [C] length variants
-- If the mask is not the gate, the refusal is either an address check or the range length. A
-- zero-length entry is the known-accepted shape; walking the length up from there locates the
-- first value the call accepts on THIS page.
print("")
print("--- [C] op=2 prot=1, length ladder on a page we own ---")
local LENS = {0, 0x1000, 0x2000, 0x4000, 0x8000}
for i = 1, #LENS do
    set_entry(A, 0, LENS[i], 1, 2)
    local rv = v548(string.format("op=2 prot=1 len=0x%X", LENS[i]))
    if rv == 0 then prot_of(A, string.format("A after len=0x%X", LENS[i])) end
end

print("")
print("--- [C2] op=2 prot=1 len=0x1000, offset field ---")
local OFFS = {0, 0x1000, 0x100000, 0xFFFFFFFF}
for i = 1, #OFFS do
    set_entry(A, OFFS[i], 0x1000, 1, 2)
    local rv = v548(string.format("op=2 prot=1 off=0x%X", OFFS[i]))
    if rv == 0 then prot_of(A, string.format("A after off=0x%X", OFFS[i])) end
end

-- ---------------------------------------------------------------- [D] second page, op 2
-- Same shapes on an independent page, so a result in [B] that turned A unusable cannot be
-- mistaken for a page-specific effect.
print("")
print("--- [D] the same op=2 shapes on the second page ---")
for i = 1, #LENS do
    set_entry(B, 0, LENS[i], 1, 2)
    local rv = v548(string.format("B op=2 prot=1 len=0x%X", LENS[i]))
    if rv == 0 then prot_of(B, string.format("B after len=0x%X", LENS[i])) end
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1479e COMPLETE ===")
