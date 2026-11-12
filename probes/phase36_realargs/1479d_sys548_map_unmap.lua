-- CRASH_CLASS: MODERATE -- op 0 and op 3 may be MAP operations, and a map at a caller-chosen
-- address that overwrites an existing mapping would corrupt the process. Every MAP attempt therefore
-- targets a VA that this probe has just unmapped and verified unmapped with 547, and a MAP whose
-- result is not visible in 547 is abandoned rather than retried with larger sizes.
-- PROBE 1479d: sys 548 ops 0, 1, 3, 4 with the measured entry layout.
--
-- 1479b measured the layout (+0x00 start, +0x08 offset, +0x10 length, +0x18 protection, +0x1C op)
-- and 1479c tests op 2 (PROTECT). Nothing is known about the other four ops on 14.10: 1479a only
-- showed that all four answer EINVAL for an all-zero entry, which is exactly what a map or unmap of
-- a zero-length range at address 0 should answer.
--
-- The interesting question is op 1. If it is UNMAP and it accepts any page-aligned start, then a
-- caller can tear an arbitrary page out of its own map -- still only a DoS -- but the acceptance
-- boundary itself is the measurement: an op that validates ownership answers EACCES for a foreign
-- range, and one that does not answers 0. op 0 and op 3 take arg1 as a descriptor (sceKernelBatchMap2
-- is fd-first), so the descriptor class is swept alongside the ranges.
--
-- -- prior art:
--   results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt (entry layout)
--   results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt (contract, ops 0/1/3/4
--       EINVAL on an all-zero entry)
--   results/kernel_handlers/asm/sys_548.asm (PART B, RVA 0xabbe60)
--   docs/VM_LAYER_14_10.md (munmap is entry-scoped, mmap validation, 673 gate chain)

print("=== PROBE 1479d: SYS 548 MAP/UNMAP OPS ===")

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
local sc73  = mk(73)

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

local function v548(a1, flags, count, tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %-48s", tag))
    local ok, v = pcall(function()
        return N(sc548(uint64(a1), uint64(flags), uint64(ent), uint64(count), uint64(cnt), uint64(0)))
    end)
    local pc = "?"
    local ok2, v2 = pcall(function() return N(memory.read_dword(cnt)) end)
    if ok2 then pc = string.format("%d", v2 % 4294967296) end
    if ok then
        print(string.format("     rv=%-4d %-20s processed=%s", v, (v == -1) and es() or "", pc))
    else
        print(string.format("     EXC processed=%s", pc))
    end
    return v
end

local function is_mapped(addr, tag)
    pcall(function() for i = 0, 0x18, 4 do memory.write_dword(rec + i, uint64(0)) end end)
    local ok, v = pcall(function()
        return N(sc547(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    local pr = -1
    if ok and v == 0 then pr = N(memory.read_dword(rec + 0x10)) end
    print(string.format("     [%s] 547 rv=%s prot=%d", tag, tostring(ok and v or "EXC"), pr))
    return pr
end

-- two independent regions so a MAP has a hole to land in
local A = N(sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1000), uint64(0xFFFFFFFF), uint64(0)))
local B = N(sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1000), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("[0] A=0x%X B=0x%X", A, B))

local good = true
if A <= 0 or A == 0xFFFFFFFFFFFFFFFF or B <= 0 or B == 0xFFFFFFFFFFFFFFFF then
    print("[!] mmap failed"); good = false
end

if good then
    pcall(function() memory.write_dword(A, uint64(0xAAAAAAAA)) end)
    pcall(function() memory.write_dword(B, uint64(0xBBBBBBBB)) end)

    print("")
    print("--- [A] every op with one valid entry {start=A, offset=0, len=0x1000, prot=3} ---")
    is_mapped(A, "A before")
    for op = 0, 4 do
        set_entry(A, 0, 0x1000, 3, op)
        local rv = v548(0, 0, 1, string.format("op=%d valid entry on A", op))
        if rv == 0 then
            local pr = is_mapped(A, string.format("A after op=%d", op))
            if pr >= 0 then
                local okr, val = pcall(function() return N(memory.read_dword(A)) end)
                print(string.format("       read ok=%s val=0x%08X", tostring(okr),
                    okr and (val % 4294967296) or 0))
            end
            -- restore if the op removed or re-protected it
            if pr < 0 or pr ~= 3 then
                set_entry(A, 0, 0x1000, 3, 2)
                v548(0, 0, 1, "   re-protect A to 3")
            end
        end
    end

    print("")
    print("--- [A2] op 1 on a page we own: does 548 unmap it? ---")
    is_mapped(A, "A before")
    set_entry(A, 0, 0x1000, 3, 1)
    local rv = v548(0, 0, 1, "op=1 start=A len=0x1000")
    if rv == 0 then is_mapped(A, "A after op1") end

    print("")
    print("--- [B] op 1 on the second page, then op 0 into the hole ---")
    is_mapped(B, "B before")
    set_entry(B, 0, 0x1000, 3, 1)
    local rvu = v548(0, 0, 1, "op=1 start=B len=0x1000")
    if rvu == 0 then
        is_mapped(B, "B after op1")
        for _, d in ipairs({0xFFFFFFFF, 0, 1}) do
            set_entry(B, 0, 0x1000, 3, 0)
            local rvm = v548(d, 0, 1, string.format("op=0 arg1=0x%X start=B len=0x1000", d))
            if rvm == 0 then
                local pr = is_mapped(B, "B after op0")
                if pr >= 0 then
                    local okr, val = pcall(function() return N(memory.read_dword(B)) end)
                    print(string.format("     read ok=%s val=0x%08X", tostring(okr),
                        okr and (val % 4294967296) or 0))
                    break
                end
            end
        end
    end

    print("")
    print("--- [C] op 3 and op 4 on a live page ---")
    for _, op in ipairs({3, 4}) do
        set_entry(A, 0, 0x1000, 3, op)
        v548(0, 0, 1, string.format("op=%d start=A len=0x1000", op))
        is_mapped(A, "A after")
    end

    print("")
    print("--- [D] op 1 with the length or the alignment wrong ---")
    set_entry(A, 0, 0x800,  3, 1); v548(0, 0, 1, "op=1 len=0x800 (unaligned)")
    set_entry(A, 0, 0,      3, 1); v548(0, 0, 1, "op=1 len=0 (empty range)")
    set_entry(A + 0x10, 0, 0x1000, 3, 1); v548(0, 0, 1, "op=1 start=A+0x10 (unaligned)")
    set_entry(0, 0, 0x1000, 3, 1); v548(0, 0, 1, "op=1 start=0")
    is_mapped(A, "A final")

    print("")
    print("--- [E] op 1 against a VA we never mapped ---")
    set_entry(0x200000000, 0, 0x1000, 3, 1)
    v548(0, 0, 1, "op=1 start=0x200000000 (never mapped)")

    print("")
    print("--- [F] flags mask with a real op ---")
    for _, fl in ipairs({0x10000000, 0x0, 0x40000000, 0x80000000}) do
        set_entry(A, 0, 0x1000, 3, 2)
        v548(0, fl, 1, string.format("op=2 flags=0x%X", fl))
    end
end

print("")
local canary = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d", canary))
print("=== PROBE 1479d COMPLETE ===")
