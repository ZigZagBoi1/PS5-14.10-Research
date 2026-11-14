-- CRASH_CLASS: MODERATE -- [C] attempts to read a device mapping that has always killed the
-- process on read. That read is the last statement of each iteration and is printed before it is
-- made, so a death leaves the address, its protection word and its name as the last line.
-- PROBE 1480c: sys 548 op 2 against the device mappings nothing else can read.
--
-- 1480a established that 548 op 2 is a real vm_map_protect for a page this process owns: prot 1
-- and 3 round-trip, 547 confirms each change, and anything carrying bit 0x4 is refused with
-- EACCES. 1480b showed the other four ops are success no-ops on an existing mapping.
--
-- That makes op 2 the only handle this process has ever had on the protection word of a mapping
-- it did not create. The GPU and driver mappings the game loader installs are exactly such a
-- case: 674 lists them as prot 0x33 (SceGnmTrapCode, TrapData, AgcDdid, EopFifo, ShadowRegInfo,
-- Cwsr, Misc, AcqRb) and prot 0x10 (SceGnmDriver), and reading any of them kills the process past
-- pcall (376a, 380a). If a protect can move one of those to prot 3, the mapping becomes readable
-- by the same mechanism that makes any RW page readable, and the GPU register file stops being
-- blind.
--
-- Phase [A] enumerates and prints the non-user protections so the set is a measurement rather
-- than a remembered list. Phase [B] protects each one and reports 547. Phase [C] reads a single
-- dword only when 547 says the protection really moved.
--
-- -- prior art:
--   results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt (op 2 works, bit 0x4 refused)
--   results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt (ops 0/1/3/4 are no-ops)
--   results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195636.txt (16 KiB rule)
--   docs/DEAD_ENDS.md (GPU device mappings read dead: 376a, 380a)
--   docs/DMEM_WINDOW_14_10.md (the one device window that is readable)

print("=== PROBE 1480c: SYS 548 OP 2 AGAINST THE DEVICE MAPPINGS ===")

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

local function v548(tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %-48s", tag))
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    local e = ""
    if r == -1 then e = es() end
    print(string.format("     rv=%-5s %-22s processed=%d", tostring(r), e, N(memory.read_dword(cnt))))
    return r
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] enumerate
print("")
print("--- [A] mappings whose protection is not 0/1/2/3/5 ---")
local buf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local nrec = 0
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[A] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("[A] 674 did not enumerate")
    print("=== PROBE 1480c INCOMPLETE ===")
    return
end
if nrec > 400 then nrec = 400 end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

local odd = {}
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
    if s >= 0x10000 and pr ~= 0 and pr ~= 1 and pr ~= 2 and pr ~= 3 and pr ~= 5 then
        odd[#odd + 1] = {s = s, e = e, pr = pr, name = name}
        print(string.format("   0x%X - 0x%X prot=0x%X %s", s, e, pr, name))
    end
end
print(string.format("[A] %d such mappings", #odd))
if #odd == 0 then
    print("[A] none; nothing to protect")
    print("=== PROBE 1480c COMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] protect
print("")
print("--- [B] ask 548 for prot 3 on each of them ---")
local moved = {}
for i = 1, #odd do
    local r = odd[i]
    local target = r.s - (r.s % 0x4000)
    if target + 0x4000 <= r.e then
        print(string.format("   target=0x%X prot_before=0x%X %s", target, r.pr, r.name))
        local before = prot_of(target)
        if before == r.pr then
            set_entry(target, 0, 0x4000, 3, 2)
            local rv = v548(string.format("op=2 prot=3 on 0x%X", target))
            if rv == 0 then
                local after = prot_of(target)
                print(string.format("     547 now prot=%s", tostring(after)))
                if after == 3 then moved[#moved + 1] = target end
            end
        else
            print(string.format("     547 disagrees with 674 (prot=%s); skipped", tostring(before)))
        end
    else
        print(string.format("   0x%X prot=0x%X is smaller than one 16 KiB page; skipped", r.s, r.pr))
    end
end
print(string.format("[B] %d mapping(s) now report prot 3", #moved))

-- ---------------------------------------------------------------- [C] read
print("")
print("--- [C] read one dword from each moved mapping ---")
if #moved == 0 then
    print("[C] nothing moved, so there is nothing to read -- the read path was never exercised")
else
    for i = 1, #moved do
        local t = moved[i]
        print(string.format("[C] reading 0x%X now (547 said prot 3)", t))
        local v = 0
        pcall(function() v = N(memory.read_dword(t)) end)
        print(string.format("[C] 0x%X -> %08X", t, v))
    end
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1480c COMPLETE ===")
