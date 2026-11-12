-- CRASH_CLASS: MODERATE
-- PROBE 1419a: 628 mmap_dmem across every container index and a physical-address ladder
--
-- prior art:
--   results/phase36_realargs/1409a_637_dmem_ceiling_20261109_152941.txt
--     628(phys,0x4000) for phys 0x100000000 / 0x200000000 / 0x1000000000 -> -1 EBUSY(16).
--   results/phase35_dead_end_reruns/1330a_mmap_dmem_flags_20261022_*.txt and 331a
--     628 refused every shape (descriptor -1, dmem0 fd, zero fd, 0, three protections,
--     flag 0x40, a nonzero address hint and two offsets); those probes varied arg1.
--   docs/DMEM_628_AND_SYSCALL_585_14_10.md
--     628 takes (phys, len, container_idx, flags, extra_bits, extra_addr); len >= 0x4000 and
--     16 KiB aligned; container index < 0x15; idx = 0xFFFFFFFF skips the lookup and makes the
--     worker store curthread at container_table-0xE8.
--   13.60 body 0xffffffff8b47d540 (decoded this session):
--     uap[0] must satisfy  (uap[0] << 0x32) == 0        -> 16 KiB aligned, < 2^50
--     uap[1] must be 16 KiB aligned and >= 0x4000
--     uap[2] = container index;  0x8ad833e0(idx, proc) is literally  cmp edi,0x15; setb al
--              i.e. NO ownership check, only idx < 0x15
--     uap[3] = flags, (flags & 0xfffffc0c) == 0  -> bits {0,1,4,5,6,7,8,9}
--     uap[4] = prot,  (prot & 0x9fdf2f) == 0     -> bits {4,6,7,11,13,21,22}
--     uap[5] = extra, must be < 0x4000
--     then 0x8ad833e0, and the range is checked against the container record
--     (record +0x20 base, +0x28 end, +0x69 state byte, +0x48/+0x50 descriptor range)
--   docs/SYSENT... 586 dmem_container: 586(n) for n != -1 does priv_check(td,0x2ad) and then
--     writes proc+0x5c4 = n for n <= 4 and record+0x38 != 0; 586(-1) returns 0 without the
--     check.  proc+0x5c4 in {1,2,3} sets td+0x408 = 1.
--
-- Reading: the container index is the physical partition selector and it is bounds-checked
-- only against 0x15.  If any container other than the game's own covers system RAM, a
-- successful 628 maps it into this process and the console is finished.  So: walk every
-- index, then walk physical addresses inside each index that stops returning EINVAL.
--
-- Method: (A) idx 0..0x14 at one phys; (B) the same with bit 6 of flags set; (C) for every
-- idx that answered anything other than EINVAL, a physical ladder; (D) read the first mapped
-- page for each success.

print("=== PROBE 1419a: 628 CONTAINER + PHYSICAL LADDER ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function call6(sc, a, b, c, d, e)
    local ok, rv = pcall(function() return sc(uint64(a or 0), uint64(b or 0), uint64(c or 0), uint64(d or 0), uint64(e or 0), uint64(0)) end)
    if not ok then return "EXC" end
    return sg(rv)
end

local pid = sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", pid))

local sc628 = mk(628)
local LEN = 0x4000

local function one(tag, phys, idx, flags, prot, extra)
    local rv = call6(sc628, phys, LEN, idx, flags, prot, extra)
    if type(rv) == "number" and rv >= 0x10000 and rv < 0x8000000000 then
        print(string.format("  *** SUCCESS %s phys=0x%X idx=0x%X flags=0x%X prot=0x%X -> VA 0x%X", tag, phys, idx, flags, prot, rv))
        return rv, "MAPPED"
    end
    return rv, nil
end

-- ---------------------------------------------------------------- A: every container index
print("[A] idx 0..0x14 at phys 0x100000000, flags 0, prot 0")
local nonEINVAL = {}
for idx = 0, 0x14 do
    local rv, mapped = one("A", 0x100000000, idx, 0, 0, 0)
    if mapped then
        nonEINVAL[#nonEINVAL + 1] = idx
        print(string.format("  idx=0x%X MAPPED 0x%X", idx, rv))
    else
        print(string.format("  idx=0x%X -> %s errno=%s", idx, tostring(rv), es()))
        if rv ~= -1 or es():find("Invalid") == nil then nonEINVAL[#nonEINVAL + 1] = idx end
    end
end

-- ---------------------------------------------------------------- B: flags with bit 6
print("[B] idx 0..0x14 at phys 0x100000000, flags 0x40, prot 0x40")
for idx = 0, 0x14 do
    local rv, mapped = one("B", 0x100000000, idx, 0x40, 0x40, 0)
    if mapped then
        print(string.format("  idx=0x%X MAPPED 0x%X", idx, rv))
        nonEINVAL[#nonEINVAL + 1] = idx
    else
        local e = es()
        if not (rv == -1 and e:find("Invalid") ~= nil) then
            print(string.format("  idx=0x%X -> %s errno=%s", idx, tostring(rv), e))
            nonEINVAL[#nonEINVAL + 1] = idx
        end
    end
end

-- ---------------------------------------------------------------- C: physical ladder
print("[C] physical ladder, flags 0x40, prot 0x40")
local PHYS = {0x0, 0x4000, 0x100000, 0x1000000, 0x10000000, 0x40000000, 0x80000000,
              0x100000000, 0x200000000, 0x400000000, 0x800000000, 0x1000000000,
              0x2000000000, 0x4000000000, 0x8000000000, 0x10000000000, 0x20000000000}
local successes = {}
for _, idx in ipairs({0, 1, 2, 3, 4}) do
    for _, phys in ipairs(PHYS) do
        local rv, mapped = one("C", phys, idx, 0x40, 0x40, 0)
        if mapped then
            successes[#successes + 1] = { idx = idx, phys = phys, va = rv }
            print(string.format("  idx=0x%X phys=0x%X MAPPED 0x%X first=%s", idx, phys, rv, hex4(rd(rv))))
        elseif rv ~= -1 then
            print(string.format("  idx=0x%X phys=0x%X -> %s errno=%s", idx, phys, tostring(rv), es()))
        end
    end
end

print(string.format("[D] successes=%d", #successes))
for i, s in ipairs(successes) do
    print(string.format("  #%d idx=0x%X phys=0x%X va=0x%X d0=%s d4=%s d8=%s dc=%s",
        i, s.idx, s.phys, s.va, hex4(rd(s.va)), hex4(rd(s.va + 4)), hex4(rd(s.va + 8)), hex4(rd(s.va + 12))))
end
print("=== PROBE 1419a COMPLETE ===")
