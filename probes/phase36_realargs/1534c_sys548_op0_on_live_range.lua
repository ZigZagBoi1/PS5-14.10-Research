-- CRASH_CLASS: MODERATE
-- PROBE 1534c: sys 548 op 0 on a range that already exists
--
-- Context: 1534b called 548 op 0 with a 16 KiB-aligned position at a free fixed
-- address and got EBUSY(16) for every descriptor - /dev/zero, /app0/eboot.bin,
-- /dev/dmem0, /dev/gc, and a bogus fd 0xFFFFFFFF - while a misaligned position
-- and arg2 bit 0x400 gave EINVAL(22) and /dev/dmem0 at position 0x120000000
-- gave the same EACCES(13) that 477 gives. So the entry checks run and the
-- descriptor is consumed, and the map then fails with EBUSY.
--
-- The fact that changes the reading: op 3 in that same run mapped the very same
-- address successfully (rv = 0x500000000, 547 confirming prot 3). The address
-- was free and mappable, so EBUSY was not an address conflict. And 1480b
-- recorded op 0 returning 0 with processed=1 on page A which the probe already
-- owned, with 547 unchanged.
--
-- HYPOTHESIS THIS RUN TESTS (it is not yet a measured fact): op 0 acts on a
-- range that already exists, taking a descriptor and a file position, rather
-- than creating one at a chosen address. If so, attaching a new object to a
-- range the caller owns would be a primitive mmap does not offer.
--
-- The rungs are ordered by risk, cheapest and most survivable first, because a
-- kill ends the capture and everything after it:
--
--   [B] /app0/eboot.bin over a live op-3 range, position 0 - if the first dword
--       becomes 0x464C457F, a vnode's content appeared where 0xAABBCCDD was
--   [C] /dev/zero, the same-shape control that cannot fault
--   [D] /dev/dmem0 at positions 0 and 0x120000000, 547 only, no read
--   [E] fd 0 and a bogus fd - the exact 1480b shape, on its own op-3 range
--   [F] the physhm descriptor from 629, last, because 477 maps it and the first
--       read kills (321a): if op 0 backs it instead, a read of the range is the
--       one test that separates a real mapping from an empty one
--   [A2] a second free slot, op 0 with MAP_FIXED (0x10) in arg2 - the descriptor
--       path ORs bit 0 into the flag word, so 1534b's arg2=0 sent flags=1 and
--       never asked for a fixed address
--
-- Every read is gated on a 547 that returns 0 and whose own range covers the
-- address, so a refused rung never dereferences a free page. Every rung that
-- leaves a mapping behind releases it before the next one runs.
--
-- -- prior art:
--   results/phase36_realargs/1534b_sys548_op0_descriptor_map_20261110_141234.txt
--       op 0 EBUSY(16) at a free fixed address for every descriptor, including
--       a bogus fd; EINVAL(22) for a misaligned position and arg2 0x400;
--       EACCES(13) for dmem0 at 0x120000000; op 3 maps the same address
--   results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt
--       op 0 rv=0 processed=1 on page A the probe already owned, arg1=0, 547
--       unchanged; the same op at free 0x0/0x10000/0x40000/0x100000/0x310000000
--       all EBUSY(16); op 1 and op 4 leave their pages mapped and readable
--   results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt
--       op 2 needs start and length 16 KiB aligned; anon 3 -> 7 gives EACCES(13)
--   results/phase36_realargs/1478a_dev_mmap_wrap_ftruncate_20261109_192453.txt
--       dmem0/dmem1 refuse positions above 0x120000000 with EACCES(13)
--   results/phase17_new_vectors/321a_physhm_ptr_20261022_122101.txt
--       629 descriptor + 477 map returns an address whose first read faults
--   docs/VM_LAYER_14_10.md sections 6, 8, 9 and 10; docs/DEVICE_WINDOW_14_10.md

print("=== PROBE 1534c: SYS 548 OP 0 ON AN EXISTING MAPPING ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))
print("")

local sc548, sc477, sc547, sc674, sc73, sc5, sc6, sc629 =
      mk(548), mk(477), mk(547), mk(674), mk(73), mk(5), mk(6), mk(629)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x40)
local cnt = memory.alloc(0x10)
local dbuf = memory.alloc(0x9000)

local function zero(p, n) for i = 0, n - 1 do pcall(function() memory.write_byte(p + i, 0) end) end end
zero(ent, 0x40); zero(rec, 0x40); zero(cnt, 0x10); zero(dbuf, 0x9000)

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end
local function rd(addr)
    local ok, v = pcall(function() return N(memory.read_dword(addr)) end)
    if ok then return v % 4294967296 end
    return nil
end
local function wr(addr, v) pcall(function() memory.write_dword(addr, uint64(v)) end) end
local function close_fd(fd)
    if fd and fd >= 0 then pcall(function() sc6(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end
end

-- 547's record is 0x18 bytes: start_lo, start_hi, end_lo, end_hi, prot, flags.
-- prot is only returned when the call succeeded AND the record's own range
-- covers the address, so an unmapped page can never look like prot 0.
local function prot_at(addr, tag)
    zero(rec, 0x20)
    local ok, v = pcall(function()
        return N(sc547(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    local lo, hi, elo, ehi = 0, 0, 0, 0
    pcall(function() lo  = N(memory.read_dword(rec + 0x00)) % 4294967296 end)
    pcall(function() hi  = N(memory.read_dword(rec + 0x04)) % 4294967296 end)
    pcall(function() elo = N(memory.read_dword(rec + 0x08)) % 4294967296 end)
    pcall(function() ehi = N(memory.read_dword(rec + 0x0C)) % 4294967296 end)
    local pv = 0
    local okp = pcall(function() pv = N(memory.read_dword(rec + 0x10)) % 4294967296 end)
    local rs, re = lo + hi * 4294967296, elo + ehi * 4294967296
    local p = nil
    if ok and v == 0 and okp and addr >= rs and addr < re then p = pv end
    print(string.format("    %-40s 547 rv=%-3s prot=%-4s range=%X..%X",
        tag, ok and tostring(v) or "EXC", p and string.format("0x%X", p) or "nil", rs, re))
    return p
end

local function unmap(addr, len, tag)
    if addr == nil or addr < 0x1000 or addr > 549755813888 then return end
    local ok, v = pcall(function()
        return N(sc73(uint64(string.format("0x%X", addr)), uint64(len), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    print(string.format("    73(0x%X, 0x%X) -> %s %s  [%s]", addr, len,
        ok and tostring(v) or "EXC", (ok and v ~= 0) and es() or "", tag))
end

local function rec_count()
    zero(cnt, 0x10)
    local ok, v = pcall(function()
        return N(sc674(uint64(dbuf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
    end)
    if not ok or v ~= 0 then return -1 end
    return N(memory.read_dword(cnt))
end

-- ------------------------------------------------- [A] a free slot and a live range
print("[A] enumerate, then create a live 16 KiB range with op 3")
local nrec = rec_count()
print(string.format("    674 records=%d", nrec))
if nrec <= 0 then
    print("    ABORT: no map enumeration")
    print("=== PROBE 1534c ABORTED ===")
    return
end
if nrec > 400 then nrec = 400 end
local marks = {}
for i = 0, nrec - 1 do
    local b = dbuf + i * 72
    local lo, hi, elo, ehi = 0, 0, 0, 0
    pcall(function() lo  = N(memory.read_dword(b + 0x00)) % 4294967296 end)
    pcall(function() hi  = N(memory.read_dword(b + 0x04)) % 4294967296 end)
    pcall(function() elo = N(memory.read_dword(b + 0x08)) % 4294967296 end)
    pcall(function() ehi = N(memory.read_dword(b + 0x0C)) % 4294967296 end)
    marks[#marks + 1] = { s = lo + hi * 4294967296, e = elo + ehi * 4294967296 }
end
local function is_free(a, n)
    for _, r in ipairs(marks) do if r.s < a + n and a < r.e then return false end end
    return true
end
local TARGET = nil
for _, a in ipairs({0x500000000, 0x500004000, 0x600000000, 0x700000000, 0x400000000, 0x800000000}) do
    if is_free(a, 0x4000) then TARGET = a break end
end
if not TARGET then
    print("    ABORT: no free slot")
    print("=== PROBE 1534c ABORTED ===")
    return
end
print(string.format("    TARGET=0x%X free=%s", TARGET, tostring(is_free(TARGET, 0x4000))))
prot_at(TARGET, "TARGET before")

local function op3(start, len, prot, tag)
    zero(ent, 0x40)
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, uint64(3)) end)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    local ok, v = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0)))
    end)
    print(string.format("  -> op 3 %s: rv=%s %s", tag, ok and tostring(v) or "EXC",
        (ok and v < 0) and es() or ""))
    if ok and v > 0x1000 and v <= 549755813888 then return v end
    return nil
end

local U = op3(TARGET, 0x4000, 3, string.format("start=0x%X", TARGET))
if not U then U = op3(0, 0x4000, 3, "start=0") end
if not U then
    print("    ABORT: could not create a live range with op 3")
    print("=== PROBE 1534c ABORTED ===")
    return
end
print(string.format("    live range U=0x%X", U))
prot_at(U, "U before")
wr(U, 0xAABBCCDD)
print(string.format("    U holds %08X", rd(U) or 0))
print("")

-- ------------------------------------------------- op 0 helpers
local function op0at(start, fd, pos, prot, len, arg2, op, tag)
    zero(ent, 0x40)
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", pos))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, uint64(op)) end)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %s (op=%d start=0x%X fd=%d pos=0x%X prot=%d len=0x%X arg2=0x%X)",
        tag, op, start, fd, pos, prot, len, arg2))
    local ok, v = pcall(function()
        return N(sc548(uint64(fd), uint64(arg2), uint64(ent), uint64(1), uint64(cnt), uint64(0)))
    end)
    local pc = "?"
    local ok2, v2 = pcall(function() return N(memory.read_dword(cnt)) end)
    if ok2 then pc = tostring(v2 % 4294967296) end
    if ok then
        print(string.format("     rv=%-12d %-18s processed=%s", v, (v < 0) and es() or "", pc))
    else
        print("     EXC")
    end
    return ok and v or -999
end

local function op0(fd, pos, prot, len, arg2, tag)
    return op0at(U, fd, pos, prot, len, arg2, 0, tag)
end

-- ------------------------------------------------- [A2] a free slot with MAP_FIXED
print("[A2] op 0 at a second free slot with MAP_FIXED in arg2")
print("     The descriptor path ORs bit 0 into the flag word, so 1534b's arg2=0")
print("     sent flags=1 and never asked for a fixed address. 0x10 is MAP_FIXED,")
print("     0x12 is MAP_FIXED|MAP_PRIVATE, 0x20 and 0x40 are further selector bits.")
local T2 = nil
for _, a in ipairs({0x500004000, 0x600000000, 0x700000000, 0x400000000, 0x800000000, 0x900000000}) do
    if a ~= TARGET and a ~= U and is_free(a, 0x4000) then T2 = a break end
end
if not T2 then
    print("    (no second free slot; skipped)")
else
    print(string.format("    T2=0x%X", T2))
    local fd_z = N(sc5(str_addr("/dev/zero"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("    open(/dev/zero) = %d", fd_z))
    if fd_z >= 0 then
        for _, f in ipairs({0x10, 0x12, 0x20, 0x40}) do
            local before_n = rec_count()
            local r = op0at(T2, fd_z, 0, 3, 0x4000, f, 0, string.format("free slot arg2=0x%X", f))
            local after_n = rec_count()
            print(string.format("     674 records %d -> %d%s", before_n, after_n,
                (before_n >= 0 and after_n > before_n) and "  <<< THE PROCESS GREW" or ""))
            local pT2 = prot_at(T2, "T2 after the rung")
            if pT2 then
                local z = rd(T2)
                print(string.format("     T2 holds %s", z and string.format("%08X", z) or "nil"))
                unmap(T2, 0x4000, "release T2 so the next rung starts free")
            elseif r > 0x1000 and r <= 549755813888 then
                print(string.format("     op 0 returned 0x%X", r))
                if prot_at(r, "the returned address") then
                    unmap(r, 0x4000, "the map op 0 placed")
                else
                    print("     547 does not describe it, so it is not released by this probe")
                end
            elseif r == 0 then
                print("     rv=0 but T2 is still unmapped and no address came back")
            end
        end
        close_fd(fd_z)
    end
end
print("")

-- ------------------------------------------------- [A3] the same with a vnode
print("[A3] the same with /app0/eboot.bin - the prize is the ELF magic at a chosen VA")
if T2 then
    local fd_eb2 = N(sc5(str_addr("/app0/eboot.bin"), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("    open(/app0/eboot.bin) = %d", fd_eb2))
    if fd_eb2 >= 0 then
        for _, f in ipairs({0x10, 0x12}) do
            local r = op0at(T2, fd_eb2, 0, 1, 0x4000, f, 0, string.format("eboot at the free slot arg2=0x%X", f))
            local pT2 = prot_at(T2, "T2 after the eboot rung")
            local at = nil
            if pT2 then
                at = T2
            elseif r > 0x1000 and r <= 549755813888 and prot_at(r, "the returned address") then
                at = r
            end
            if at then
                local m = rd(at)
                print(string.format("     0x%X holds %s   (ELF magic is 464C457F)",
                    at, m and string.format("%08X", m) or "nil"))
                unmap(at, 0x4000, "release the eboot map")
            elseif r == 0 then
                print("     rv=0 but neither T2 nor a returned address is mapped")
            else
                print("     no mapping resulted")
            end
        end
        close_fd(fd_eb2)
    end
end
print("")

-- ------------------------------------------------- [B] a vnode over the live range
print("[B] /app0/eboot.bin over the live range - does the vnode's content appear?")
wr(U, 0xAABBCCDD)
print(string.format("    sentinel restored: U holds %08X", rd(U) or 0))
local fd_eb = N(sc5(str_addr("/app0/eboot.bin"), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/app0/eboot.bin) = %d", fd_eb))
if fd_eb >= 0 then
    local r = op0(fd_eb, 0, 1, 0x4000, 0, "eboot pos=0 prot=R")
    local m = rd(U)
    print(string.format("     U holds %s   (ELF magic is 464C457F, sentinel was AABBCCDD)",
        m and string.format("%08X", m) or "nil"))
    prot_at(U, "U after the eboot rung")
    if r == 0 then
        wr(U, 0xAABBCCDD)
        local r2 = op0(fd_eb, 0x4000, 1, 0x4000, 0, "eboot pos=0x4000 prot=R")
        local m2 = rd(U)
        print(string.format("     U holds %s   (must differ from the magic if the position is a file offset)",
            m2 and string.format("%08X", m2) or "nil"))
        prot_at(U, "U after the second eboot rung")
        if r2 ~= 0 then print("     (second rung refused; nothing to compare)") end
    end
    close_fd(fd_eb)
end
print("")

-- ------------------------------------------------- [C] the same-shape control
print("[C] /dev/zero over the live range, the same-shape control")
wr(U, 0xAABBCCDD)
local fd_zero = N(sc5(str_addr("/dev/zero"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/dev/zero) = %d", fd_zero))
if fd_zero >= 0 then
    op0(fd_zero, 0, 3, 0x4000, 0, "zero pos=0 prot=RW")
    local z = rd(U)
    print(string.format("     U holds %s   (00000000 means the zero object is now over U)", z and string.format("%08X", z) or "nil"))
    prot_at(U, "U after the zero rung")
    close_fd(fd_zero)
end
print("")

-- ------------------------------------------------- [D] dmem0, 547 only
print("[D] /dev/dmem0 over the live range (547 only, never read)")
local fd_dmem = N(sc5(str_addr("/dev/dmem0"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/dev/dmem0) = %d", fd_dmem))
if fd_dmem >= 0 then
    op0(fd_dmem, 0, 3, 0x4000, 0, "dmem0 pos=0")
    prot_at(U, "U after dmem0 pos 0")
    op0(fd_dmem, 0x120000000, 3, 0x4000, 0, "dmem0 pos=0x120000000")
    prot_at(U, "U after dmem0 high pos")
    close_fd(fd_dmem)
end
print("")

-- ------------------------------------------------- [E] the 1480b shape on its own range
print("[E] the 1480b shape - fd 0 and a bogus fd - on a range of its own")
local U2 = op3(0, 0x4000, 3, "E's own range")
if U2 then
    wr(U2, 0xAABBCCDD)
    print(string.format("    U2=0x%X holds %08X", U2, rd(U2) or 0))
    op0at(U2, 0, 0, 3, 0x4000, 0, 0, "fd=0 pos=0 the 1480b shape")
    local a1 = rd(U2)
    print(string.format("     U2 holds %s   (AABBCCDD means nothing was installed)", a1 and string.format("%08X", a1) or "nil"))
    prot_at(U2, "U2 after the fd=0 rung")
    op0at(U2, 0xFFFFFFFF, 0, 3, 0x4000, 0, 0, "bogus fd 0xFFFFFFFF")
    local a2 = rd(U2)
    print(string.format("     U2 holds %s", a2 and string.format("%08X", a2) or "nil"))
    prot_at(U2, "U2 after the bogus fd rung")
    unmap(U2, 0x4000, "release U2")
else
    print("    (op 3 refused a kernel-chosen address; skipped)")
end
print("")

-- ------------------------------------------------- [F] physhm, last
print("[F] the physhm descriptor from 629 over the live range - LAST, the read may fault")
local fd_ph = N(sc629(uint64(1), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    629(1,2,0,0) = %d", fd_ph))
if fd_ph >= 0 then
    wr(U, 0xAABBCCDD)
    local before = prot_at(U, "U before physhm")
    local r = op0(fd_ph, 0, 3, 0x4000, 0, "physhm pos=0")
    local after = prot_at(U, "U after physhm")
    if r == 0 and after and after ~= before then
        print("     the rung returned 0 and the record changed; reading U is the backing test")
        local ph = rd(U)
        print(string.format("     U holds %s%s", ph and string.format("%08X", ph) or "nil",
            (ph and ph ~= 0xAABBCCDD) and "   <<< CONTENT CHANGED" or ""))
    elseif r == 0 then
        print("     rv=0 but the 547 record did not change; not reading U")
    else
        print("     refused; not reading U")
    end
    close_fd(fd_ph)
end
print("")

-- ------------------------------------------------- [G] op 1
print("[G] op 1 on the live range")
wr(U, 0xAABBCCDD)
op0at(U, 0, 0, 3, 0x4000, 0, 1, "op 1 on U")
print(string.format("     U holds %s after op 1", rd(U) and string.format("%08X", rd(U)) or "nil"))
prot_at(U, "U after op 1")
print("")

-- ------------------------------------------------- [H] tidy up
print("[H] tidy up")
prot_at(U, "U final")
unmap(U, 0x4000, "release U")
if T2 then prot_at(T2, "T2 final") end
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1534c COMPLETE ===")
