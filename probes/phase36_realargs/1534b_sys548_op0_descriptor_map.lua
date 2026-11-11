-- CRASH_CLASS: LOW
-- PROBE 1534b: sys 548 op 0 is a descriptor-backed mmap - map through it
--
-- Context: 548 (batch VM operation) dispatches on the entry opcode at +0x1C,
-- 0..4. Op 2 is measured as a real mprotect gated on 16 KiB alignment (1533a).
-- Op 0's previous measurements (1479a, 1479d, 1480b, 1488b) all used a file
-- POSITION that was not 16 KiB aligned, so every one of them answered EINVAL
-- at the entry check and never reached the mapping code.
--
-- The dispatcher's four-field test at 0x8b47c00e..0x8b47c03f
--   (map+0x1c9 >= 2, !(proc+0x464 & 2), !(arg2 & 0x400), proc+0x5d4 >= 0x2500000)
-- is NOT an accept/refuse gate: every branch lands on 0x8b47c1c5, which
-- re-validates the entry and calls 0xffffffff8b478430 - the same mmap helper
-- op 3 reaches. The request it builds there is
--
--   +0x00 start        (entry+0x00)
--   +0x08 length       (entry+0x10)
--   +0x10 protection   (entry+0x18)
--   +0x18 arg2 | 1
--   +0x20 0
--   +0x28 fd           (uap[0] = arg1, `mov esi,[rbx]` at 0x8b47bffa)
--   +0x30 position     (entry+0x08, `mov r9,[rbp-0x90]`)
--
-- so op 0 is a descriptor-backed mmap: arg1 is the fd, arg2 a flag word, and
-- the entry's +0x08 is the file position. `proc+0x5d4` is zero from process
-- init (`0xffffffff8aefba5e mov qword [rbx+0x5d4], 0`), so the descriptor path
-- is the one a game process always takes.
--
-- The question is not memory growth. It is whether this second map entry point
-- backs a descriptor that 477 cannot: /dev/dmem0 refuses positions above
-- 0x120000000 with EACCES through 477 (1478a), and the physhm descriptor from
-- 629 maps through 477 and then kills on first touch (321a).
--
-- The probe therefore carries four controls, because a bare success proves
-- nothing:
--   - a bogus fd (0xFFFFFFFF): if that also succeeds, arg1 is ignored
--   - /app0/eboot.bin at position 0 and 0x4000: a vnode-backed map whose
--     content must be the ELF magic at 0 and something else at 0x4000, which
--     is the only way to show the position is a real file position
--   - op 3 at the same address: the mappability control for TARGET itself
--   - the rv of every op 0 is the landing address where the kernel returns
--     one, so TARGET is never assumed
--
-- Safety: the only pages this probe reads are the /dev/zero map (cannot
-- fault), the eboot.bin map (vnode-backed, p=0x3/0x5, readable) and the
-- 548 op 3 map. Device mappings are checked with 547 and never dereferenced -
-- a 477 mapping of physhm is also "mapped" to 547 and still kills on touch,
-- so 547 alone is not backing evidence and this probe does not pretend it is.
--
-- -- prior art:
--   results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt
--       op 2 is a working mprotect; start and length must be 16 KiB aligned
--   results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt
--       entry layout +0x00 start, +0x08 offset, +0x10 length, +0x18 prot, +0x1C op
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202017.txt
--       op 2 on a device window (0x33 taken on SceGnmTrapData)
--   results/phase36_realargs/1478a_dev_mmap_wrap_ftruncate_20261109_192453.txt
--       dmem0/dmem1 refuse offsets above 0x120000000 with EACCES(13)
--   results/phase36_realargs/1396b_dev_map_writable_*.txt
--       open(5) with 0x4002 (O_RDWR|O_NONBLOCK), 477 with mtype 1 and an fd
--   docs/VM_LAYER_14_10.md sections 6, 8 and 9; docs/DEVICE_WINDOW_14_10.md

print("=== PROBE 1534b: SYS 548 OP 0, DESCRIPTOR-BACKED MMAP ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))
print("")

local sc548, sc477, sc547, sc674, sc73, sc5, sc6 =
      mk(548), mk(477), mk(547), mk(674), mk(73), mk(5), mk(6)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x40)
local cnt = memory.alloc(0x10)
local dbuf = memory.alloc(0x9000)

local function zero(p, n) for i = 0, n - 1 do pcall(function() memory.write_byte(p + i, 0) end) end end
local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end
local function rd(addr) local ok, v = pcall(function() return N(memory.read_dword(addr)) end) if ok then return v % 4294967296 end return nil end

local function prot_at(addr, tag)
    zero(rec, 0x20)
    local ok, v = pcall(function()
        return N(sc547(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    local p = nil
    local lo, hi, elo, ehi = 0, 0, 0, 0
    pcall(function() lo  = N(memory.read_dword(rec + 0x00)) % 4294967296 end)
    pcall(function() hi  = N(memory.read_dword(rec + 0x04)) % 4294967296 end)
    pcall(function() elo = N(memory.read_dword(rec + 0x08)) % 4294967296 end)
    pcall(function() ehi = N(memory.read_dword(rec + 0x0C)) % 4294967296 end)
    local pv = 0
    local okp = pcall(function() pv = N(memory.read_dword(rec + 0x10)) % 4294967296 end)
    local rs, re = lo + hi * 4294967296, elo + ehi * 4294967296
    if ok and v == 0 and okp and addr >= rs and addr < re then p = pv end
    print(string.format("    %-32s 547 rv=%-3s prot=%-4s range=%X..%X",
        tag, ok and tostring(v) or "EXC", p and string.format("0x%X", p) or "nil", rs, re))
    return p
end

local function unmap(addr, len, tag)
    local ok, v = pcall(function()
        return N(sc73(uint64(string.format("0x%X", addr)), uint64(len), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    print(string.format("    73(0x%X) -> %s %s  [%s]", addr, ok and tostring(v) or "EXC",
        (ok and v ~= 0) and es() or "", tag))
    return ok and v or -999
end

-- --------------------------------------------------------- [A] the VM map
print("[A] enumerate the VM map")
zero(dbuf, 0x9000); zero(cnt, 0x10)
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(dbuf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("    674 rv=%d records=%d", okc and c or -999, nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("    ABORT: cannot enumerate the map, so free-space claims below would be guesses")
    print("=== PROBE 1534b ABORTED ===")
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
    for _, r in ipairs(marks) do
        if r.s < a + n and a < r.e then return false end
    end
    return true
end
local TARGET = nil
for _, a in ipairs({0x500000000, 0x500004000, 0x600000000, 0x700000000, 0x400000000, 0x800000000}) do
    if is_free(a, 0x4000) then TARGET = a break end
end
if not TARGET then
    print("    ABORT: no free 16 KiB slot in the candidate list")
    print("=== PROBE 1534b ABORTED ===")
    return
end
print(string.format("    TARGET=0x%X", TARGET))
if prot_at(TARGET, "TARGET before") ~= nil then
    print("    ABORT: TARGET is already mapped")
    print("=== PROBE 1534b ABORTED ===")
    return
end
print("")

-- --------------------------------------------------------- [B] op 0 helper
local last_landing = nil
local function op0(fd, pos, prot, len, arg2, tag)
    zero(ent, 0x40)
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", TARGET))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", pos))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, uint64(0)) end)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %s (fd=%d pos=0x%X prot=%d len=0x%X arg2=0x%X)", tag, fd, pos, prot, len, arg2))
    local ok, v = pcall(function()
        return N(sc548(uint64(fd), uint64(arg2), uint64(ent), uint64(1), uint64(cnt), uint64(0)))
    end)
    local pc = "?"
    local ok2, v2 = pcall(function() return N(memory.read_dword(cnt)) end)
    if ok2 then pc = tostring(v2 % 4294967296) end
    if ok then
        print(string.format("     rv=%-5d %-18s processed=%s", v, (v < 0) and es() or "", pc))
    else
        print("     EXC")
    end
    last_landing = nil
    if ok and v > 0x10000000000 and v <= 549755813888 then last_landing = v end
    return ok and v or -999
end

local function rung_done(tag)
    if last_landing and last_landing ~= TARGET then
        print(string.format("     rv says the map landed at 0x%X, not TARGET", last_landing))
        prot_at(last_landing, "at the rv address")
        unmap(last_landing, 0x4000, tag .. " (rv address)")
    end
    if prot_at(TARGET, "TARGET after " .. tag) ~= nil then
        unmap(TARGET, 0x4000, tag)
        prot_at(TARGET, "TARGET after the unmap")
    end
    print("")
end

-- --------------------------------------------------------- [C] /dev/zero
print("[B] /dev/zero - the descriptor that cannot fault")
local fd_zero = N(sc5(str_addr("/dev/zero"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/dev/zero) = %d", fd_zero))
if fd_zero >= 0 then
    op0(fd_zero, 0, 3, 0x4000, 0, "zero pos=0")
    local U = last_landing or TARGET
    if prot_at(U, "after op 0 (zero pos 0)") ~= nil then
        local v0 = rd(U)
        print(string.format("     read  = %s", v0 and string.format("%08X", v0) or "nil"))
        if v0 ~= nil then
            pcall(function() memory.write_dword(U, uint64(0x41424344)) end)
            local w0 = rd(U)
            print(string.format("     rw    = %08X%s", w0 and (w0 % 4294967296) or 0,
                (w0 and w0 % 4294967296 == 0x41424344) and "  <<< WRITABLE" or ""))
        end
    end
    rung_done("zero pos 0")

    op0(0xFFFFFFFF, 0, 3, 0x4000, 0, "bogus fd 0xFFFFFFFF")
    rung_done("bogus fd")

    op0(fd_zero, 0x1000, 3, 0x4000, 0, "zero pos=0x1000 (misaligned position)")
    rung_done("zero pos 0x1000")

    op0(fd_zero, 0, 3, 0x4000, 0x400, "zero arg2=0x400")
    rung_done("zero arg2 0x400")

    pcall(function() sc6(uint64(fd_zero), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("")

-- --------------------------------------------------------- [D] a vnode, to prove position
print("[C] /app0/eboot.bin - the position must select different file content")
local fd_eb = N(sc5(str_addr("/app0/eboot.bin"), uint64(0x0000), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/app0/eboot.bin, O_RDONLY) = %d", fd_eb))
if fd_eb >= 0 then
    op0(fd_eb, 0, 1, 0x4000, 0, "eboot pos=0 prot=R")
    local U = last_landing or TARGET
    if prot_at(U, "after op 0 (eboot pos 0)") ~= nil then
        local m = rd(U)
        print(string.format("     first dword = %s (ELF magic is 464C457F)", m and string.format("%08X", m) or "nil"))
    end
    rung_done("eboot pos 0")

    op0(fd_eb, 0x4000, 1, 0x4000, 0, "eboot pos=0x4000 prot=R")
    local U2 = last_landing or TARGET
    if prot_at(U2, "after op 0 (eboot pos 0x4000)") ~= nil then
        local m2 = rd(U2)
        print(string.format("     first dword at file position 0x4000 = %s (must differ from the magic)",
            m2 and string.format("%08X", m2) or "nil"))
    end
    rung_done("eboot pos 0x4000")
    pcall(function() sc6(uint64(fd_eb), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("")

-- --------------------------------------------------------- [E] devices
print("[D] /dev/dmem0 through op 0 (547 only, never dereferenced)")
local fd_dmem = N(sc5(str_addr("/dev/dmem0"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/dev/dmem0) = %d", fd_dmem))
if fd_dmem >= 0 then
    op0(fd_dmem, 0, 3, 0x4000, 0, "dmem0 pos=0")
    rung_done("dmem0 pos 0")
    op0(fd_dmem, 0x120000000, 3, 0x4000, 0, "dmem0 pos=0x120000000 (477 refuses)")
    rung_done("dmem0 high pos")
    pcall(function() sc6(uint64(fd_dmem), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("")

print("[E] /dev/gc through op 0")
local fd_gc = N(sc5(str_addr("/dev/gc"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    open(/dev/gc) = %d", fd_gc))
if fd_gc >= 0 then
    op0(fd_gc, 0, 3, 0x4000, 0, "gc pos=0")
    rung_done("gc pos 0")
    pcall(function() sc6(uint64(fd_gc), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("")

-- --------------------------------------------------------- [F] controls
print("[F] mappability control: op 3 at the same address")
zero(ent, 0x40)
pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", TARGET))) end)
pcall(function() memory.write_qword(ent + 0x10, uint64(0x4000)) end)
pcall(function() memory.write_dword(ent + 0x18, uint64(3)) end)
pcall(function() memory.write_byte(ent + 0x1C, uint64(3)) end)
pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
local ok3, v3 = pcall(function()
    return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0)))
end)
print(string.format("    op 3 rv=%s %s", ok3 and tostring(v3) or "EXC", (ok3 and v3 < 0) and es() or ""))
if ok3 and v3 > 0x10000000000 and v3 <= 549755813888 then
    prot_at(v3, "op 3 landing")
    unmap(v3, 0x4000, "op 3 control")
end
print("")

print("[G] 477 on the same descriptor, as the reference")
local fd_ref = N(sc5(str_addr("/dev/dmem0"), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
if fd_ref >= 0 then
    local va = N(sc477(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd_ref), uint64(0)))
    print(string.format("    477(dmem0, pos 0, 0x4000) = %s", (va > 0x1000) and string.format("0x%X", va) or tostring(va)))
    if va > 0x1000 and va <= 549755813888 then unmap(va, 0x4000, "477 ref") end
    local va2 = N(sc477(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd_ref), uint64(0x120000000)))
    print(string.format("    477(dmem0, pos 0x120000000) = %s   (1478a: EACCES)", (va2 > 0x1000) and string.format("0x%X", va2) or tostring(va2)))
    if va2 > 0x1000 and va2 <= 549755813888 then unmap(va2, 0x4000, "477 ref high") end
    pcall(function() sc6(uint64(fd_ref), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("")

print("[H] leave the address space as we found it")
prot_at(TARGET, "final")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1534b COMPLETE ===")
