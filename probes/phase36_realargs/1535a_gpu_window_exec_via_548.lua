-- CRASH_CLASS: HIGH
-- PROBE 1535a: is a device window executable once 548 op 2 grants it PROT_EXEC?
--
-- Context: every W^X claim in this project rests on one sentence - "no
-- protection this process can request is executable" (424a-424c). That was
-- measured on anonymous mappings, where mprotect(2) refuses PROT_EXEC outright
-- and where 477 with prot 7 produces a writable page whose first instruction
-- fetch still faults.
--
-- 548 op 2 is a different entry point into the same VM primitive, and its only
-- protection check is `and ecx, 8; jne EINVAL` at 0xffffffff8b47c0dc - bit 0x8,
-- not PROT_EXEC (0x4). 1481g measured it accepting 0x0, 0x1, 0x3, 0x10, 0x20
-- and 0x33 on SceGnmTrapData at 0xF00004000, reading each back through 547,
-- with every value carrying bit 0x8 refused. 1533a repeated the 0x33 rung.
--
-- CORRECTION: 0x33 does NOT carry the exec bit. FreeBSD VM_PROT is READ=0x1,
-- WRITE=0x2, EXECUTE=0x4, so 0x33 is 0b00110011 - READ|WRITE plus the Sony
-- attribute bits 0x10 and 0x20, with bit 0x4 clear. Every protection 1481g and
-- 1533a accepted had bit 0x4 clear, so an earlier draft of this probe could not
-- have executed anything. The values that actually ask for executable are 0x5
-- (R|X), 0x7 (R|W|X) and 0x37 / 0x27 / 0x17 (the same with the attribute bits).
--
-- The question is therefore narrow: does this window's vm_map_entry max_prot
-- include EXECUTE? If it does, op 2 will accept 0x7 or 0x37 where anonymous
-- memory refuses, and the window becomes the one executable mapping a game
-- process can own. If it does not, the answer is EACCES(13) exactly as 1533a
-- measured for anon 3 -> 7, and the W^X wall holds at the entry's max_prot.
--
-- RISK, and it is real: a child that fetches from a mapping without X does not
-- simply die. 424b recorded the loader entering its fault-dump loop (257 dumps,
-- then the process died) and 1459a's capture ends right after its plain fetch
-- fault with no COMPLETE line, because the handler resumes the child at the
-- faulting instruction. If that happens here, the capture fills with binary
-- ucontext dumps until the process dies, [F]'s diagnosis is lost, and [G]'s
-- protection restore never runs. The window would be left executable. A
-- relaunch is the expected cost of a negative result.
--
-- Method:
--   [A] marker page holding a sentinel
--   [B] find SceGnmTrapData through 674 by name - abort if it is not named, and
--       require a 16 KiB-aligned start whose record covers 0x4000
--   [C] save 8 original bytes at window+0x100, plant `48 89 07 EB FE`
--       (mov [rdi],rax; jmp $) and read it back; abort unless all 5 landed
--   [D] 548 op 2 -> 0x37, then 0x7, then 0x5, reading 547 after each; stop at
--       the first value that is accepted AND reads back with bit 0x4 set
--   [E] thr_new(455) with start_func = window+0x100, arg = the marker, and a
--       stack whose top is inside the allocation
--   [F] poll the marker for one second, expecting exactly 0x1C7 (rax = 455 at
--       thread entry, measured in 56l)
--   [G] restore the window's original protection and its original 8 bytes
--
-- The gadget ends in `jmp $`, not `ret`: thr_new puts RSP at the top of the
-- stack argument, so a `ret` would pop heap metadata and jump there. The child
-- spins instead, which is harmless in a process that ends with the probe.
--
-- -- prior art:
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202017.txt
--       prot 0x0/0x1/0x3/0x10/0x20/0x33 accepted on SceGnmTrapData, bit 0x8
--       refused, 547 readback matches; no accepted value carried bit 0x4
--   results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt
--       op 2 needs start and length 16 KiB aligned; anon 3 -> 7 gives EACCES(13)
--   results/phase36_realargs/1481b_gpu_windows_write_20261109_201732.txt
--       six named GPU windows accept stores and read back; all restored
--   results/phase13_53batch/56l_thr_new_real_20261023_105601.txt
--       thr_new delivers arg in rdi; `mov [rdi],rax;ret` wrote rax=455
--   probes/phase17_new_vectors/424b_mmap_rwx.lua
--       a child fetching from a non-executable mapping produces a fault-dump
--       loop, not one clean death
--   probes/phase36_realargs/1468a_dual_map_wx.lua, 1459a capture
--       the same class, declared HIGH for the same reason
--   docs/DEVICE_WINDOW_14_10.md; docs/VM_LAYER_14_10.md sections 8, 9 and 10

print("=== PROBE 1535a: EXECUTABLE DEVICE WINDOW VIA 548 OP 2 ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))
print("")

local sc548, sc547, sc674, sc455, sc240 = mk(548), mk(547), mk(674), mk(455), mk(240)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x40)
local cnt = memory.alloc(0x10)
local dbuf = memory.alloc(0x9000)
local mark = memory.alloc(0x40)
local tparam = memory.alloc(0x40)
local tstack = memory.alloc(0x10000)
local child_tid = memory.alloc(0x10)
local ts = memory.alloc(0x10)

local function zero(p, n) for i = 0, n - 1 do pcall(function() memory.write_byte(p + i, 0) end) end end
zero(ent, 0x40); zero(rec, 0x40); zero(cnt, 0x10); zero(dbuf, 0x9000)
zero(mark, 0x40); zero(tparam, 0x40); zero(tstack, 0x10000); zero(child_tid, 0x10); zero(ts, 0x10)

local function rd(addr) local ok, v = pcall(function() return N(memory.read_dword(addr)) end) if ok then return v % 4294967296 end return nil end
local function wr(addr, val) pcall(function() memory.write_dword(addr, uint64(val)) end) end

-- 547's record: start_lo, start_hi, end_lo, end_hi, prot, flags. prot is only
-- accepted when the call succeeded and the record's range covers the address.
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
    print(string.format("    %-38s 547 rv=%-3s prot=%-4s range=%X..%X", tag,
        ok and tostring(v) or "EXC", p and string.format("0x%X", p) or "nil", rs, re))
    return p
end

-- ------------------------------------------------- [A] the marker
print("[A] marker page")
local MARKER = N(mark)
wr(MARKER, 0xDEADBEEF)
print(string.format("    marker at 0x%X holds %08X", MARKER, rd(MARKER) or 0))
print("")

-- ------------------------------------------------- [B] locate the window
print("[B] locate SceGnmTrapData through 674")
zero(cnt, 0x10)
local okc, c = pcall(function()
    return N(sc674(uint64(dbuf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("    674 rv=%d records=%d", okc and c or -999, nrec))
if nrec > 400 then nrec = 400 end
local WIN, WEND = nil, nil
for i = 0, nrec - 1 do
    local b = dbuf + i * 72
    local name = ""
    for j = 0, 31 do
        local okb, ch = pcall(function() return N(memory.read_byte(b + 0x21 + j)) end)
        if not okb or ch == 0 then break end
        name = name .. string.char(ch % 256)
    end
    if name:find("TrapData") then
        local lo, hi, elo, ehi = 0, 0, 0, 0
        pcall(function() lo  = N(memory.read_dword(b + 0x00)) % 4294967296 end)
        pcall(function() hi  = N(memory.read_dword(b + 0x04)) % 4294967296 end)
        pcall(function() elo = N(memory.read_dword(b + 0x08)) % 4294967296 end)
        pcall(function() ehi = N(memory.read_dword(b + 0x0C)) % 4294967296 end)
        WIN, WEND = lo + hi * 4294967296, elo + ehi * 4294967296
        print(string.format("    found '%s' at 0x%X..0x%X", name, WIN, WEND))
        break
    end
end
if not WIN then
    print("    ABORT: 674 did not name SceGnmTrapData; no rung below is interpretable")
    print("=== PROBE 1535a ABORTED ===")
    return
end
if WIN % 0x4000 ~= 0 then
    print(string.format("    ABORT: the window starts at 0x%X, not on a 16 KiB boundary", WIN))
    print("=== PROBE 1535a ABORTED ===")
    return
end
if WEND < WIN + 0x4000 then
    print(string.format("    ABORT: the record ends at 0x%X, less than one 16 KiB page", WEND))
    print("=== PROBE 1535a ABORTED ===")
    return
end
local before = prot_at(WIN, "window protection before")
if not before then
    print("    ABORT: 547 cannot describe the window, so no rung is interpretable")
    print("=== PROBE 1535a ABORTED ===")
    return
end
print("")

-- ------------------------------------------------- [C] plant the gadget first
print("[C] save the original bytes, then plant `mov [rdi],rax; jmp $` at window+0x100")
local SLOT = WIN + 0x100
local orig = {}
local saved = ""
for i = 0, 7 do
    local okb, ch = pcall(function() return N(memory.read_byte(SLOT + i)) end)
    orig[i] = (okb and (ch % 256)) or 0
    saved = saved .. string.format("%02X ", orig[i])
end
print(string.format("    original 8 bytes at 0x%X: %s", SLOT, saved))
local bytes = {0x48, 0x89, 0x07, 0xEB, 0xFE}
local wrote = true
for i = 1, 5 do
    local ok = pcall(function() memory.write_byte(SLOT + i - 1, uint64(bytes[i])) end)
    if not ok then wrote = false print(string.format("     write byte %d FAILED", i - 1)) end
end
local echo = ""
for i = 0, 7 do
    local okb, ch = pcall(function() return N(memory.read_byte(SLOT + i)) end)
    if okb then echo = echo .. string.format("%02X ", ch % 256) else echo = echo .. "?? " end
end
print(string.format("    at 0x%X: %s  (expect 48 89 07 EB FE)", SLOT, echo))
if echo:sub(1, 14) ~= "48 89 07 EB FE" then
    print("    ABORT: the gadget did not land; the child would execute device data")
    for i = 0, 7 do pcall(function() memory.write_byte(SLOT + i, uint64(orig[i])) end) end
    print("    (original bytes written back; no protection was changed)")
    print("=== PROBE 1535a ABORTED ===")
    return
end
print("")

-- ------------------------------------------------- [D] ask for executable
print("[D] 548 op 2 with an exec bit - 0x37 keeps the device attributes, then 0x7, then 0x5")
local function op2(start, len, prot, tag)
    zero(ent, 0x40)
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(0)) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, uint64(2)) end)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %s (prot=0x%X len=0x%X)", tag, prot, len))
    local ok, v = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0)))
    end)
    local pc = "?"
    local ok2, v2 = pcall(function() return N(memory.read_dword(cnt)) end)
    if ok2 then pc = tostring(v2 % 4294967296) end
    print(string.format("     rv=%-5s %-18s processed=%s", ok and tostring(v) or "EXC",
        (ok and v < 0) and es() or "", pc))
    return ok and v or -999
end

local EXEC_PROT = nil
for _, p in ipairs({0x37, 0x7, 0x5}) do
    local r = op2(WIN, 0x4000, p, string.format("window -> 0x%X", p))
    local now = prot_at(WIN, string.format("window after 0x%X", p))
    if r == 0 and now and (now % 8) >= 4 then
        EXEC_PROT = now
        print(string.format("    ACCEPTED with bit 0x4 set: 547 reads back 0x%X", now))
        break
    end
    if r == 0 and now and (now % 8) < 4 then
        print(string.format("    accepted but 547 reads 0x%X - bit 0x4 did not survive the map", now))
    end
end
if not EXEC_PROT then
    print("    no protection carrying bit 0x4 was accepted; the entry's max_prot excludes X")
    print("    (the same EACCES that 1533a measured for anon 3 -> 7; the W^X wall holds here too)")
end
print("")

-- ------------------------------------------------- [E] run a child there
if EXEC_PROT then
    print("[E] thr_new(455) with start_func = the window")
    pcall(function() memory.write_qword(tparam + 0x00, uint64(string.format("0x%X", SLOT))) end)
    pcall(function() memory.write_qword(tparam + 0x08, uint64(string.format("0x%X", MARKER))) end)
    pcall(function() memory.write_qword(tparam + 0x10, uint64(string.format("0x%X", N(tstack)))) end)
    pcall(function() memory.write_qword(tparam + 0x18, uint64(0xF000)) end)
    pcall(function() memory.write_qword(tparam + 0x30, uint64(string.format("0x%X", N(child_tid)))) end)
    local okn, rvn = pcall(function()
        return N(sc455(uint64(tparam), uint64(0x38), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    print(string.format("    thr_new rv=%s %s  child_tid=%s", okn and tostring(rvn) or "EXC",
        (okn and rvn < 0) and es() or "", tostring(rd(child_tid))))

    print("[F] poll the marker, expecting exactly 0x1C7 (rax = 455 at thread entry)")
    local hit = false
    for i = 1, 20 do
        local v = rd(MARKER)
        if v == 0x1C7 then
            print(string.format("    poll %d: marker=%08X  <<< rax=455 landed, THE CHILD EXECUTED AT THE WINDOW", i, v))
            hit = true
            break
        elseif v and v ~= 0xDEADBEEF then
            print(string.format("    poll %d: marker=%08X - changed, but not 0x1C7, so not this gadget", i, v))
        end
        pcall(function() return N(sc240(uint64(ts), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    end
    if not hit then
        print(string.format("    marker still %08X after 20 polls: no execution observed", rd(MARKER) or 0))
        if okn and rvn == 0 and (rd(child_tid) or 0) ~= 0 then
            print("    a tid exists, so a child ran - the fetch was contained this time")
        else
            print("    thr_new refused and no tid appeared: nothing executed, this rung is VOID")
        end
    end
else
    print("[E] skipped: no executable protection was granted, so a jump would prove nothing")
    print("[F] skipped")
end
print("")

-- ------------------------------------------------- [G] restore
print("[G] restore the window: protection first, then the bytes")
op2(WIN, 0x4000, before, string.format("window -> 0x%X (original)", before))
prot_at(WIN, "window protection restored")
for i = 0, 7 do pcall(function() memory.write_byte(SLOT + i, uint64(orig[i])) end) end
local back = ""
for i = 0, 7 do
    local okb, ch = pcall(function() return N(memory.read_byte(SLOT + i)) end)
    if okb then back = back .. string.format("%02X ", ch % 256) else back = back .. "?? " end
end
print(string.format("    bytes at 0x%X now: %s  (originally %s)", SLOT, back, saved))
print("")

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1535a COMPLETE ===")
