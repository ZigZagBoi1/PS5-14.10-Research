-- CRASH_CLASS: LOW -- one POSIX shm object, two mappings of it, and one carve. Every address is
--   inside memory this process created.
-- PROBE 1514a: does 548 op 3's clip corrupt a vm_object SHARED by two entries?
--
-- Why: 1513a showed the clip leaves a vnode mapping's page-cache object intact (a second mapping of
-- the same file read correctly afterwards). A vnode object is only softly shared, though -- each
-- mapping can fault its own pages. A MAP_SHARED POSIX shm object is HARD shared: the two entries
-- point at one vm_object and one set of physical pages, so a write through either mapping is
-- visible through the other. That makes divergence a direct proof of object-level damage.
--
-- op 3 = vm_map_delete(range) then vm_map_insert(anon). Delete on a range in the middle of an entry
-- runs vm_map_clip_start + vm_map_clip_end (1512a measured the split), and each clip clones the
-- entry with adjusted offset/size while vm_map_delete drops one vm_object reference. If the drop is
-- not paired with the clone's take, the surviving fragment's object is freed under it -- a
-- vm_object use-after-free driven by a syscall on a page we own.
--
-- Witness: write through A, read through B (and back). They must agree, before and after the carve.
--
-- [A] shm_open(SHM_ANON) + ftruncate 0x40000, map A and B MAP_SHARED prot 3
--     confirm A and B really are one object: write through A, read through B, and back
-- [B] 548(0, 0x10, {A+0x10000, 0, 0x4000, 3, op=3}, 1, &proc, 0)
-- [C] the witness again below / at / above the carve, in both directions; 547 all four segments
-- [D] unmap A entirely, then prove B is still a working shared mapping
-- [E] re-open the object's surviving fragments, read the whole 0x40000, and count pages that are
--     neither the written pattern nor zeros
--
-- -- prior art:
--   results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt (op 3 SPLITS an entry;
--     three entries afterwards, markers outside the carve survive)
--   results/phase36_realargs/1513a_sys548_op3_vnode_clip_20261109_230353.txt (the clip leaves a
--     vnode page-cache object readable through a second mapping)
--   results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt (MAP_FIXED bit 0x10)
--   results/phase34_shm_race/932b_*.txt (shm lifecycle correct across unlink/close)
--   results/phase34_shm_race/933a_*.txt (eight stale mappings unchanged after unlink+close --
--     refcounting held for the unlink path, but the CLIP path was never exercised)
--   probes/phase19_posixshm/391a_shm_open_retest.lua (the shm_open/ftruncate/mmap shape used here)

print("=== PROBE 1514a: 548 op 3 CLIP OF A SHARED SHM OBJECT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function rdq(a)
    local lo, hi = rd(a), rd(a + 4)
    if lo == nil or hi == nil then return nil end
    return lo + hi * 4294967296
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent  = memory.alloc(0x40)
local done = memory.alloc(0x10)

local function batch(flags, start, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent, uint64(start)) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return mk(548)(uint64(0), uint64(flags), uint64(ent), uint64(1), uint64(done), uint64(0))
    end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(done))
end

local rec = memory.alloc(0x30)
local function q547(addr)
    for i = 0, 0x2C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return nil end
    if sgn(rv) ~= 0 then return nil end
    local s, e = rdq(rec), rdq(rec + 8)
    if s == nil or e == nil then return nil end
    return s, e, rd(rec + 0x10), rd(rec + 0x14)
end

local function show547(tag, a)
    local s, e, p, f = q547(a)
    if s == nil then
        print(string.format("   %-12s 547(0x%X): no entry", tag, a))
    else
        print(string.format("   %-12s 547(0x%X): start=0x%X end=0x%X len=0x%X prot=0x%X",
            tag, a, s, e, e - s, p or 0))
    end
end

--============================================================== [A] shared object
print("")
print("[A] shm_open(SHM_ANON) and map it twice MAP_SHARED")
local okf, fd = pcall(function() return mk(482)(uint64(1), uint64(0x202), uint64(0x180), uint64(0), uint64(0), uint64(0)) end)
fd = okf and sgn(fd) or -1
print(string.format("   shm_open = %d %s", fd, fd < 0 and es() or ""))
if fd < 0 then print("   VERDICT: VOID -- no shm object") return end

local LEN = 0x40000
local okf2, ft = pcall(function() return mk(480)(uint64(fd), uint64(LEN), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("   ftruncate = %d %s", okf2 and sgn(ft) or -999, (okf2 and sgn(ft) ~= 0) and es() or ""))

local okA, Av = pcall(function() return mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(1), uint64(fd), uint64(0)) end)
local A = okA and sgn(Av) or -1
print(string.format("   map A = %s %s", A > 0x10000 and string.format("0x%X", A) or "FAILED", A <= 0x10000 and es() or ""))
if A <= 0x10000 then print("   VERDICT: VOID -- first mapping failed") return end

local okB, Bv = pcall(function() return mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(1), uint64(fd), uint64(0)) end)
local B = okB and sgn(Bv) or -1
print(string.format("   map B = %s %s", B > 0x10000 and string.format("0x%X", B) or "FAILED", B <= 0x10000 and es() or ""))
if B <= 0x10000 then print("   VERDICT: VOID -- second mapping failed") return end

-- proof the two mappings are one object
wr(A + 0x8000, 0xA1B2C3D4)
wr(B + 0x24000, 0xE5F6A7B8)
local shared_fwd = (rd(B + 0x8000) == 0xA1B2C3D4)
local shared_bwd = (rd(A + 0x24000) == 0xE5F6A7B8)
print(string.format("   write A+0x8000 read B+0x8000: %s", shared_fwd and "MATCH" or "differ"))
print(string.format("   write B+0x24000 read A+0x24000: %s", shared_bwd and "MATCH" or "differ"))
if not (shared_fwd and shared_bwd) then
    print("   VERDICT: VOID -- the two mappings do not share an object, so divergence proves nothing")
    return
end
show547("A", A)
show547("B", B)

--============================================================== [B] carve
print("")
print("[B] 548 op3 MAP_FIXED carve of A+0x10000")
local rv, proc = batch(0x10, A + 0x10000, 0x4000, 3, 3)
print(string.format("   rv=%d processed=%d %s", rv, proc, rv == -1 and es() or ""))
if proc ~= 1 then
    print("   VERDICT: op 3 refused -- nothing was clipped")
    return
end
print(string.format("   requested 0x%X, landed 0x%X", A + 0x10000, rv))

--============================================================== [C] witness after the carve
print("")
print("[C] is the shared object still shared?")
local checks = {
    { 0x0000, 0xA1B2C3D4 },
    { 0x8000, 0xA1B2C3D4 },
    { 0x24000, 0xE5F6A7B8 },
}
local lost = 0
for _, c in ipairs(checks) do
    local av, bv = rd(A + c[1]), rd(B + c[1])
    local okab = (av == c[2]) and (bv == c[2])
    if not okab then lost = lost + 1 end
    print(string.format("   +0x%05X expected %08X | A=%s B=%s %s", c[1], c[2],
        av and string.format("%08X", av) or "FAULT",
        bv and string.format("%08X", bv) or "FAULT",
        okab and "" or "<-- LOST"))
end
-- fresh write after the carve: does propagation still work both ways?
wr(A + 0x20000, 0x11223344)
local fwd2 = (rd(B + 0x20000) == 0x11223344)
wr(B + 0x28000, 0x55667788)
local bwd2 = (rd(A + 0x28000) == 0x55667788)
print(string.format("   after carve, A->B propagation: %s", fwd2 and "WORKS" or "BROKEN"))
print(string.format("   after carve, B->A propagation: %s", bwd2 and "WORKS" or "BROKEN"))
show547("A below", A)
show547("A at   ", A + 0x10000)
show547("A above", A + 0x30000)
show547("B      ", B)

-- a full sweep of B: how many dwords are neither a pattern we wrote nor zero
local odd, oddoff = 0, -1
for off = 0, LEN - 4, 4 do
    local v = rd(B + off)
    if v == nil then
        if odd == 0 then oddoff = off end
        odd = odd + 1
    elseif v ~= 0 and v ~= 0xA1B2C3D4 and v ~= 0xE5F6A7B8 and v ~= 0x11223344 and v ~= 0x55667788 then
        odd = odd + 1
        if oddoff < 0 then oddoff = off end
    end
end
print(string.format("   B sweep: %d dwords not ours and not zero (first at +0x%X)", odd, oddoff))

--============================================================== [D] drop one mapping
print("")
print("[D] unmap A; B must still be a working shared mapping")
local mm = sgn(mk(73)(uint64(A), uint64(LEN), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("   munmap A = %d", mm))
local b1, b2 = rd(B + 0x8000), rd(B + 0x24000)
print(string.format("   B+0x8000 = %s  B+0x24000 = %s",
    b1 and string.format("%08X", b1) or "FAULT", b2 and string.format("%08X", b2) or "FAULT"))
wr(B + 0x3C000, 0xCAFED00D)
print(string.format("   B write +0x3C000 then read back: %s",
    rd(B + 0x3C000) == 0xCAFED00D and "OK" or "FAILED"))
show547("B after", B)

--============================================================== [E] carve B too
print("")
print("[E] carve B's middle while A is gone, then read the whole surface")
local rv3, proc3 = batch(0x10, B + 0x20000, 0x4000, 3, 3)
print(string.format("   rv=%d processed=%d %s", rv3, proc3, rv3 == -1 and es() or ""))
local ok3, tail = true, 0
for off = 0, LEN - 4, 4 do
    if rd(B + off) == nil then tail = tail + 1 end
end
print(string.format("   unreadable dwords in B after both carves: %d", tail))
show547("B below", B)
show547("B at   ", B + 0x20000)
show547("B above", B + 0x30000)

print("")
local final_pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[Z] alive pid=%d (was %d)", final_pid, PID))
print(string.format("[Z] shared-object witness: %d of %d checks lost after the first carve; A->B %s; B->A %s",
    lost, #checks, fwd2 and "works" or "BROKEN", bwd2 and "works" or "BROKEN"))
print("=== PROBE 1514a COMPLETE ===")
