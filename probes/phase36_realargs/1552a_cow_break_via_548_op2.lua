-- CRASH_CLASS: LOW
-- PROBE 1552a: does 548 op 2 grant WRITE on a MAP_PRIVATE vnode page without
--              breaking COW? (a page-cache write-through test)
--
-- prior art:
--   docs/VM_LAYER_14_10.md §8  — 548 op 2 IS a real vm_map_protect gated on
--     16 KiB alignment; 1533a measured anon 3->1, 1->2 (WRITE implies READ),
--     3->0, and prot 7 refused with EACCES (max_prot excludes X).
--   docs/VM_LAYER_14_10.md §17 — the op 0 / op 3 helper masks the OBJECT's
--     declared max-protection word with `and r9d,0x3f3` (strips EXEC and 0x8).
--     That mask is NOT applied to an op-2 request: op 2 is limited only by the
--     entry's own max_protection inside vm_map_protect, which no capture in
--     results/ has measured for a vnode entry. [E] measures it.
--   Every op-2 measurement to date used an anonymous mapping, the
--     `SceGnmTrapData` window, or a carve produced by op 3. A MAP_PRIVATE vnode
--     mapping — the one entry carrying MAP_ENTRY_NEEDS_COPY — has never been in
--     a 548 request. 1533a is the control for the anonymous case; 1535a for the
--     device window.
--   probes/phase36_realargs/1531a_mlfs_truncate_race.lua:129-147 — the writable
--     MLFS path `/av_contents/content_tmp/` and the `open(path, 0x202, 0x1FF)`
--     + ftruncate(480) idiom. 1531a's vnode mmaps all pass flags 1
--     (MAP_SHARED); a grep over probes/ finds ZERO MAP_PRIVATE vnode mmaps.
--   probes/phase17_new_vectors/1024a_fstat_full_scan_20261103_173240.txt — a
--     fresh process already holds fds 0..23, so this probe's fds land above 23.
--
-- Invariant under test: adding VM_PROT_WRITE to a private mapping of a vnode
-- object must break copy-on-write before the PTE takes the W bit. If the kernel
-- grants W on the PTE while the page is still the object's (owned by the page
-- cache), one store corrupts the cached page and every other mapping of the
-- same file sees it.
--
-- Vacuity controls, all of which must pass before [F] means anything:
--   [C]  both mappings read the file's own marker bytes.
--   [C2] a byte written THROUGH fd2 appears in V2 — proves the two mappings
--        share the page-cache page, so a later V2 change is evidence.
--   [E]  547 confirms the protection really became 3.
--   [F]  the store must read back as 0x5C in V1; a swallowed store proves
--        nothing (the write path swallows faults on this platform).
--
-- Method uses our own MLFS file only, never a system file, and never MAP_SHARED.

print("=== PROBE 1552a: 548 op2 on a MAP_PRIVATE vnode page ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function N(v)
    if type(v) == "table" then return to_num(v) end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rdb(a)
    local ok, v = pcall(function() return memory.read_byte(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wrb(a, v)
    pcall(function() memory.write_byte(uint64(a), v) end)
end
local function rdw(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function hex4(a)
    local t = {}
    for i = 0, 3 do t[#t + 1] = string.format("%02X", rdb(a + i) or 0) end
    return table.concat(t, " ")
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end

-- Every syscall handle is created BEFORE the helpers that use it: a `local`
-- declared after a function body is not in that body's scope, it is a nil
-- global read at call time.
local sc_open   = mk(5)
local sc_close  = mk(6)
local sc_write  = mk(4)
local sc_ftr    = mk(480)
local sc_mmap   = mk(477)
local sc_munmap = mk(73)
local sc_lseek  = mk(478)
local sc_547    = mk(547)
local sc_548    = mk(548)

local path = "/av_contents/content_tmp/r1552.bin"
local pathbuf = memory.alloc(0x80)
for i = 1, #path do wrb(pathbuf + (i - 1), path:byte(i)) end
wrb(pathbuf + #path, 0)

-- O_RDWR: a MAP_PRIVATE mapping of an O_RDONLY descriptor may carry
-- max_prot = READ only, in which case op 2 could never grant WRITE and the run
-- would answer EACCES for a reason unrelated to COW.
local function open_rw(tag)
    local ok, rv = pcall(function()
        return sc_open(uint64(pathbuf), uint64(2), uint64(0))
    end)
    if not ok then
        print(string.format("[B] open(%s) raised", tag))
        return -1
    end
    local v = N(rv)
    print(string.format("[B] open(%s) rv=%d %s", tag, v, v < 0 and es() or ""))
    return v
end

-- 477 signature measured as (addr_hint, len, prot, flags, fd, offset).
-- MAP_PRIVATE is 0x2; MAP_ANON is 0x1000 and is deliberately absent.
local function map_priv(fd, tag)
    print(string.format("[B] mmap(hint=0, 0x8000, prot=1, flags=0x2, fd=%d, 0) ...", fd))
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(0x8000), uint64(1),
                       uint64(0x2), uint64(fd), uint64(0))
    end)
    local a = ok and N(v) or -1
    print(string.format("[B] %s = 0x%X %s", tag, a,
        (not ok or a < 0x1000) and es() or ""))
    if not ok or a < 0x1000 or a > 549755813888 then return nil end
    return a
end

-- 547 writes {start qword @0x00, end qword @0x08, prot dword @0x10,
--             flags dword @0x14}. The protection is a DWORD: reading a qword
-- would swallow the flags word (0x610020) into the high half.
local function prot_of(a)
    local rec = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do memory.write_dword(uint64(rec + i), 0xEE) end
    local ok, rv = pcall(function()
        return sc_547(uint64(a), uint64(rec), uint64(0x40),
                      uint64(0), uint64(0), uint64(0))
    end)
    if not ok or to_num(rv) ~= 0 then return nil, nil, nil end
    return rdw(rec + 0x10), rdw(rec + 0x00), rdw(rec + 0x08)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local function set_entry(start, off, len, prot, op)
    pcall(function()
        for i = 0, 0x3C, 4 do memory.write_dword(uint64(ent + i), 0) end
        memory.write_dword(uint64(ent + 0x00), start % 4294967296)
        memory.write_dword(uint64(ent + 0x04), math.floor(start / 4294967296))
        memory.write_dword(uint64(ent + 0x08), off % 4294967296)
        memory.write_dword(uint64(ent + 0x0C), math.floor(off / 4294967296))
        memory.write_dword(uint64(ent + 0x10), len % 4294967296)
        memory.write_dword(uint64(ent + 0x14), math.floor(len / 4294967296))
        memory.write_dword(uint64(ent + 0x18), prot)
        memory.write_byte(uint64(ent + 0x1C), op)
        memory.write_dword(uint64(done), 0xEEEEEEEE)
    end)
end

local function op2(tag, start, len, prot)
    set_entry(start, 0, len, prot, 2)
    print(string.format("[%s] 548 op2 start=0x%X len=0x%X prot=%d ...",
        tag, start, len, prot))
    local ok, rv = pcall(function()
        return sc_548(uint64(0), uint64(0), uint64(ent), uint64(1),
                      uint64(done), uint64(0))
    end)
    local v = ok and to_num(rv) or -999
    print(string.format("[%s] rv=%d processed=%s %s", tag, v,
        tostring(rdw(done) or "?"), (v ~= 0) and es() or ""))
    return v
end

-- ---- [A] our own file ----
pcall(function() mk(10)(uint64(pathbuf)) end)   -- unlink any leftover
print("[A] create " .. path)
local okf, rfd = pcall(function()
    return sc_open(uint64(pathbuf), uint64(0x202), uint64(0x1FF))
end)
local filefd = okf and N(rfd) or -999
print(string.format("[A] open rv=%d %s", filefd, filefd < 0 and es() or ""))
if filefd < 0 then print("=== ABORT: no file ===") return end

local okt, rvt = pcall(function()
    return sc_ftr(uint64(filefd), uint64(0x8000))
end)
print(string.format("[A] ftruncate(0x8000) rv=%s", tostring(okt and N(rvt) or "err")))
if not okt or N(rvt) ~= 0 then print("=== ABORT: ftruncate ===") return end

-- file content: "COW0" at 0x00, 0x11 at 0x10 (so [C2] has a different byte to set)
local marker = memory.alloc(0x20)
wrb(marker + 0x00, 0x43) wrb(marker + 0x01, 0x4F)
wrb(marker + 0x02, 0x57) wrb(marker + 0x03, 0x30)
wrb(marker + 0x10, 0x11)
local okw, rvw = pcall(function()
    return sc_write(uint64(filefd), uint64(marker), uint64(0x20))
end)
print(string.format("[A] write(0x20) rv=%s", tostring(okw and N(rvw) or "err")))
if not okw or N(rvw) ~= 0x20 then print("=== ABORT: marker write ===") return end
pcall(function() sc_lseek(uint64(filefd), uint64(0), uint64(0)) end)
pcall(function() sc_close(uint64(filefd)) end)

-- ---- [B] two independent MAP_PRIVATE read mappings ----
local fd2 = open_rw("fd2")
local fd3 = open_rw("fd3")
if fd2 < 0 or fd3 < 0 then print("=== ABORT: reopen ===") return end

local V1 = map_priv(fd2, "V1")
local V2 = map_priv(fd3, "V2")
if not V1 or not V2 or V1 == V2 then
    print("=== ABORT: mappings ===")
    return
end
print(string.format("[B] V1=0x%X V2=0x%X", V1, V2))

-- ---- [C] both mappings show the file ----
print(string.format("[C] V1[0..3] = %s", hex4(V1)))
print(string.format("[C] V2[0..3] = %s", hex4(V2)))
local m1, m2 = rdb(V1), rdb(V2)
if m1 ~= 0x43 or m2 ~= 0x43 then
    print(string.format("[C] marker missing (V1=%s V2=%s) — mappings are not file-backed",
        tostring(m1), tostring(m2)))
    print("=== VOID: not file-backed ===")
    return
end
print("[C] both mappings read the file marker: true")

-- ---- [C2] positive control: the two mappings share the page-cache page ----
print(string.format("[C2] write 0xA7 at file offset 0x10 through fd2 ..."))
pcall(function() sc_lseek(uint64(fd2), uint64(0x10), uint64(0)) end)
local one = memory.alloc(0x10)
wrb(one, 0xA7)
local okc, rvc = pcall(function()
    return sc_write(uint64(fd2), uint64(one), uint64(1))
end)
print(string.format("[C2] write rv=%s", tostring(okc and N(rvc) or "err")))
local c2 = rdb(V2 + 0x10)
print(string.format("[C2] V2[0x10] = %s (want 0xA7)", tostring(c2)))
if c2 ~= 0xA7 then
    print("[C2] the second mapping does not see a page-cache change — either the")
    print("[C2] pager copies at private-fault time or the write missed. A clean V2")
    print("[C2] after [F] would then prove nothing.")
    print("=== VOID: mappings do not share the page ===")
    return
end
print("[C2] shared page-cache page confirmed")

-- ---- [D] alignment and the protection baseline ----
if V1 % 0x4000 ~= 0 then
    print(string.format("[D] V1=0x%X is not 16 KiB aligned; op 2 would answer EINVAL", V1))
    print("=== VOID: not aligned ===")
    return
end
local p0, s0, e0 = prot_of(V1)
print(string.format("[D] V1 before: prot=%s start=0x%X end=0x%X",
    tostring(p0), s0 or 0, e0 or 0))
if p0 == nil then
    print("=== VOID: 547 could not read V1 ===")
    return
end

-- ---- [E] 548 op 2 -> WRITE ----
if p0 ~= 1 then
    print(string.format("[E] unexpected starting protection %d; forcing 1 first", p0))
    op2("E0", V1, 0x4000, 1)
    p0 = prot_of(V1)
    print(string.format("[E] V1 now prot=%s", tostring(p0)))
end
op2("E", V1, 0x4000, 3)
local p1 = prot_of(V1)
print(string.format("[E] V1 after : prot=%s%s", tostring(p1),
    (p1 == 3) and "  <<< WRITE GRANTED" or ""))
if p1 ~= 3 then
    print("[E] op 2 did not grant WRITE on this vnode entry, so its max_prot")
    print("[E] excludes W. The COW question is not reachable through op 2.")
    print("=== DONE (no W) ===")
    return
end

-- ---- [F] one store, then look through the OTHER mapping ----
print(string.format("[F] store 0x5C at V1+0x10 (0x%X) ...", V1 + 0x10))
wrb(V1 + 0x10, 0x5C)
local a1 = rdb(V1 + 0x10)
local a2 = rdb(V2 + 0x10)
if a1 == nil then
    print("[F] V1 read faulted")
    print("=== VOID: read fault ===")
    return
end
print(string.format("[F] V1[0x10] after = 0x%02X %s", a1,
    (a1 == 0x5C) and "(store landed)" or "(store did NOT land)"))
if a1 ~= 0x5C then
    print("[F] the store was swallowed; a page whose PTE lacks W reports success")
    print("[F] on this platform, so this run contains no COW evidence.")
    print("=== VOID: store did not land ===")
    return
end
if a2 == nil then
    print("[F] V2 read faulted")
    print("=== VOID: read fault ===")
    return
end
print(string.format("[F] V2[0x10] after = 0x%02X", a2))
if a2 == 0x5C then
    print("[F] *** SHARED: COW WAS NOT BROKEN — the store reached the page cache ***")
    print("[F] *** and every mapping of this file now reads 0x5C ***")
elseif a2 == 0xA7 then
    print("[F] private copy: COW held (V2 still reads the page-cache byte)")
else
    print(string.format("[F] unexpected byte 0x%02X — record, do not conclude", a2))
end

-- ---- [G] a fresh mapping, faulted after the store, reading the page cache ----
local fd4 = open_rw("fd4")
if fd4 >= 0 then
    local V3 = map_priv(fd4, "V3")
    if V3 then
        local c = rdb(V3 + 0x10)
        print(string.format("[G] V3[0x10] = %s (0x5C would mean the cache is corrupt)",
            tostring(c)))
        pcall(function() sc_munmap(uint64(V3), uint64(0x8000)) end)
    end
    pcall(function() sc_close(uint64(fd4)) end)
end

-- ---- [H] teardown ----
pcall(function() sc_munmap(uint64(V1), uint64(0x8000)) end)
pcall(function() sc_munmap(uint64(V2), uint64(0x8000)) end)
pcall(function() sc_close(uint64(fd2)) end)
pcall(function() sc_close(uint64(fd3)) end)
pcall(function() mk(10)(uint64(pathbuf)) end)
print("[H] teardown done")
print("=== PROBE 1552a COMPLETE ===")
