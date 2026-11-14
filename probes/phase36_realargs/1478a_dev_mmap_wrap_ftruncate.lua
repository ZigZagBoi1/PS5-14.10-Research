-- CRASH_CLASS: LOW -- every call here is an mmap/ftruncate/547 argument test; no page is read
-- except the two device offsets already proven populated (0 and 0x1000) and the 0x1000000000 rung.
-- PROBE 1478a: device mmap offset+length arithmetic, and ftruncate widening the device size.
--
-- Why this shape. 1450a measured that munmap(73) on 14.10 removes the WHOLE vm_map_entry that
-- contains the address instead of splitting it, so this kernel's VM layer is NOT stock FreeBSD 11
-- code: it has been rewritten. That rewrites the prior that every remaining bounds check in the
-- device path is the textbook one. 1395a tried huge offsets and huge lengths but always as one
-- large value with the other small; the untested shape is the ARITHMETIC one -- an offset near
-- 2^64 with a length that makes `offset + length` wrap, which passes any `if (off + len > size)`
-- test done in 64-bit without an overflow guard, and which is exactly how a pager computes a
-- physical address.
--
-- Second arm: the refusal above the aperture is EACCES(13), which is a permission answer and not
-- an EINVAL size answer, so the limit is an ACL or a vnode size, not a hard-coded constant. A cdev
-- whose size lives in the vnode can have that size changed by ftruncate(480) on the descriptor.
-- 932a recorded ftruncate returning 0 on a descriptor number that was really an error value, so
-- ftruncate on a device descriptor has never been measured cleanly. If ftruncate(dmem0_fd, X)
-- returns 0 and the EACCES boundary moves, the aperture is caller-controlled.
--
-- Nothing here writes to a mapped page except the marker in [A], and every mapping is released
-- before the next one so the address space does not fill.
--
-- -- prior art:
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (munmap is entry-scoped)
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt (huge offsets/lengths)
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (4 GiB maps, 0x200000000 EACCES)
--   results/phase36_realargs/1410a (two ACL windows, lone rung at 0x1000000000), 1411a, 1412a
--   results/phase36_realargs/1463a_dev_mmap_census_20261109_175504.txt (which nodes map at all)
--   results/phase36_realargs/1475a_dev_pager_exec_20261109_181728.txt (prot 4..7 EACCES)
--   docs/DMEM_WINDOW_14_10.md, docs/VM_LAYER_14_10.md

print("=== PROBE 1478a: DEVICE MMAP WRAP + FTRUNCATE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIGSYS ignored so an absent slot cannot destroy the run; harmless for present ones.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local O_RDWR     = 2
local PROT_RW    = 3
local MAP_SHARED = 1

local sc_open   = mk(5)
local sc_close  = mk(6)
local sc_mmap   = mk(477)
local sc_munmap = mk(73)
local sc_trunc  = mk(480)
local sc_547    = mk(547)
local sc_659    = mk(659)

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return N(b)
end

local function open_node(path)
    local p = str_addr(path)
    if p == 0 then return -1 end
    local ok, v = pcall(function() return N(sc_open(uint64(p), uint64(O_RDWR), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if ok then return v end
    return -1
end

-- one mmap attempt, no page is touched
local function try_map(fd, off_hi, off_lo, len_hi, len_lo, prot)
    local off = uint64(string.format("0x%08X%08X", off_hi, off_lo))
    local len = uint64(string.format("0x%08X%08X", len_hi, len_lo))
    local ok, v = pcall(function()
        return N(sc_mmap(uint64(0), len, uint64(prot), uint64(MAP_SHARED), uint64(fd), off))
    end)
    if not ok then return -2 end
    return v
end

local function release(addr)
    if addr and addr > 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
        pcall(function() return sc_munmap(uint64(addr), uint64(0x1000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end

-- a 547 query tells us what the kernel thinks the mapping is, without dereferencing it
local rec = memory.alloc(0x40)
local function prot_of(addr)
    pcall(function() for i = 0, 0x38, 4 do memory.write_dword(rec + i, uint64(0)) end end)
    pcall(function() memory.write_dword(rec, 0x40) end)
    local ok, v = pcall(function() return N(sc_547(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if not ok or v ~= 0 then return -1, 0, 0 end
    -- 547 copies a 0x18-byte record: {start_low32, prot, end_low32, prot}, so the protection
    -- is at +0x04 and +0x0C, NOT at +0x18 (that dword is past the copyout).
    local en = N(memory.read_dword(rec + 0x08))
    local pr = N(memory.read_dword(rec + 0x10))
    return v, pr, en
end

local fd_d0 = open_node("/dev/dmem0")
local fd_d1 = open_node("/dev/dmem1")
local fd_gc = open_node("/dev/gc")
local fd_z  = open_node("/dev/zero")
print(string.format("[0] fds dmem0=%d dmem1=%d gc=%d zero=%d", fd_d0, fd_d1, fd_gc, fd_z))
if fd_d0 <= 0 then print("[!] no dmem0 descriptor; nothing to test"); return end

-- ---------------------------------------------------------------- [A] baseline
print("")
print("--- [A] baseline: offset 0x1000 must map ---")
do
    local a = try_map(fd_d0, 0, 0x1000, 0, 0x1000, PROT_RW)
    print(string.format("[A] dmem0 off=0x1000 len=0x1000 -> rv=%d %s", a, a < 0 and es() or ""))
    if a > 0 then
        local _, pr, en = prot_of(a)
        print(string.format("[A] 547: prot=%d end=0x%X", pr, en))
        local ok, v = pcall(function() return N(memory.read_dword(a)) end)
        print(string.format("[A] first dword readable=%s value=0x%s", tostring(ok), hex(ok and v or 0)))
        release(a)
    end
end

-- ---------------------------------------------------------------- [B] wrap shapes
print("")
print("--- [B] offset + length wrap, dmem0 ---")
local WRAPS = {
    {0xFFFFFFFF, 0xFFFFF000, 0x00000000, 0x00002000, "off=2^64-0x1000 len=0x2000"},
    {0xFFFFFFFF, 0xFFFFF000, 0x00000000, 0x00001000, "off=2^64-0x1000 len=0x1000"},
    {0xFFFFFFFF, 0xFFFFE000, 0x00000000, 0x00002000, "off=2^64-0x2000 len=0x2000"},
    {0xFFFFFFFF, 0xFFFFF000, 0xFFFFFFFF, 0xFFFFF000, "both huge"},
    {0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, "off=2^63 len=2^33"},
    {0x00000000, 0x00000000, 0x00000002, 0x00000000, "off=0 len=2^33"},
    {0x00000010, 0x00000000, 0x00000000, 0x00001000, "off=0x1000000000 (lone rung) len=0x1000"},
    {0xFFFFFFFF, 0xFFFFF000, 0x00000000, 0x00001001, "off=2^64-0x1000 len=0x1001"},
}
for _, w in ipairs(WRAPS) do
    local a = try_map(fd_d0, w[1], w[2], w[3], w[4], PROT_RW)
    print(string.format("[B] %-40s -> rv=%d %s", w[5], a, a < 0 and es() or ""))
    if a > 0 then
        local _, pr, en = prot_of(a)
        print(string.format("[B]     mapped 0x%X prot=%d end=0x%X", a, pr, en))
        release(a)
    end
end

-- ---------------------------------------------------------------- [C] ftruncate widening
print("")
print("--- [C] ftruncate the descriptor, then retry the refused offsets ---")
local BOUNDS = {0x1000000000, 0x400000000, 0x200000000, 0x140000000, 0x120000000}
local function try_off(fd, off)
    if off >= 0x100000000 then
        return try_map(fd, math.floor(off / 4294967296), off % 4294967296, 0, 0x1000, PROT_RW)
    end
    return try_map(fd, 0, off, 0, 0x1000, PROT_RW)
end
for _, off in ipairs(BOUNDS) do
    local a = try_off(fd_d0, off)
    print(string.format("[C] before ftruncate off=0x%X -> rv=%d %s", off, a, a < 0 and es() or ""))
    if a > 0 then release(a) end
end
for _, size in ipairs({0x1000000000, 0x400000000, 0x10000000000, 0x1000}) do
    local hi = math.floor(size / 4294967296)
    local lo = size % 4294967296
    local ok, v = pcall(function() return N(sc_trunc(uint64(fd_d0), uint64(string.format("0x%08X%08X", hi, lo)), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    print(string.format("[C] ftruncate(dmem0, 0x%X) -> rv=%s %s", size, tostring(v or "EXC"), (v == -1) and es() or ""))
    if v == 0 then
        for _, off in ipairs(BOUNDS) do
            local a2 = try_off(fd_d0, off)
            print(string.format("[C]   after truncate off=0x%X -> rv=%d %s", off, a2, a2 < 0 and es() or ""))
            if a2 > 0 then release(a2) end
        end
    end
end

-- ---------------------------------------------------------------- [D] other nodes
print("")
print("--- [D] the same wrap on dmem1 / gc / zero ---")
local NODES = {{"dmem1", fd_d1}, {"gc", fd_gc}, {"zero", fd_z}}
for _, nd in ipairs(NODES) do
    local fd = nd[2]
    if fd > 0 then
        for _, w in ipairs({WRAPS[1], WRAPS[3], WRAPS[4]}) do
            local a = try_map(fd, w[1], w[2], w[3], w[4], PROT_RW)
            print(string.format("[D] %-5s %-32s -> rv=%d %s", nd[1], w[5], a, a < 0 and es() or ""))
            if a > 0 then release(a) end
        end
    else
        print(string.format("[D] %-5s no descriptor", nd[1]))
    end
end

-- ---------------------------------------------------------------- [E] sanity
print("")
print("--- [E] sanity: the low offsets still behave as measured ---")
do
    local a = try_map(fd_d0, 0, 0x0000, 0, 0x1000, PROT_RW)
    print(string.format("[E] dmem0 off=0 len=0x1000 -> rv=%d", a))
    if a > 0 then
        local ok, v = pcall(function() return N(memory.read_dword(a)) end)
        print(string.format("[E] first dword ok=%s value=0x%s (C0012800 expected)", tostring(ok), hex(ok and v or 0)))
        local before = ok and v or 0
        local wok = pcall(function() memory.write_dword(a, uint64(0x1478A147)) end)
        local ok2, v2 = pcall(function() return N(memory.read_dword(a)) end)
        print(string.format("[E] write ok=%s readback=0x%s (page-0 write expected to stick)", tostring(wok), hex(ok2 and v2 or 0)))
        if ok and ok2 and v2 ~= 0x1478A147 then
            pcall(function() memory.write_dword(a, uint64(before)) end)
        end
        release(a)
    end
end
if fd_d0 > 0 then pcall(function() sc_close(uint64(fd_d0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end
if fd_d1 > 0 then pcall(function() sc_close(uint64(fd_d1), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end
if fd_gc > 0 then pcall(function() sc_close(uint64(fd_gc), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end
if fd_z  > 0 then pcall(function() sc_close(uint64(fd_z),  uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end) end

print("")
local canary = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d", canary))
print("=== PROBE 1478a COMPLETE ===")
