-- CRASH_CLASS: LOW -- read-only mappings, no stores anywhere.  A mapping that succeeds is read and
-- closed; nothing is written to device memory.
-- PROBE 1397b: what does the /dev/dmem0 mmap offset index?
--
-- 1396b measured two things that no earlier probe in this tree had: the page at /dev/dmem0 offset
-- 0x1000 accepts a store, and the stored dwords are visible through a *second* independent mapping
-- of the same offset, and also through /dev/dmem1 offset 0x1000.  So dmem0 and dmem1 are two
-- descriptors onto one backing store, and an offset selects a page inside it.
--
-- Offset 0 reads the GPU register block (0x80000000C0012800, 0x80000000C0001200, ...), which the
-- tree already documents as "phys 0 = GPU HW reg".  Offset 0x1000 reads a zeroed page that we can
-- write.  The question this probe answers is the one that decides whether the node is a curiosity
-- or the exploit: does the offset walk a linear address space, and if so how far can it walk?
-- 1395a only tried 0x10000000 and above and got EINVAL, which says nothing about 0x2000..0x1000000.
--
-- If the offset is a linear index into physical memory, the page at offset 0x1000 is physical
-- 0x1000 and the page at offset 0x200000 is physical 0x200000, and a writable mapping of an
-- arbitrary offset is a physical-memory write.  If the offset is instead a small window id that
-- the driver switches on, only a handful of values will map and their contents will not vary
-- with the offset.
--
-- Read-only on purpose: this probe never stores.
--
-- -- prior art:
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt (store lands, shared backing)
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt (0x1000 and 0 only)
--   docs/DEAD_ENDS.md (the /dev/dmem0 bullet: "GPU aperture only")

print("=== PROBE 1397b: /dev/dmem0 OFFSET INDEX ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function isva(v) return v > 0 and v < 2147483647 end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local fd0 = N(mk(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
local fd1 = N(mk(5)(uint64(str_addr("/dev/dmem1")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] dmem0 fd=%d dmem1 fd=%d", fd0, fd1))

-- ---------------------------------------------------------------- A
print("")
print("[A] offset ladder on dmem0 (prot=1, read only, one page each)")
local OFFS = {
    0, 0x1000, 0x2000, 0x3000, 0x4000, 0x8000, 0xC000, 0x10000, 0x20000,
    0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000, 0x1000000,
    0x2000000, 0x4000000, 0x8000000, 0x10000000,
}
local OK = {}
for _, off in ipairs(OFFS) do
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd0), uint64(off)))
    if isva(va) then
        print(string.format("   off=0x%08X -> va=0x%08X : %s %s %s %s %s %s %s %s",
            off, va, hex4(rd(va)), hex4(rd(va + 4)), hex4(rd(va + 8)), hex4(rd(va + 0xC)),
            hex4(rd(va + 0x10)), hex4(rd(va + 0x14)), hex4(rd(va + 0x18)), hex4(rd(va + 0x1C))))
        OK[#OK + 1] = off
    else
        print(string.format("   off=0x%08X -> %d %s", off, va, es()))
    end
end
print(string.format("   [A] mapped %d of %d offsets", #OK, #OFFS))

-- ---------------------------------------------------------------- B
print("")
print("[B] same offsets on dmem1 (should be the same backing store)")
for _, off in ipairs(OK) do
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd1), uint64(off)))
    if isva(va) then
        print(string.format("   off=0x%08X -> va=0x%08X : %s %s %s %s", off, va,
            hex4(rd(va)), hex4(rd(va + 4)), hex4(rd(va + 8)), hex4(rd(va + 0xC))))
    else
        print(string.format("   off=0x%08X -> %d %s", off, va, es()))
    end
end

-- ---------------------------------------------------------------- C
print("")
print("[C] alignment and length rules at the offset that worked")
for _, off in ipairs({0x1001, 0x1800, 0x800, 0x1400}) do
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd0), uint64(off)))
    print(string.format("   dmem0 off=0x%X -> %d %s", off, va, es()))
end
for _, len in ipairs({0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x40000}) do
    local va = N(mk(477)(uint64(0), uint64(len), uint64(1), uint64(1), uint64(fd0), uint64(0x1000)))
    if isva(va) then
        print(string.format("   dmem0 off=0x1000 len=0x%X -> va=0x%X : %s %s %s %s", len, va,
            hex4(rd(va)), hex4(rd(va + 4)), hex4(rd(va + 8)), hex4(rd(va + 0xC))))
    else
        print(string.format("   dmem0 off=0x1000 len=0x%X -> %d %s", len, va, es()))
    end
end

-- ---------------------------------------------------------------- D
print("")
print("[D] /dev/gc offsets (its page read all FF)")
for _, off in ipairs({0, 0x1000, 0x2000, 0x4000, 0x10000, 0x100000, 0x1000000}) do
    local fdg = N(mk(5)(uint64(str_addr("/dev/gc")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fdg), uint64(off)))
    if isva(va) then
        print(string.format("   gc off=0x%08X -> va=0x%08X : %s %s %s %s", off, va,
            hex4(rd(va)), hex4(rd(va + 4)), hex4(rd(va + 8)), hex4(rd(va + 0xC))))
    else
        print(string.format("   gc off=0x%08X -> %d %s", off, va, es()))
    end
    pcall(function() return mk(6)(uint64(fdg), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

print("")
print("[E] close")
for _, fd in ipairs({fd0, fd1}) do
    if fd > 0 then print(string.format("   close(%d) -> %d", fd, N(mk(6)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))) end
end

print("")
print("=== PROBE 1397b COMPLETE ===")
