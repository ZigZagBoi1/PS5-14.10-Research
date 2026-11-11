-- CRASH_CLASS: MODERATE
-- PROBE 1437a: sys 628 mmap_dmem with a live /dev/dmem0 descriptor
--
-- 1436a swept 628 with no device open: every container index 0..20 answered
-- EBUSY(16) and 21 answered EINVAL(22).  EBUSY on *every* index is not a
-- per-container state problem, it reads as "this process has no descriptor for
-- that container".  The 13.60 worker computes the container record as
-- container_table(0x8de90e50) + idx*0x138 and calls 0x8ad83740(td, record, 1)
-- to resolve a descriptor; nothing in that path consults the caller's fd, so the
-- descriptor has to be created by something else -- most cheaply by opening the
-- node, which is what this probe varies.
--
-- Order matters and is the experiment:
--   [A] 628 before any open          (the 1436a result, as a control)
--   [B] open /dev/dmem0, no mmap, 628 again
--   [C] mmap offset 0 (the register window), 628 again
--   [D] mmap a data offset, 628 again
--   [E] second fd on /dev/dmem1, 628 again
--   [F] the physical sweep repeated in the state that worked
--
-- SAFETY: container index 0xFFFFFFFF is never passed (it stores curthread at
-- container_table-0xE8 and panics).  len is always 0x4000 and 0x4000-aligned.
--
-- Prior art:
--   1436a results/phase36_realargs/1436a_mmap_dmem_phys_sweep_20261109_164617.txt
--   1409a results/phase36_realargs/1409a_637_dmem_ceiling_20261109_152941.txt
--   docs/DMEM_628_AND_SYSCALL_585_14_10.md
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1437a: 628 WITH A LIVE DMEM DESCRIPTOR ===")
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
local function rd(p) return to_num(memory.read_dword(p)) end

local m628, m477, m5 = sc(628), sc(477), sc(5)

-- open() wants a pointer to the path, not a Lua string
local function str_addr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local function call628(phys, len, idx, flags)
    local ok, r = pcall(function()
        return m628(uint64(phys), uint64(len), uint64(idx),
            uint64(flags or 0), uint64(0), uint64(0))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end
local function looks_va(v)
    return type(v) == "number" and v >= 0x10000 and v <= 0x8000000000
end
local function probe(phys)
    local rv = call628(phys, 0x4000, 0, 0)
    local e = es()
    local extra = ""
    if looks_va(rv) then
        local ok, a, b, c, d = pcall(function()
            return rd(rv), rd(rv + 4), rd(rv + 8), rd(rv + 12)
        end)
        if ok then extra = string.format("  [%08X %08X %08X %08X]", a, b, c, d)
        else extra = "  [READ-EXC]" end
    end
    return string.format("628(%#x) -> %-6s (%-24s)%s", phys, tostring(rv), e, extra), rv
end
local function step(label, phys)
    local line, rv = probe(phys)
    print("  " .. label)
    print("    " .. line)
    return rv
end

local function open_dev(path)
    local ok, r = pcall(function()
        return m5(uint64(str_addr(path)), uint64(0x4002), uint64(0))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end
local function map_off(fd, off, len, prot)
    local ok, r = pcall(function()
        return m477(uint64(0), uint64(len), uint64(prot or 3), uint64(1),
            uint64(fd), uint64(off))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end

print("[A] control: 628 before any open")
step("phys 0", 0)
step("phys 0x100000", 0x100000)
print("")

print("[B] open /dev/dmem0, no mapping")
local fd0 = open_dev("/dev/dmem0")
print(string.format("  open(/dev/dmem0) -> %s", tostring(fd0)))
step("phys 0", 0)
step("phys 0x100000", 0x100000)
step("phys 0x100000000", 0x100000000)
print("")

print("[C] mmap offset 0 (the register window) through that fd")
local va0 = map_off(fd0, 0, 0x4000, 3)
print(string.format("  mmap(off 0) -> %s", tostring(va0)))
if looks_va(va0) then
    print(string.format("    first dwords: %08X %08X %08X %08X", rd(va0), rd(va0 + 4), rd(va0 + 8), rd(va0 + 12)))
end
step("phys 0", 0)
step("phys 0x100000", 0x100000)
print("")

print("[D] mmap a data offset through the same fd")
local va1 = map_off(fd0, 0x10000000, 0x4000, 3)
print(string.format("  mmap(off 0x10000000) -> %s", tostring(va1)))
step("phys 0", 0)
step("phys 0x10000000", 0x10000000)
print("")

print("[E] second fd on /dev/dmem1")
local fd1 = open_dev("/dev/dmem1")
print(string.format("  open(/dev/dmem1) -> %s", tostring(fd1)))
step("phys 0", 0)
step("phys 0x40000000", 0x40000000)
print("")

print("[F] physical sweep in the current state")
for _, p in ipairs({0, 0x4000, 0x100000, 0x10000000, 0x80000000,
                    0xC0000000, 0x100000000, 0x200000000}) do
    local line = probe(p)
    print("  " .. line)
end
print("")

print("[G] container index sweep at phys 0")
for _, ix in ipairs({0, 1, 2, 3, 0x14}) do
    local rv = call628(0, 0x4000, ix, 0)
    print(string.format("  idx=%-3d -> %-6s (%s)", ix, tostring(rv), es()))
end
print("")

print("[H] survivor check")
print(string.format("  re-open /dev/dmem0 -> %s", tostring(open_dev("/dev/dmem0"))))
if looks_va(va0) then
    print(string.format("  first mapping still reads %08X", rd(va0)))
end

print("")
print("=== PROBE 1437a COMPLETE ===")
