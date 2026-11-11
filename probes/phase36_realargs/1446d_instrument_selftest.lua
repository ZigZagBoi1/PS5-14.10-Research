-- CRASH_CLASS: LOW
-- PROBE 1446d: instrument self-test for the select length experiment
--
-- Context: probes 1446b and 1446c both died inside their setup, before printing a
--   single measurement line, so the failure is in the instrument and not in the
--   kernel surface under test.  1446c's capture
--   (results/phase36_realargs/1446c_select_fdset_len_20261109_171018.txt) is a raw
--   loader mcontext dump: 0x13371337, then 0, then 0x0b (SIGSEGV), i.e. a userland
--   fault inside the mmap/zero-marker prologue.
--
--   This probe does nothing but print a step number before each action, so the
--   capture names the exact instruction group that faults.
--
-- -- prior art: 1446a (results/phase36_realargs/1446a_select_fdset_bound_20261109_170718.txt)
--   successfully mapped 0x10000 and wrote the whole region with the identical `wr`
--   helper, so `map`+`wr` is proven; the difference here is the region size and the
--   munmap.  docs/DEAD_ENDS.md has no select bullet.

print("=== PROBE 1446d: INSTRUMENT SELF-TEST ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc477 = make_syscall(477)
local sc73  = make_syscall(73)
local sc20  = make_syscall(20)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wr(a, v)
    local ok = pcall(function() memory.write_dword(a, uint64(v)) end)
    return ok
end

print(string.format("step 1: pid=%d", to_num(sc20())))
print("step 2: calling mmap(0x4000)")

local okm, vam = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not okm then
    print("step 2: mmap RAISED -- abort")
    print("=== PROBE 1446d COMPLETE ===")
    return
end
local Q = to_num(vam)
print(string.format("step 3: mmap returned 0x%08X", Q))
if Q < 0x10000 or Q > 0x8000000000 then
    print("step 3: not a usable address -- abort")
    print("=== PROBE 1446d COMPLETE ===")
    return
end

print("step 4: write one dword at base")
local o1 = wr(Q, 0x11111111)
print(string.format("step 5: write ok=%s  readback=0x%08X", tostring(o1), rd(Q)))
print("step 6: write one dword at base+0x2FFC")
local o2 = wr(Q + 0x2FFC, 0x22222222)
print(string.format("step 7: write ok=%s  readback=0x%08X", tostring(o2), rd(Q + 0x2FFC)))
print("step 8: write one dword at base+0x3FFC (last mapped dword)")
local o3 = wr(Q + 0x3FFC, 0x33333333)
print(string.format("step 9: write ok=%s  readback=0x%08X", tostring(o3), rd(Q + 0x3FFC)))
print("step 10: calling munmap(base+0x3000, 0x1000)")
print(string.format("step 11: munmap rv=%d", to_num(sc73(uint64(Q + 0x3000), uint64(0x1000)))))
print(string.format("step 12: markers 0x%08X 0x%08X (want 11111111 22222222)",
    rd(Q), rd(Q + 0x2FFC)))
print("step 13: done")
print("")
print("=== PROBE 1446d COMPLETE ===")
