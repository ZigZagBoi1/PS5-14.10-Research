-- CRASH_CLASS: HIGH
-- PROBE 803d: identify which 548 op is the protect, with a fresh page per op
--
-- 803c showed op=3 returning the mapped address and leaving prot=3 on a page that ops 1/2 had
-- already unmapped, so the op matrix has never been measured against a live page.  This probe
-- maps a fresh page before every (op, prot) pair and reads the protection back from sys 674.
--
-- Classification: ret == addr and prot changed  -> map; region GONE -> unmap; ret == 0 and prot
-- changed -> protect; ret == 0 and prot unchanged -> no-op or a check that ignored us.

print("=== PROBE 803d: 548 OP MATRIX ON A LIVE PAGE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function split(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end

local getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc_mmap = make_syscall(477)
local sc548 = make_syscall(548)
local sc_munmap = make_syscall(73)
pcall(function() return getpid() end)

local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)

local function region_of(va)
    wq(countp, uint64(0))
    local ok = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return nil end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        if va >= lo and va < hi then
            return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18)
        end
    end
    return nil
end

local recs = memory.alloc(0x20 * 8)
local function batch(addr, payload, len, prot, op)
    local b = recs
    wq(b, split(0, addr))
    wq(b + 8, split(0, payload))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, op)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end

local TARGET = 0x700000000
local function fresh(prot)
    pcall(function() return sc_munmap(uint64(TARGET), uint64(0x4000)) end)
    local ok, rv = pcall(function()
        return sc_mmap(uint64(TARGET), uint64(0x4000), uint64(prot), uint64(0x1012),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return -999 end
    return to_num(rv)
end

print("[A] control: a fresh page per op, prot requested = 7")
for op = 0, 4 do
    local m = fresh(3)
    local lo, hi, p0, nm0 = region_of(TARGET)
    local r = batch(TARGET, 0, 0x4000, 7, op)
    local lo2, hi2, p1, nm1 = region_of(TARGET)
    print(string.format("  op=%d mmap=%d before=%-4s ret=%-12s after=%-4s %s", op, m,
        tostring(p0), tostring(r), p1 and tostring(p1) or "GONE", nm1 or ""))
end

print("")
print("[B] the op that changed the protection, across requested values")
-- find it: rerun each op once with prot=0 on a prot=3 page; a protect op sets prot to 0
local protect_op = nil
for op = 0, 4 do
    fresh(3)
    local r = batch(TARGET, 0, 0x4000, 0, op)
    local _, _, p = region_of(TARGET)
    if p == 0 then protect_op = op end
end
print("  protect op = " .. tostring(protect_op))
if protect_op then
    for _, want in ipairs({1, 2, 3, 4, 5, 6, 7}) do
        fresh(3)
        local r = batch(TARGET, 0, 0x4000, want, protect_op)
        local _, _, p = region_of(TARGET)
        print(string.format("  want=%d ret=%s got=%s", want, tostring(r), p and tostring(p) or "GONE"))
    end
    print("")
    print("[C] can it raise a page it did not create? (the eboot rx page)")
    local eb_lo, eb_hi, eb_p = region_of(0x4CEF0000)
    print(string.format("  eboot page before prot=%s", eb_p and tostring(eb_p) or "?"))
    local r = batch(0x4CEF0000, 0, 0x4000, 7, protect_op)
    local _, _, p2 = region_of(0x4CEF0000)
    print(string.format("  eboot page after ret=%s prot=%s", tostring(r), p2 and tostring(p2) or "?"))
end

print("")
print("[D] alive pid=" .. to_num(getpid()))
