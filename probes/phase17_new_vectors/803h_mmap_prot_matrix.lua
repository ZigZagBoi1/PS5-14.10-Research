-- CRASH_CLASS: MODERATE
-- PROBE 803h: what protection does mmap actually store for each requested prot?
--
-- 803g showed max_protection == the mapping's creation prot for every page (text pages refuse
-- W, heap pages refuse X).  That makes the creation call the only way to obtain an executable
-- page.  This probe maps one page per requested prot value and reads back what sys 674 reports,
-- including the Sony 0x30/0x10 flag bits.
print("=== PROBE 803h: MMAP PROTECTION MATRIX ===")
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
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local ok, v = pcall(function() return memory.read_byte(a + i) end)
        local b = ok and (to_num(v) % 256) or 0
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end
local getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc_mmap = make_syscall(477)
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
        if va >= lo and va < hi then return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18) end
    end
    return nil
end
local i = 0
local prots = {0,1,2,3,4,5,6,7,0x08,0x10,0x20,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}
print("[A] flags=0x1012 (fixed anon private)")
for _, pr in ipairs(prots) do
    i = i + 1
    local a = 0x700000000 + i * 0x20000
    pcall(function() return sc_munmap(uint64(a), uint64(0x4000)) end)
    local ok, rv = pcall(function()
        return sc_mmap(uint64(a), uint64(0x4000), uint64(pr), uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local r = ok and to_num(rv) or -999
    local _, _, p = region_of(a)
    print(string.format("  want=%02X ret=%-4s stored=%s", pr, tostring(r), p and string.format("%02X", p) or "GONE"))
end
print("")
print("[B] flags=0x1002 (kernel-chosen address)")
for _, pr in ipairs({3,5,7,0x33,0x37}) do
    local ok, rv = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(pr), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local r = ok and to_num(rv) or -999
    local _, _, p = region_of(r)
    print(string.format("  want=%02X ret=%-12s stored=%s", pr, tostring(r), p and string.format("%02X", p) or "GONE"))
end
print("")
print("[Z] alive pid=" .. to_num(getpid()))
