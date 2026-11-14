-- CRASH_CLASS: MODERATE -- unmaps one 16 KiB device window that has already been read and written
-- harmlessly (1481b). The GPU register file SceGnmDriver is deliberately not touched.
-- PROBE 1498a: does unmapping a device windows entry return its physical pages to the anonymous pool?
--
-- 1480c showed 548 op 2 moves a device window from prot 0x33 to ordinary prot 3, after which it
-- reads and writes like RAM (1481b: 6/6 stores landed and restored). The window is backed by a
-- device pager, not by anonymous memory, so the physical pages behind it belong to the GPU. The
-- question nobody has asked: what does munmap do to such an entry? If it drops the pager's pages
-- into the general free pool while the device still holds them, then the next anonymous mapping can
-- hand back a page that a device is still using - a physical page aliasing primitive, and on a
-- unified memory console the device side is the GPU.
--
-- The detector needs no knowledge of the device: SceGnmTrapData's first dwords are 00144000 0000000F,
-- which is distinctive, so after the unmap a large anonymous mapping is scanned for that value.
-- Finding it means the page came back to the user allocator.
--
-- [A] find SceGnmTrapData in 674, 547 it, 548 op 2 -> prot 3, read its first dwords
-- [B] munmap the entry
-- [C] 674 again: did the entry disappear, and did anything replace it
-- [D] mmap 32 MiB anonymous and count pages whose first dword is 0x00144000 or that hold the second
--     dword 0x0000000F, plus every non-zero first dword, so a coincidence cannot pass as a hit
-- [E] verdict
--
-- -- prior art:
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (prot 0x33 -> 3)
--   results/phase36_realargs/1481b_gpu_windows_write_20261109_201732.txt (6/6 stores landed)
--   results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt (window contents)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (munmap is entry scoped)

print("=== PROBE 1498a: UNMAP A DEVICE WINDOW ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h, l = N(v.h), N(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return h * 4294967296 + l
end
local function qw(a) return N(memory.read_dword(a + 4)) * 4294967296 + N(memory.read_dword(a)) end
local function dw(a) return N(memory.read_dword(a)) end
local function nm(a, maxlen)
    local o = {}
    for i = 0, maxlen - 1 do
        local c = N(memory.read_byte(a + i))
        if c == 0 then break end
        if c >= 32 and c < 127 then o[#o + 1] = string.char(c) else o[#o + 1] = "." end
    end
    return table.concat(o)
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
local rec = memory.alloc(0x40)

local function map547(a)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", a)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

local function protect(a, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", a))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

local function vmmap()
    local buf = memory.alloc(72 * 512)
    local cnt = memory.alloc(8)
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local ok, rv = pcall(function()
        return N(mk(674)(uint64(buf), uint64(72), uint64(512), uint64(cnt), uint64(0x40000000), uint64(0)))
    end)
    local n = N(memory.read_dword(cnt))
    if n > 512 then n = 512 end
    local out = {}
    for i = 0, n - 1 do
        local r = buf + i * 72
        local name = ""
        local okn = pcall(function() name = nm(r + 0x20, 40) end)
        out[#out + 1] = {addr = qw(r), len = qw(r + 8) - qw(r), prot = dw(r + 0x18), name = okn and name or ""}
    end
    return out, ok and rv or nil
end

-- ---------------------------------------------------------------- [A]
print("")
print("--- [A] find and protect SceGnmTrapData ---")
local ALL, rv674 = vmmap()
print(string.format("  674 rv=%s, %d records", tostring(rv674), #ALL))
local T = nil
for _, r in ipairs(ALL) do
    if r.name:find("SceGnmTrapData", 1, true) then T = r end
end
if T == nil then
    print("  SceGnmTrapData not present; stopping")
    print("=== PROBE 1498a INCOMPLETE ===")
    return
end
print(string.format("  %s 0x%X len 0x%X prot %d", T.name, T.addr, T.len, T.prot))
print(string.format("  547 = %d", map547(T.addr)))
local before = {dw(T.addr), dw(T.addr + 4), dw(T.addr + 8), dw(T.addr + 12)}
local rvp, prp = protect(T.addr, 0x4000, 3)
print(string.format("  op2 prot 3 -> rv=%s processed=%d, 547 now %d", tostring(rvp), prp, map547(T.addr)))
if map547(T.addr) == 3 then
    before = {dw(T.addr), dw(T.addr + 4), dw(T.addr + 8), dw(T.addr + 12)}
    print(string.format("  content %08X %08X %08X %08X", before[1], before[2], before[3], before[4]))
end

-- ---------------------------------------------------------------- [B]
print("")
print("--- [B] munmap the entry ---")
local okm, rvm = pcall(function()
    return N(mk(73)(uint64(T.addr), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("  munmap rv=%s %s", okm and tostring(rvm) or "EXC", (okm and rvm == -1) and es() or ""))
print(string.format("  547 after = %d", map547(T.addr)))

-- ---------------------------------------------------------------- [C]
print("")
print("--- [C] 674 after the unmap ---")
local AFTER = vmmap()
local still = nil
local repl = {}
for _, r in ipairs(AFTER) do
    if r.addr <= T.addr and T.addr < r.addr + r.len then
        if r.name:find("SceGnmTrapData", 1, true) then still = r else repl[#repl + 1] = r end
    end
end
print(string.format("  the named entry is %s", still and "still present" or "GONE"))
for _, r in ipairs(repl) do
    print(string.format("  replaced by %-24s 0x%X len 0x%X prot %d", r.name, r.addr, r.len, r.prot))
end

-- ---------------------------------------------------------------- [D]
print("")
print("--- [D] anonymous allocation, scanned for the device content ---")
local LEN = 0x2000000
local okA, vA = pcall(function()
    return mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local A = okA and sgn(vA) or -1
print(string.format("  mmap 32 MiB -> 0x%X %s", A, A < 0 and es() or ""))
if A > 0x10000 then
    local hits, nonzero, other = 0, 0, 0
    local firsthit, firstnz = -1, -1
    local i = 0
    while i < LEN do
        local v = dw(A + i)
        if v ~= 0 then
            nonzero = nonzero + 1
            if firstnz < 0 then firstnz = i end
            if v == 0x00144000 then
                hits = hits + 1
                if firsthit < 0 then firsthit = i end
            else
                other = other + 1
            end
        end
        i = i + 16384
    end
    print(string.format("  2048 pages: %d non-zero first dwords, %d of them 0x00144000, %d other",
        nonzero, hits, other))
    if firstnz >= 0 then
        print(string.format("  first non-zero page +0x%X holds %08X %08X", firstnz, dw(A + firstnz), dw(A + firstnz + 4)))
    end
    if hits > 0 then
        print("  *** a device page appears to have returned to the anonymous pool ***")
    else
        print("  no device content in the fresh anonymous mapping")
    end
end

-- ---------------------------------------------------------------- [E]
print("")
print("--- [E] verdict ---")
print(string.format("  entry unmapped: %s", still and "no" or "yes"))
print(string.format("  original content was %08X %08X %08X %08X", before[1], before[2], before[3], before[4]))
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1498a COMPLETE ===")
