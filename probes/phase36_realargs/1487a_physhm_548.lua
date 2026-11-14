-- CRASH_CLASS: HIGH -- the read at the end may fault and take the loader, which is expected: 318a
-- and 321a record that the first read at a physhm mapping kills the process. Everything before the
-- read is printed first, so a death still leaves the descriptor, the mapping address, the 547 record
-- and the 548 return value as data.
-- PROBE 1487a: physhm under a 548 protection rewrite
--
-- 314a/315a/316a/318a/321a established: 629(1, 2, 0, 0) returns a descriptor, mmap(MAP_SHARED) on
-- it "succeeds" and returns an address, but the pages are not backed and the first read kills the
-- process. read/write/ioctl/628 all refuse the descriptor.
--
-- 1480c/1486a changed what a mapping can do: 548 op 2 rewrites the protection of an entry and the
-- kernel honours it, including entries backed by a device pager. physhm is the one descriptor in the
-- tree whose whole purpose is physical memory, and it has never been tried under a 548 rewrite.
--
-- [A] 629(1,2,0,0) -> fd, and 547 of nothing
-- [B] mmap(fd, 0x4000, prot 3, MAP_SHARED) -> va, then 547 at va
-- [C] 548 op 2 prot 0 at va (drop), then prot 3 at va (restore) - does the pager react?
-- [D] 547 again, then read dword 0, dword 1, ... printing each one on its own line
-- [E] if the reads survive: store a marker and read it back
--
-- -- prior art:
--   probes/phase17_new_vectors/315a_physhm_map.lua (the fd and mmap shape)
--   results/phase17_new_vectors/318a_physhm_read_20261022_*.txt (first read kills)
--   docs/DEAD_ENDS.md: "physhm (sys 629) mmap - pages aren't backed"
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (548 on a pager entry)

print("=== PROBE 1487a: PHYSHM UNDER 548 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
-- Rebuild the full 64-bit value: a mapped address has a small high dword and dropping it turned
-- 0x310B40000 into 0x10B40000 in the first run of this probe.
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h, l = N(v.h), N(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return h * 4294967296 + l
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local function q547(addr, tag)
    local r = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(r + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(r), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok then print(string.format("    %s 547 EXC", tag)) return end
    if rv ~= 0 then print(string.format("    %s 547 rv=%s (not a mapped range)", tag, tostring(rv))) return end
    local slo, shi = N(memory.read_dword(r + 0x00)), N(memory.read_dword(r + 0x04))
    local elo, ehi = N(memory.read_dword(r + 0x08)), N(memory.read_dword(r + 0x0C))
    print(string.format("    %s 547 prot=%d 0x%X%08X-0x%X%08X flags=%d",
        tag, N(memory.read_dword(r + 0x10)), shi, slo, ehi, elo, N(memory.read_dword(r + 0x14))))
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
local sc548 = mk(548)
local function protect(addr, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

-- ---------------------------------------------------------------- [A] the descriptor
print("")
print("--- [A] 629(1,2,0,0) ---")
local okf, fdv = pcall(function()
    return mk(629)(uint64(1), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not okf then print("[A] 629 EXC") print("=== PROBE 1487a INCOMPLETE ===") return end
local fd = sgn(fdv)
print(string.format("[A] physhm fd = %d", fd))
if fd < 0 then
    print("[A] " .. es())
    print("=== PROBE 1487a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] map it
print("")
print("--- [B] mmap(fd, 0x4000, prot 3, MAP_SHARED) ---")
local okm, va = pcall(function()
    return sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0)))
end)
if not okm then print("[B] mmap EXC") print("=== PROBE 1487a INCOMPLETE ===") return end
print(string.format("[B] va = 0x%X", va))
if va <= 0x10000 then
    print("[B] " .. es())
    print("=== PROBE 1487a INCOMPLETE ===")
    return
end
q547(va, "[B]")

-- ---------------------------------------------------------------- [C] 548 both ways
print("")
print("--- [C] 548 op 2 on the mapping ---")
local r0, d0 = protect(va, 0x4000, 0)
print(string.format("    prot 0 -> rv=%s processed=%d %s", tostring(r0), d0, r0 == -1 and es() or ""))
q547(va, "[C] after prot 0")
local r3, d3 = protect(va, 0x4000, 3)
print(string.format("    prot 3 -> rv=%s processed=%d %s", tostring(r3), d3, r3 == -1 and es() or ""))
q547(va, "[C] after prot 3")

-- ---------------------------------------------------------------- [D] read, one dword at a time
print("")
print("--- [D] reads ---")
local survived = true
for i = 0, 7 do
    print(string.format("    reading +0x%02X ...", i * 4))
    local v = nil
    local ok = pcall(function() v = N(memory.read_dword(va + i * 4)) end)
    if not ok or v == nil then
        print(string.format("    +0x%02X  <no value>", i * 4))
        survived = false
        break
    end
    print(string.format("    +0x%02X  %08X", i * 4, v))
end

-- ---------------------------------------------------------------- [E] write it back
if survived then
    print("")
    print("--- [E] store and read back ---")
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(va + i, uint64(0xA1B2C300 + i)) end) end
    print("    wrote")
    for i = 0, 7 do
        print(string.format("    reading +0x%02X ...", i * 4))
        local v = nil
        local ok = pcall(function() v = N(memory.read_dword(va + i * 4)) end)
        if not ok or v == nil then print("    <no value>") break end
        print(string.format("    +0x%02X  %08X", i * 4, v))
    end
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1487a COMPLETE ===")
