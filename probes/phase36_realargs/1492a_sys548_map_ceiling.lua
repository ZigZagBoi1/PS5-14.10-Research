-- CRASH_CLASS: MODERATE -- op 3 asks the kernel to install a mapping at addresses the mmap wrapper
-- refuses. If it succeeds somewhere unexpected, one guarded read follows and that read is last.
-- Nothing is stored into any address the probe did not create.
-- PROBE 1492a: does 548 op 3 honour the mmap address ceiling, and what does it do to an occupied
-- address?
--
-- Two facts that have never been put together:
--   1395a: MAP_FIXED|MAP_ANON is refused at 0x7FFFFFFF0000 (EINVAL), 0x7FFFFFFFFFF000 (ENOMEM) and
--          0xFFFFFFFFC0000000 (EINVAL), so the mmap syscall has an explicit user-address ceiling.
--   1488b: 548 op 3 maps anonymous memory and RETURNS the address in rax, and its case
--          (0xffffffff8b47c11e) does not go through the mmap wrapper - it builds its own
--          uvm_map_args and calls 0x8b478430 directly, forcing fd=-1 and taking the map flags from
--          entry[+0x08] | 0x1000.
-- If the ceiling lives in the wrapper and not in vm_map, op 3 installs a mapping the mmap path
-- forbids. A user-accessible page at a high address is a bug whether or not it is usable, and the
-- same question applies at an address that is already mapped: op 3 onto a live entry tests whether
-- the batch path replaces, splits or refuses, which is the same family as munmap being entry
-- scoped (1450a) instead of range scoped.
--
-- [A] baselines: mmap MAP_FIXED|MAP_ANON at five high addresses - confirm 1395a still holds
-- [B] op 3 at the same five addresses, printing rv, the returned address and 547
-- [C] op 3 onto occupied addresses: our own anon page, a /dev/dmem0 page, ./AOSharedState
-- [D] one guarded read of any address that became mapped, last
--
-- -- prior art:
--   results/phase36_realargs/1395a_dev_mmap_offset_wrap_20261109_141742.txt (the mmap ceiling)
--   results/phase36_realargs/1488b_sys548_map_desc_20261109_215258.txt (op 3 returns the address)
--   results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt (op 0 at an occupied address)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (munmap is entry scoped)

print("=== PROBE 1492a: SYS 548 MAP CEILING ===")

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

local function protect(addr, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
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

-- op 3: map anonymous memory at addr, flags from field8, returns the address it used
local function map_op3(addr, len, prot, field8)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr or 0))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", field8 or 0))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 3) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

local function map547(addr)
    if addr == nil or addr <= 0 then return -1 end
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

local HIGH = {
    {addr = 0x7FFFFFFF0000,     name = "0x7FFFFFFF0000"},
    {addr = 0x7FFFFFFFFFF000,   name = "0x7FFFFFFFFFF000"},
    {addr = 0xFFFFFFFFC0000000, name = "0xFFFFFFFFC0000000"},
    {addr = 0x10000000000,      name = "0x10000000000"},
    {addr = 0x400000000000,     name = "0x400000000000"},
}

-- ---------------------------------------------------------------- [A] the mmap baseline
print("")
print("--- [A] mmap MAP_FIXED|MAP_ANON at the same addresses (1395a baseline) ---")
for _, h in ipairs(HIGH) do
    local ok, v = pcall(function()
        return mk(477)(uint64(string.format("0x%X", h.addr)), uint64(0x4000), uint64(3), uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local va = ok and sgn(v) or -1
    print(string.format("  %-20s mmap -> 0x%X %s", h.name, va, va < 0 and es() or ""))
    if va > 0x10000 then
        pcall(function() mk(73)(uint64(string.format("0x%X", va)), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        print("      (unmapped again)")
    end
end

-- ---------------------------------------------------------------- [D] control before anything else
print("")
print("--- [D] 548 controls ---")
local ctl_ok = false
local ctlva = 0
do
    local rv, pr = map_op3(0, 0x4000, 3, 0)
    local va = rv
    print(string.format("  op3 start=0 -> rv=0x%X processed=%d", va, pr))
    if va > 0x10000 then
        ctlva = va
        print(string.format("      547 prot %d", map547(va)))
    end
    local a = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a > 0x10000 then
        local rv2, pr2 = protect(a, 0x4000, 1)
        local p1 = map547(a)
        print(string.format("  op2 on anon 0x%X -> rv=%s processed=%d -> prot %d", a, tostring(rv2), pr2, p1))
        if rv2 == 0 and p1 == 1 then ctl_ok = true end
        protect(a, 0x4000, 3)
    end
end
print(string.format("[D] control usable: %s", tostring(ctl_ok)))
if not ctl_ok then
    print("548 is not behaving as measured; stopping")
    print("=== PROBE 1492a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] op 3 at the high addresses
print("")
print("--- [B] op 3 at the addresses mmap refused ---")
local landed = {}
for _, h in ipairs(HIGH) do
    local rv, pr = map_op3(h.addr, 0x4000, 3, 0)
    local p = map547(rv)
    local shown = "as an error"
    if type(rv) == "number" and rv > 0x10000 then
        shown = string.format("MAPPED at 0x%X", rv)
        landed[#landed + 1] = rv
    elseif rv == -1 then
        shown = es()
    end
    print(string.format("  %-20s op3 rv=%-14s processed=%-2s 547=%d %s",
        h.name, tostring(rv), tostring(pr), p, shown))
end

-- ---------------------------------------------------------------- [C] op 3 onto occupied addresses
print("")
print("--- [C] op 3 onto an address that is already mapped ---")
local OCC = {}
do
    -- our own anon page with a marker
    local a = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a > 0x10000 then
        pcall(function() memory.write_dword(a, uint64(0xAABBCCDD)) end)
        OCC[#OCC + 1] = {addr = a, name = "anon with marker", expect = 0xAABBCCDD}
    end
    -- a dmem0 page
    local path = "/dev/dmem0"
    local pb = memory.alloc(#path + 2)
    for i = 1, #path do pcall(function() memory.write_byte(pb + i - 1, string.byte(path, i)) end) end
    pcall(function() memory.write_byte(pb + #path, 0) end)
    local ok, v = pcall(function() return mk(5)(uint64(pb), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    local fd = ok and sgn(v) or -1
    if fd >= 0 then
        local ok2, v2 = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1), uint64(fd), uint64(0))
        end)
        local dva = ok2 and sgn(v2) or -1
        if dva > 0x10000 then OCC[#OCC + 1] = {addr = dva, name = "dmem0 page", fd = fd} end
        print(string.format("  dmem0 fd=%d va=0x%X", fd, dva))
    end
end
for _, o in ipairs(OCC) do
    local before = map547(o.addr)
    local rv, pr = map_op3(o.addr, 0x4000, 3, 0)
    local after = map547(rv)
    print(string.format("  %-18s 0x%X prot %d -> op3 rv=%-12s processed=%-2s -> 547 %d",
        o.name, o.addr, before, tostring(rv), tostring(pr), after))
    if o.expect then
        local v = nil
        local ok = pcall(function() v = N(memory.read_dword(o.addr)) end)
        print(string.format("      marker at the original address reads %s (expected %08X)",
            ok and string.format("%08X", v) or "fault", o.expect))
    end
end

-- ---------------------------------------------------------------- [E] one guarded read, last
print("")
print("--- [E] guarded read of the first high address that mapped ---")
if #landed == 0 then
    print("  none of the high addresses mapped")
else
    local a = landed[1]
    print(string.format("  reading 0x%X (547 prot %d) ...", a, map547(a)))
    local v = nil
    local ok = pcall(function() v = N(memory.read_dword(a)) end)
    print(string.format("  -> %s", ok and string.format("%08X", v) or "fault"))
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1492a COMPLETE ===")
