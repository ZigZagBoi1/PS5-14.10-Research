-- CRASH_CLASS: LOW -- read only. No store, no protection change.
-- PROBE 1489c: does the ./AOSharedState marker survive this process?
--
-- 1489b wrote DEAD1234 CAFEBABE 55667788 99AABBCC at +0x100 of ./AOSharedState while 548 had
-- raised the region to prot 3, and the values were still there after the protection went back to 1.
-- The remaining question is whether that memory belongs to this process or to whoever else maps the
-- same object: if the marker is still present after the loader restarts with a new pid, the region
-- is a durable shared object and 548 has handed this process a cross-process write channel; if it
-- reads back as the original 08000000 pattern, the region is per-process and the family is closed.
--
-- -- prior art:
--   results/phase36_realargs/1489b_ao_shared_write_20261109_215541.txt (the marker and the restore)
--   results/phase36_realargs/1489a_ao_shared_prot_20261109_215505.txt (prot 1 -> 3 -> 1)

print("=== PROBE 1489c: AO SHARED STATE PERSISTENCE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
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

local MAX = 400
local buf = memory.alloc(MAX * 72 + 0x40)
local cnt = memory.alloc(0x10)
for i = 0, MAX * 72 + 0x30, 8 do pcall(function() memory.write_qword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local ok = pcall(function()
    return N(mk(674)(uint64(buf), uint64(72), uint64(MAX), uint64(cnt), uint64(0x40000000), uint64(0)))
end)
if not ok then
    print("674 raised")
    print("=== PROBE 1489c INCOMPLETE ===")
    return
end
local n = N(memory.read_dword(cnt))
if n <= 0 or n > MAX then n = 0 end
print(string.format("674 count=%d", n))

local found = 0
for i = 0, n - 1 do
    local r = buf + i * 72
    local name = nm(r + 0x20, 40)
    if name:find("SharedState") then
        local s, e = qw(r + 0x00), qw(r + 0x08)
        found = found + 1
        print(string.format("  %s 0x%X len 0x%X prot=%d flags=0x%X",
            name, s, e - s, N(memory.read_dword(r + 0x18)), N(memory.read_dword(r + 0x1C))))
        print(string.format("    header: %08X %08X %08X %08X",
            N(memory.read_dword(s)), N(memory.read_dword(s + 4)),
            N(memory.read_dword(s + 8)), N(memory.read_dword(s + 12))))
        print(string.format("    +0x100: %08X %08X %08X %08X",
            N(memory.read_dword(s + 0x100)), N(memory.read_dword(s + 0x104)),
            N(memory.read_dword(s + 0x108)), N(memory.read_dword(s + 0x10C))))
        local v = N(memory.read_dword(s + 0x100))
        if v == 0xDEAD1234 then
            print("    VERDICT: the marker SURVIVED the process - the region is durable and shared")
        else
            print(string.format("    VERDICT: marker absent (+0x100 = %08X), region is per-process", v))
        end
    end
end
if found == 0 then print("  ./AOSharedState not present this boot") end
print("=== PROBE 1489c COMPLETE ===")
