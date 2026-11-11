-- CRASH_CLASS: LOW -- read-only. No store, no protection change. Every read is gated on 547 first.
-- PROBE 1495a: which named regions are being written by somebody else?
--
-- 1489c showed ./AOSharedState is regenerated per process - the address moved and the content went
-- back to its initial value. That answers the question for one region. The other named regions have
-- never been looked at, and the question matters: if a named heap is a vm_object that a different,
-- more privileged process also maps, then 548 op 2 (which lifts a read-only region to writable,
-- 1489b) becomes a cross process write channel into a daemon's heap.
--
-- Sharing can be detected with no writes at all: a region only this process can touch has identical
-- bytes before and after a sleep in which we do nothing. A region somebody else is using changes.
-- The launcher and the system daemons run continuously, so a shared heap will churn.
--
-- [A] 674, collect every entry that has a name, with its prot
-- [B] checksum the first 0x400 bytes of each readable one, sleep 1500 ms, checksum again
-- [C] report which regions changed, and the 547 record for each that did
--
-- -- prior art:
--   results/phase36_realargs/1489c_ao_state_persist_20261109_215707.txt (AOSharedState is per process)
--   results/phase36_realargs/1489b_ao_shared_write_20261109_215541.txt (548 op 2 makes prot 1 writable)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the full named list)

print("=== PROBE 1495a: NAMED REGION CHURN ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
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

local rec = memory.alloc(0x40)
local function map547(addr)
    if addr == nil or addr <= 0 then return -1 end
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

-- FNV over n bytes, one pcall for the whole run so a bad region aborts only its own checksum
local function sum(base, n)
    local h = 2166136261
    local ok = pcall(function()
        local i = 0
        while i < n do
            local w = dw(base + i)
            for _ = 1, 4 do
                h = h - h % 256
                local b = w % 256
                h = (h * 16777619 + b) % 4294967296
                w = math.floor(w / 256)
            end
            i = i + 4
        end
    end)
    if not ok then return nil end
    return h
end

-- ---------------------------------------------------------------- [A]
print("")
print("--- [A] named entries ---")
local REGS = {}
do
    local buf = memory.alloc(72 * 512)
    local cnt = memory.alloc(8)
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local ok, rv = pcall(function()
        return N(mk(674)(uint64(buf), uint64(72), uint64(512), uint64(cnt), uint64(0x40000000), uint64(0)))
    end)
    local n = N(memory.read_dword(cnt))
    print(string.format("  674 rv=%s count=%d", ok and tostring(rv) or "EXC", n))
    if n > 512 then n = 512 end
    for i = 0, n - 1 do
        local r = buf + i * 72
        local s = qw(r)
        local e = qw(r + 8)
        local p = dw(r + 0x18)
        local name = ""
        local okn = pcall(function() name = nm(r + 0x20, 40) end)
        if okn and #name > 0 and e > s then
            REGS[#REGS + 1] = {addr = math.floor(s / 65536) * 65536, len = e - s, prot = p, name = name}
        end
    end
end
print(string.format("  %d named entries", #REGS))

-- ---------------------------------------------------------------- [B] two checksums with a sleep between
print("")
print("--- [B] checksum, sleep 1500 ms, checksum again ---")
local READABLE = {[1] = true, [3] = true, [2] = true, [0x10] = true, [0x20] = true, [0x23] = true, [0x33] = true}
local rows = {}
for _, r in ipairs(REGS) do
    if READABLE[r.prot] and r.len >= 0x800 then
        local p = map547(r.addr)
        local row = {name = r.name, addr = r.addr, len = r.len, prot = r.prot, map = p}
        if p ~= -1 then
            row.a = sum(r.addr, 0x400)
        else
            row.a = nil
        end
        rows[#rows + 1] = row
    end
end

local ts = memory.alloc(16)
pcall(function() memory.write_qword(ts, uint64(1)) end)
pcall(function() memory.write_qword(ts + 8, uint64(500000000)) end)
local okn, rvn = pcall(function()
    return N(mk(240)(uint64(ts), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("  nanosleep rv=%s", okn and tostring(rvn) or "EXC"))

local changed = 0
for _, row in ipairs(rows) do
    if row.a ~= nil then
        row.b = sum(row.addr, 0x400)
        if row.b ~= nil and row.b ~= row.a then
            row.churn = true
            changed = changed + 1
        end
    end
end

-- ---------------------------------------------------------------- [C]
print("")
print("--- [C] results ---")
for _, row in ipairs(rows) do
    local st = "unreadable"
    if row.a == nil then st = "checksum faulted"
    elseif row.b == nil then st = "second checksum faulted"
    elseif row.churn then st = "*** CHANGED ***"
    else st = "identical" end
    print(string.format("  %-34s 0x%010X len 0x%-8X prot %-3d 547 %-3d %s",
        row.name, row.addr, row.len, row.prot, row.map, st))
end
print("")
print(string.format("  regions that changed while this process did nothing: %d of %d", changed, #rows))
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1495a COMPLETE ===")
