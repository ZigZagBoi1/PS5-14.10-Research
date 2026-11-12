-- CRASH_CLASS: LOW -- read-only, per-page mappings (1397g showed a hole at 0x17000).
-- PROBE 1397i: checksum-diff of the 0xF000 block across a sleep.
--
-- 1397h took a full table snapshot and then died in its own diff loop with "attempt to index field
-- '?' (a number value)" before printing anything useful, so no liveness answer was produced.  This
-- run computes a rolling checksum per page and prints the first eight dwords, sleeps 1.5 s with
-- nanosleep(240), and computes the same checksums again.  No tables of snapshots, nothing to index.
--
-- The question is unchanged: 0xF000-0x16FFF holds Sony-magic records (BEEB03FF, "COrbisMemory ONION",
-- stride-0x80 descriptor bodies).  If those bytes move while the console sits idle-but-rendering,
-- they are live structures and a store into them is a store into something the GPU or the kernel
-- driver walks.  If they are byte-identical after 1.5 s, they are a boot-time snapshot.
--
-- -- prior art:
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (the records, the 0x17000 hole)
--   results/phase36_realargs/1397h_dmem_block_liveness_20261109_143213.txt (dies before the diff)

print("=== PROBE 1397i: dmem BLOCK CHECKSUM DIFF ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex(v) return string.format("%08X", v) end
local function isva(v) return v > 0 and v < 0x8000000000 end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local fd0 = N(mk(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] dmem0 fd=%d", fd0))

local PG = {}
for p = 0x00, 0x16 do
    local va = N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd0), uint64(p * 0x1000)))
    if isva(va) then PG[p] = va end
end
local np = 0
for p = 0x00, 0x16 do if PG[p] then np = np + 1 end end
print(string.format("[0] mapped %d of 23 pages", np))

local function checksum(va)
    local h = 2166136261
    for i = 0, 0x3FF do
        local v = rd(va + i * 4)
        if v == nil then v = 0 end
        h = (h * 16777619 + v) % 4294967296
        h = (h + i) % 4294967296
    end
    return h
end

print("")
print("[A] first pass")
local C1 = {}
for p = 0x00, 0x16 do
    if PG[p] then
        C1[p] = checksum(PG[p])
        print(string.format("   page 0x%02X sum=%s  head: %s %s %s %s %s %s %s %s", p, hex(C1[p]),
            hex(rd(PG[p])), hex(rd(PG[p] + 4)), hex(rd(PG[p] + 8)), hex(rd(PG[p] + 0xC)),
            hex(rd(PG[p] + 0x10)), hex(rd(PG[p] + 0x14)), hex(rd(PG[p] + 0x18)), hex(rd(PG[p] + 0x1C))))
    end
end

print("")
print("[B] nanosleep 1.5 s")
local ts = memory.alloc(0x10)
pcall(function() memory.write_qword(ts, uint64(1)) end)
pcall(function() memory.write_qword(ts + 8, uint64(500000000)) end)
print(string.format("   nanosleep -> %d", N(mk(240)(uint64(ts), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("[C] second pass")
local changed = 0
for p = 0x00, 0x16 do
    if PG[p] then
        local c2 = checksum(PG[p])
        local flag = ""
        if C1[p] ~= c2 then flag = "   <-- CHANGED"; changed = changed + 1 end
        print(string.format("   page 0x%02X sum=%s%s", p, hex(c2), flag))
    end
end
print(string.format("   [C] %d pages changed over 1.5 s", changed))

print("")
print("[D] head dwords after the sleep, for the records")
for _, p in ipairs({0x0F, 0x10, 0x11}) do
    if PG[p] then
        print(string.format("   page 0x%02X : %s %s %s %s %s %s %s %s", p,
            hex(rd(PG[p])), hex(rd(PG[p] + 4)), hex(rd(PG[p] + 8)), hex(rd(PG[p] + 0xC)),
            hex(rd(PG[p] + 0x10)), hex(rd(PG[p] + 0x14)), hex(rd(PG[p] + 0x18)), hex(rd(PG[p] + 0x1C))))
    end
end

print("")
print("[Z] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397i COMPLETE ===")
