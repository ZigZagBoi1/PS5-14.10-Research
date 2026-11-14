-- CRASH_CLASS: LOW -- read-only, and every page gets its own mapping because 1397g showed a hole
-- (page 0x17000 faults even inside a mapping that spans it).
-- PROBE 1397h: is the 0xF000-0x16FFF block live or a boot-time snapshot?
--
-- 1397g dumped it.  It is structured: a BEEB03FF magic at 0xF000, 0xF100, 0xF200 with PM4-shaped
-- dwords after it, ASCII at 0xF020/0xF140/0xF220 ("SbrO"/"hdr"), and at 0x103C0 the string
-- "COrbisMemory ONION".  From 0x11000 up it is a stride-0x80 record array with a stable 32-byte body,
-- a run of AFAFAFAF, and a per-record counter (0210FD30, 0210FD32, 0210FD34 ... walking by 2, then a
-- second series 0210FD6F, 0210FD71).  At 0x10080 it is pairs of (00FD0060, 2), (00FD0070, 2) ...
--
-- A snapshot taken at boot never moves.  A live structure - a command ring, a descriptor list the
-- GPU walks, a per-frame state block - does.  Sleeping a second and diffing separates them, and the
-- answer decides whether a store here is a GPU command injection or a write into dead memory.
-- The game is running (a loader process on a live console), so a live ring must move.
--
-- -- prior art:
--   results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt (the dump, and the 0x17000 hole)
--   results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt (only these pages are non-zero)

print("=== PROBE 1397h: dmem 0xF000 BLOCK LIVENESS ===")

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

local function page_map(off)
    return N(mk(477)(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd0), uint64(off)))
end

-- per-page mappings: one hole must not take the whole probe down
local PG = {}
for p = 0x0F, 0x16 do
    local va = page_map(p * 0x1000)
    if isva(va) then
        PG[p] = va
    else
        print(string.format("   page 0x%02X map refused: %s", p, es()))
    end
end
local np = 0
for p = 0x0F, 0x16 do if PG[p] then np = np + 1 end end
print(string.format("[0] mapped %d pages", np))

local function snap(va)
    local t = {}
    for i = 0, 0x3FF do t[i] = rd(va + i * 4) or 0 end
    return t
end

print("")
print("[A] first snapshot")
local S1 = {}
for p = 0x0F, 0x16 do
    if PG[p] then
        S1[p] = snap(PG[p])
        local h = 0
        for i = 0, 0x3FF do h = (h + S1[p][i] * (i + 1)) % 4294967296 end
        print(string.format("   page 0x%02X checksum %s", p, hex(h)))
    end
end

print("")
print("[B] sleep 1200 ms (nanosleep 240)")
local ts = memory.alloc(0x10)
pcall(function() memory.write_qword(ts, uint64(1)) end)
pcall(function() memory.write_qword(ts + 8, uint64(200000000)) end)
local rv = N(mk(240)(uint64(ts), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("   nanosleep -> %d %s", rv, es()))

print("")
print("[C] second snapshot and diff")
local total = 0
for p = 0x0F, 0x16 do
    if PG[p] and S1[p] then
        local S2 = snap(PG[p])
        local n = 0
        for i = 0, 0x3FF do
            if S1[p][i] ~= S2[p][i] then
                n = n + 1
                if n <= 6 then
                    print(string.format("   page 0x%02X +0x%03X : %s -> %s", p, i * 4, hex(S1[p][i]), hex(S2[p][i])))
                end
            end
        end
        total = total + n
        print(string.format("   page 0x%02X : %d dwords changed", p, n))
    end
end
print(string.format("   [C] total changed dwords: %d", total))

print("")
print("[D] three quick re-reads of page 0x0F (is it a ring head that moves per read?)")
if PG[0x0F] then
    for k = 1, 3 do
        print(string.format("   %s %s %s %s", hex(rd(PG[0x0F])), hex(rd(PG[0x0F] + 4)), hex(rd(PG[0x0F] + 8)), hex(rd(PG[0x0F] + 0xC))))
    end
end

print("")
print("[Z] close")
print(string.format("   dmem0 -> %d", N(mk(6)(uint64(fd0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1397h COMPLETE ===")
