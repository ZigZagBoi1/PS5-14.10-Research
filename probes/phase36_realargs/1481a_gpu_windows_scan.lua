-- CRASH_CLASS: MODERATE -- [B] reads device memory that has always killed the process before
-- 1480c moved its protection, and [C] writes to a device page. Every read and write prints its
-- address first, and the write targets a page verified as fill (0xAFAFAFAF) rather than data.
-- PROBE 1481a: what is in the GPU windows once 548 op 2 makes them readable.
--
-- 1480c: sys 548 op 2 turned 19 pre-existing device mappings from prot 0x33 to prot 3, 547
-- confirmed each change, and the pages that 376a/380a recorded as read-fatal then read normally
-- (0xF00000000 -> BF800001, 0xFE0000000 -> C0012800, 0xFE0200000 -> FFFFFFFF).
--
-- That is the first read access any probe has had to the GPU register file and the driver's
-- mapped tables. This probe asks the two questions that decide whether it is useful:
--   [B] does any of it hold a kernel pointer (0xFFFF8xxx_xxxxxxxx)? A single real kernel VA is
--       worth more than every syscall sweep in this tree.
--   [C] is the moved protection also writable? A write is attempted only on a page whose content
--       is the 0xAFAFAFAF fill, so a stray store cannot corrupt live data.
-- The mapping list is rebuilt from 674 by name every run, because the anon regions move.
--
-- -- prior art:
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (19 mappings moved, reads land)
--   results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt (op 2 is a real protect)
--   docs/DEAD_ENDS.md (GPU device mappings read dead: 376a, 380a)
--   docs/DMEM_WINDOW_14_10.md (the dmem0 window: page 0 register table, the ONION block)

print("=== PROBE 1481a: GPU WINDOWS AFTER 548 OP 2 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local sc547 = mk(547)
local sc674 = mk(674)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x20)
local cnt = memory.alloc(0x10)

local function set_entry(start, offset, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", offset))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

local function v548(tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    if r ~= 0 then
        local e = ""
        if r == -1 then e = es() end
        print(string.format("     %-40s rv=%-4s %s", tag, tostring(r), e))
    end
    return r
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] rebuild the list
print("")
print("--- [A] enumerate and protect by name ---")
local buf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[A] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("[A] 674 did not enumerate")
    print("=== PROBE 1481a INCOMPLETE ===")
    return
end
if nrec > 400 then nrec = 400 end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

local WANT = {
    ["SceGnmDriver"] = 0x4000,
    ["SceGnmTrapCode"] = 0x4000,
    ["SceGnmTrapData"] = 0x4000,
    ["SceGnmShadowRegInfo"] = 0x4000,
    ["SceGnmMisc"] = 0x4000,
    ["SceGnmEopFifo"] = 0x4000,
    ["SceGnmDingDong"] = 0x4000,
    ["SceAgcDdid"] = 0x4000,
    ["SceGnmACQRB"] = 0x2000,
    ["SceGnmCwsr"] = 0x2000,
    ["(NoName)eboot.bin"] = 0x2000,
}

local picked = {}
for i = 0, nrec - 1 do
    local b = buf + i * 72
    local s = u64at(b, 0x00)
    local e = u64at(b, 0x08)
    local pr = 0
    pcall(function() pr = N(memory.read_dword(b + 0x18)) end)
    local name = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        name = name .. string.char(ch)
    end
    if WANT[name] and s >= 0x10000 then
        picked[#picked + 1] = {s = s, e = e, pr = pr, name = name, scan = WANT[name]}
    end
end
print(string.format("[A] %d named windows found", #picked))

local readable = {}
for i = 1, #picked do
    local r = picked[i]
    local before = prot_of(r.s)
    if before ~= 3 then
        set_entry(r.s - (r.s % 0x4000), 0, 0x4000, 3, 2)
        local rv = v548(r.name)
        if rv ~= 0 then
            print(string.format("     %-20s not protected (%s), skipping", r.name, tostring(rv)))
        end
    end
    local after = prot_of(r.s)
    print(string.format("   %-22s 0x%X-0x%X prot %s -> %s", r.name, r.s, r.e, tostring(before), tostring(after)))
    if after == 3 then readable[#readable + 1] = r end
end

-- ---------------------------------------------------------------- [B] scan for kernel pointers
print("")
print("--- [B] first bytes and any kernel-shaped qword ---")
local KHITS = 0
for i = 1, #readable do
    local r = readable[i]
    local lim = r.scan
    if r.s + lim > r.e then lim = r.e - r.s end
    print(string.format("  %s @0x%X:", r.name, r.s))
    local head = ""
    for k = 0, 31 do
        local v = 0
        pcall(function() v = N(memory.read_byte(r.s + k)) end)
        head = head .. string.format("%02X ", v)
    end
    print("    " .. head)
    local hits = 0
    local off = 0
    while off + 8 <= lim and hits < 6 do
        local lo, hi = 0, 0
        pcall(function() lo = N(memory.read_dword(r.s + off)) end)
        pcall(function() hi = N(memory.read_dword(r.s + off + 4)) end)
        if hi >= 0xFFFF8000 and hi <= 0xFFFFFFFF and not (lo == 0xFFFFFFFF and hi == 0xFFFFFFFF) then
            hits = hits + 1
            KHITS = KHITS + 1
            print(string.format("    +0x%04X = %08X%08X  <-- kernel shaped", off, hi, lo))
        end
        off = off + 8
    end
end
print(string.format("[B] %d kernel-shaped qwords across %d windows", KHITS, #readable))

-- ---------------------------------------------------------------- [C] is it writable?
print("")
print("--- [C] a write test on a page that is fill, not data ---")
local wrote = false
for i = 1, #readable do
    local r = readable[i]
    local v = 0
    pcall(function() v = N(memory.read_dword(r.s)) end)
    if v == 0xAFAFAFAF and r.e - r.s >= 0x4000 then
        print(string.format("[C] target 0x%X (%s) reads AFAFAFAF", r.s, r.name))
        pcall(function() memory.write_dword(r.s, uint64(0xDEADBEEF)) end)
        local back = 0
        pcall(function() back = N(memory.read_dword(r.s)) end)
        print(string.format("[C] wrote DEADBEEF, read %08X -> %s", back, back == 0xDEADBEEF and "WRITE LANDED" or "write did not land"))
        pcall(function() memory.write_dword(r.s, uint64(0xAFAFAFAF)) end)
        wrote = true
        break
    end
end
if not wrote then
    print("[C] no fill page found; the write path was not exercised")
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481a COMPLETE ===")
