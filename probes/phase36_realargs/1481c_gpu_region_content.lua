-- CRASH_CLASS: MODERATE -- [B] bulk-reads device memory that killed the process before 548 op 2.
-- Each region prints its name and a progress mark every 1 MiB, so a death is localised to a
-- 64-chunk window. Every read is gated on a successful protect of that exact chunk.
-- PROBE 1481c: what is inside the GPU regions 548 just made readable.
--
-- 1481a only looked at the first 32 bytes of each window (all zeros except SceGnmTrapCode,
-- SceGnmTrapData and SceGnmDriver). The big ones were never read: SceGnmCwsr is 16 MiB,
-- SceGnmACQRB 1.9 MiB, SceAgcDdid 0xFC000. CWSR in particular is the compute wave save/restore
-- area, and ACQRB is the queue the command processor consumes.
--
-- This probe reads them with memory.read_buffer (a C-side bulk copy, so 16 MiB costs 1024 calls
-- instead of 4 million), and reports per extent:
--   - the first non-zero chunk,
--   - qwords whose high dword is 0xFFFFFFFF and whose low dword lands inside this boot's
--     measured image window (0xCC800000-0xD2800000), 8-byte aligned,
--   - how many other kernel-half values there are (reported, not claimed as pointers),
--   - printable strings of 8 or more characters.
-- Nothing is written.
--
-- A region whose protect or read failed says so and voids its own verdict, so a run where the
-- 548 gate refuses cannot be misread as "the GPU regions are empty".
--
-- -- prior art:
--   results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt (32-byte heads of all 19)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (op 2 moves 0x33 -> 3)
--   results/1331a_20261109_200838.txt (this boot's image base)
--   docs/DEAD_ENDS.md (GPU device mappings read dead before this; 376a, 380a)

print("=== PROBE 1481c: GPU REGION CONTENT ===")

-- Low dwords of this boot's measured image window. The high dword of an in-image qword is
-- 0xFFFFFFFF by construction, so only the low half has to be compared.
local KLO_MIN = 0xCC800000
local KLO_END = 0xD2800000

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d kernel image assumed 0x%08X%08X", PID, 0xFFFFFFFF, KLO_MIN))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc548 = mk(548)
local sc674 = mk(674)
local sc547 = mk(547)
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

local function prot_to3(addr, len)
    set_entry(addr, 0, len, 3, 2)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    if not ok then return -999 end
    return N(rv)
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] enumerate
print("")
print("--- [A] enumerate ---")
local buf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[A] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("=== PROBE 1481c INCOMPLETE ===")
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
    ["SceGnmCwsr"] = 0x1000000,
    ["SceGnmACQRB"] = 0x1E0000,
    ["SceAgcDdid"] = 0xFC000,
    ["SceGnmEopFifo"] = 0x3C000,
    ["SceGnmDriver"] = 0x10000,
    ["SceGnmMisc"] = 0x4000,
    ["SceGnmShadowRegInfo"] = 0x4000,
    ["SceGnmTrapCode"] = 0x4000,
    ["SceGnmTrapData"] = 0x4000,
    ["SceGnmDingDong"] = 0x4000,
    ["(NoName)eboot.bin"] = 0x8000,
}

-- Collect the extents per name, merging only genuinely adjacent ones. 674 lists several
-- (NoName)eboot.bin windows at unrelated addresses; collapsing them into one span would make the
-- scan walk off the end of a 16 KiB mapping into an unmapped hole.
local region = {}
local REGION_ORDER = {}
for i = 0, nrec - 1 do
    local b = buf + i * 72
    local s = u64at(b, 0x00)
    local e = u64at(b, 0x08)
    local name = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        name = name .. string.char(ch)
    end
    if WANT[name] and s >= 0x10000 and e > s then
        local list = region[name]
        if not list then
            list = {}
            region[name] = list
            REGION_ORDER[#REGION_ORDER + 1] = name
        end
        local merged = false
        for _, r in ipairs(list) do
            if s <= r.e and e >= r.s then
                if s < r.s then r.s = s end
                if e > r.e then r.e = e end
                merged = true
                break
            end
        end
        if not merged then list[#list + 1] = {s = s, e = e} end
    end
end
for _, name in ipairs(REGION_ORDER) do
    for _, r in ipairs(region[name]) do
        print(string.format("[A] %-22s 0x%X-0x%X (0x%X)", name, r.s, r.e, r.e - r.s))
    end
end

-- ---------------------------------------------------------------- [B] scan
print("")
print("--- [B] bulk read ---")
local TOTAL_K = 0
local TOTAL_S = 0

for _, name in ipairs(REGION_ORDER) do
    for _, r in ipairs(region[name]) do
        local lim = WANT[name]
        if r.e - r.s < lim then lim = r.e - r.s end
        lim = lim - (lim % 0x4000)
        if lim > 0 then
            print(string.format("  [%s] 0x%X-0x%X scanning 0x%X", name, r.s, r.e, lim))
            local kfound, scount, readfail, protfail = 0, 0, 0, 0
            local khalf = 0
            local firstnz = nil
            local off = 0
            while off < lim do
                local a = r.s + off
                local ready = (prot_of(a) == 3)
                if not ready then
                    local rv = prot_to3(a, 0x4000)
                    if rv ~= 0 then
                        protfail = protfail + 1
                        if protfail <= 3 then
                            local e = ""
                            if rv == -1 then e = es() end
                            print(string.format("    +0x%X protect rv=%s %s", off, tostring(rv), e))
                        end
                    end
                    ready = (prot_of(a) == 3)
                end
                if ready then
                    local okr, d = pcall(function() return memory.read_buffer(a, 0x4000) end)
                    if not okr or type(d) ~= "string" or #d ~= 0x4000 then
                        readfail = readfail + 1
                        print(string.format("    +0x%X read failed (%s)", off, type(d)))
                    else
                        local nz = d:find("[^%z]")
                        if nz then
                            if not firstnz then firstnz = off end
                            -- kernel-image qwords: every in-image qword ends with FF FF FF FF
                            local p = 1
                            while true do
                                local h0 = d:find("\255\255\255\255", p, true)
                                if not h0 then break end
                                local q = h0 - 5
                                if q >= 0 and q + 8 <= #d then
                                    local b0 = d:byte(q + 1) or 0
                                    local b1 = d:byte(q + 2) or 0
                                    local b2 = d:byte(q + 3) or 0
                                    local b3 = d:byte(q + 4) or 0
                                    local lo = b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
                                    if lo >= KLO_MIN and lo < KLO_END and (q % 8) == 0 then
                                        kfound = kfound + 1
                                        TOTAL_K = TOTAL_K + 1
                                        if kfound <= 8 then
                                            print(string.format("    +0x%X = FFFFFFFF%08X  <-- candidate in measured image", off + q, lo))
                                        end
                                    elseif lo >= 0x80000000 then
                                        khalf = khalf + 1
                                    end
                                end
                                local skip = d:find("[^\255]", h0)
                                p = skip or (#d + 1)
                            end
                            -- printable strings
                            local pos = 1
                            while pos <= 0x4000 do
                                local e0 = d:find("[%w%p ]", pos)
                                if not e0 then break end
                                local run = d:match("^[%w%p ]+", e0)
                                if run and #run >= 8 then
                                    scount = scount + 1
                                    TOTAL_S = TOTAL_S + 1
                                    if scount <= 6 then
                                        print(string.format("    +0x%X str %q", off + e0 - 1, run:sub(1, 48)))
                                    end
                                    pos = e0 + #run
                                else
                                    pos = e0 + 1
                                end
                            end
                        end
                    end
                end
                off = off + 0x4000
                if off % 0x100000 == 0 and off < lim then
                    print(string.format("    ... +0x%X", off))
                end
            end
            local void = (readfail > 0 or protfail > 0)
            print(string.format("  [%s] 0x%X: first non-zero %s, %d image candidates, %d other kernel-half, %d strings, %d read fails, %d protect fails%s",
                name, r.s, firstnz and string.format("+0x%X", firstnz) or "none",
                kfound, khalf, scount, readfail, protfail,
                void and "  -- VERDICT VOID" or ""))
            if firstnz then
                local a = r.s + firstnz
                local okr, d = pcall(function() return memory.read_buffer(a, 64) end)
                if okr and type(d) == "string" then
                    local hex = ""
                    for i = 1, math.min(64, #d) do hex = hex .. string.format("%02X ", d:byte(i)) end
                    print("    first non-zero bytes: " .. hex)
                end
            end
        end
    end
end

print("")
print(string.format("[B] totals: %d image candidates, %d strings", TOTAL_K, TOTAL_S))
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481c COMPLETE ===")
