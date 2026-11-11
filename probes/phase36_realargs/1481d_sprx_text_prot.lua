-- CRASH_CLASS: HIGH -- [B] removes execute permission from one page of a system library. If that
-- page is on a hot path the process dies on the next call into it, and the loader is killed with
-- it. Mitigation: the target is the LAST 16 KiB of the module's text (cold, and usually padding),
-- and modules the Lua loader never calls (libSceSsl, libSceNpGameIntent, libSceHttp) are preferred
-- over libkernel. Every call prints its arguments and its return value before the next one.
-- PROBE 1481d: can 548 op 2 give read access to .sprx text?
--
-- 1480c moved 19 device mappings from prot 0x33 to 3 with 548 op 2, and 1480a showed op 2 refuses
-- prot 5 and prot 7 with EACCES on every kind of page, including on eboot text that already has
-- prot 5. A refusal of a no-op (5 -> 5) is evidence for an explicit "prot & 4 -> EACCES" filter
-- rather than the vm_map's own max_protection test.
--
-- That distinction decides whether .sprx text is readable. 674 lists every system library's text
-- as prot 4 (execute-only): a read kills the process (377a), so the real 14.10 libkernel code,
-- its syscall table and its gadgets have never been seen. If the filter is only "no bit 4", then
-- prot 1 on a text page is legal for the filter, and it succeeds or fails purely on the entry's
-- max_protection. If it succeeds, the page becomes readable and this probe reads its first 64
-- bytes -- the first .sprx text this project has ever read.
--
-- The change cannot be undone: restoring prot 4 also carries bit 4 and is refused. So a success
-- costs that page its execute permission for the rest of the process's life, which is why the
-- targets are chosen for being cold.
--
-- -- prior art:
--   results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt (prot 5 and 7 -> EACCES)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (.sprx text prot 4 refused)
--   results/374a_sprx_text_read_fatal_*.txt (a text read kills the process)
--   docs/DEAD_ENDS.md (Execute-only memory: system lib .text is XO, reading crashes)

print("=== PROBE 1481d: SPRX TEXT PROTECTION VIA 548 OP 2 ===")

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

local function prot_set(addr, len, prot)
    set_entry(addr, 0, len, prot, 2)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    local proc = 0
    pcall(function() proc = N(memory.read_dword(cnt)) end)
    return r, proc
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] find text regions
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
    print("=== PROBE 1481d INCOMPLETE ===")
    return
end
if nrec > 400 then nrec = 400 end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

-- Modules the loader does not call. Order matters: the first one that answers wins the read.
local PREF = {"libSceNpGameIntent", "libSceSsl", "libSceHttp", "libSceWebBrowserDialog", "libSceNpCommon"}

local texts = {}
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
    if pr == 4 and s >= 0x10000 and e - s >= 0x4000 and name:find("%.sprx$") then
        texts[#texts + 1] = {s = s, e = e, name = name}
    end
end
print(string.format("[A] %d execute-only text regions", #texts))

local picked = {}
for _, want in ipairs(PREF) do
    for i = 1, #texts do
        if texts[i].name == want .. ".sprx" then
            picked[#picked + 1] = texts[i]
            break
        end
    end
end
-- A control from libkernel last, only if nothing else is left.
for i = 1, #texts do
    if texts[i].name == "libkernel.sprx" and #picked < 3 then
        picked[#picked + 1] = texts[i]
    end
end
if #picked == 0 then
    for i = 1, math.min(3, #texts) do picked[#picked + 1] = texts[i] end
end
for i = 1, #picked do
    print(string.format("[A] target %-28s 0x%X-0x%X", picked[i].name, picked[i].s, picked[i].e))
end

-- ---------------------------------------------------------------- [B] try prot 1
print("")
print("--- [B] 548 op 2 with prot 1 on the last 16 KiB of each ---")
for i = 1, #picked do
    local t = picked[i]
    local last = t.e - 0x4000
    last = last - (last % 0x4000)
    print(string.format("[B] %s: page 0x%X prot before=%s", t.name, last, tostring(prot_of(last))))
    local rv, proc = prot_set(last, 0x4000, 1)
    local e = ""
    if rv == -1 then e = es() end
    print(string.format("[B]   548 op2 prot 1 -> rv=%s processed=%d %s", tostring(rv), proc, e))
    if rv == 0 then
        local pr = prot_of(last)
        print(string.format("[B]   547 says prot after = %s", tostring(pr)))
        local okr, d = pcall(function() return memory.read_buffer(last, 64) end)
        if okr and type(d) == "string" and #d == 64 then
            local hex = ""
            for k = 1, 64 do hex = hex .. string.format("%02X ", d:byte(k)) end
            print("[B]   FIRST 64 BYTES: " .. hex)
        else
            print("[B]   read failed")
        end
        -- The page cannot be restored (prot 4 carries bit 4 and is refused), so stop here:
        -- further library calls risk the fetch fault this change created.
        print("[B]   stopping: this page has no execute permission any more")
        break
    end
end

-- ---------------------------------------------------------------- [C] a control on our own page
print("")
print("--- [C] controls: prot 1 and prot 4 on an anonymous page of ours ---")
local cal = 0
local okm, mv = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
if okm then
    local v = mv
    if type(v) == "table" and v.tonumber then v = v:tonumber() end
    cal = tonumber(v) or 0
end
if cal >= 0x10000 then
    local r1 = prot_set(cal, 0x4000, 1)
    print(string.format("[C] anon prot 1 -> rv=%s prot now %s", tostring(r1), tostring(prot_of(cal))))
    local r4 = prot_set(cal, 0x4000, 4)
    local e4 = ""
    if r4 == -1 then e4 = es() end
    print(string.format("[C] anon prot 4 -> rv=%s %s (an explicit bit-4 filter predicts -1 here)", tostring(r4), e4))
else
    print("[C] mmap failed")
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481d COMPLETE ===")
