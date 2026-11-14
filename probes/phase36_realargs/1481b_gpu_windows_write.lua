-- CRASH_CLASS: HIGH -- [B]/[C] store into GPU-backed memory. A refused store is swallowed by the
-- loader's write path, so the oracle is a marker plus a read-back, not survival. The GPU register
-- file at SceGnmDriver is deliberately NOT written: a stray register store can hang the console,
-- and the question (does a store land at all) is answered just as well by the data windows.
-- PROBE 1481b: after 548 op 2 makes the GPU windows prot 3, do stores land?
--
-- 1481a read them: SceGnmTrapCode holds real bytes, SceGnmTrapData a small table,
-- SceGnmDriver mirrors the dmem0 page-0 register block, the rest is zeros. The remaining question
-- is direction. prot 3 means read-write, but the pmap answers that, not the vm_map, and the only
-- way to ask is to store.
--
-- The oracle is a marker and a read-back: 381a showed the loader's write path swallows a store it
-- cannot make, so "the process survived" proves nothing. Each target is read, a different dword
-- is written, the dword is read back, and the original is restored. A store that lands changes
-- the read-back; a store the pmap refuses leaves it.
--
-- -- prior art:
--   results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt (contents, 4 kernel-shaped qwords)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (op 2 moves 0x33 -> 3)
--   results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt (store oracle calibration)
--   docs/DEAD_ENDS.md (GPU device mappings read dead before this; 376a, 380a)
--   docs/DMEM_WINDOW_14_10.md (the dmem0 window is already writable RAM)

print("=== PROBE 1481b: ARE THE GPU WINDOWS WRITABLE ===")

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
local sc477 = mk(477)

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
        print(string.format("     %-38s rv=%-4s %s", tag, tostring(r), e))
    end
    return r
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

-- Calibrate the store oracle on a page that is certainly writable, so the capture carries a
-- known-positive next to every negative.
print("")
print("--- [A] calibration on an anonymous page of ours ---")
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
    pcall(function() memory.write_dword(cal, uint64(0x11223344)) end)
    local b = 0
    pcall(function() b = N(memory.read_dword(cal)) end)
    print(string.format("[A] anon 0x%X: wrote 11223344 read %08X -> %s", cal, b,
        b == 0x11223344 and "oracle works" or "ORACLE BROKEN"))
    if b ~= 0x11223344 then
        print("=== PROBE 1481b INCOMPLETE ===")
        return
    end
else
    print("[A] mmap failed; the oracle cannot be calibrated")
    print("=== PROBE 1481b INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] the named windows
print("")
print("--- [B] rebuild the named windows and protect them ---")
local buf = memory.alloc(0x9000)
for i = 0, 0x8FFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[B] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("=== PROBE 1481b INCOMPLETE ===")
    return
end
if nrec > 400 then nrec = 400 end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

-- Only these three. SceGnmDriver is the register file and is never written.
local TARGETS = {"SceGnmTrapCode", "SceGnmTrapData", "(NoName)eboot.bin"}
local cand = {}
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
    for _, want in ipairs(TARGETS) do
        if name == want and s >= 0x10000 then
            cand[#cand + 1] = {s = s, e = e, pr = pr, name = name}
        end
    end
end
print(string.format("[B] %d candidate windows", #cand))

for i = 1, #cand do
    local r = cand[i]
    if r.pr ~= 3 then
        set_entry(r.s - (r.s % 0x4000), 0, 0x4000, 3, 2)
        v548(r.name .. " -> prot 3")
    end
    local now = prot_of(r.s)
    print(string.format("   %-20s 0x%X-0x%X prot now %s", r.name, r.s, r.e, tostring(now)))
end

-- ---------------------------------------------------------------- [C] store
print("")
print("--- [C] store a marker into each and read it back ---")
local landed, tried = 0, 0
for i = 1, #cand do
    local r = cand[i]
    if prot_of(r.s) == 3 then
        tried = tried + 1
        local v0 = 0
        pcall(function() v0 = N(memory.read_dword(r.s)) end)
        local mark = (v0 + 0x11) % 4294967296
        print(string.format("[C] %-20s 0x%X: read %08X, writing %08X", r.name, r.s, v0, mark))
        pcall(function() memory.write_dword(r.s, uint64(mark)) end)
        local back = 0
        pcall(function() back = N(memory.read_dword(r.s)) end)
        print(string.format("[C]    readback %08X -> %s", back, back == mark and "STORE LANDED" or "store did not land"))
        if back == mark then landed = landed + 1 end
        pcall(function() memory.write_dword(r.s, uint64(v0)) end)
        local rest = 0
        pcall(function() rest = N(memory.read_dword(r.s)) end)
        print(string.format("[C]    restored %08X (was %08X) %s", rest, v0,
            rest == v0 and "OK" or "NOT RESTORED"))
    end
end
print(string.format("[C] %d of %d stores landed", landed, tried))

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481b COMPLETE ===")
