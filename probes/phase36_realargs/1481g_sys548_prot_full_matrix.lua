-- CRASH_CLASS: MODERATE -- changes protections on our own pages and restores them. Never
-- executes the pages it touches, so a protection that is silently not applied cannot fault here.
-- PROBE 1481g: the full 548 op-2 protection matrix, and why prot 4 is refused
--
-- 1480a measured that 548 op 2 accepts prot 1 and 3 on an anonymous page but answers EACCES for
-- prot 5 and 7. Two explanations fit: (a) Sony filters out the execute bit, or (b) the entry's
-- max_prot does not contain execute, because the page was mmap'd with prot 3, and vm_map_protect
-- reports KERN_PROTECTION_FAILURE for anything outside max_prot.
--
-- The distinction matters. Under (b) a page mmap'd with prot 7 has an entry whose max_prot allows
-- every combination, so 548 could move it to prot 5 - read+execute - which mprotect refuses
-- outright at the entry point. Under (a) nothing below 4 is reachable and the W^X wall stands.
--
-- [A] sweeps prot 0..15 on an anon page mmap'd with prot 3 (max_prot 3).
-- [B] sweeps the same values on a page mmap'd with prot 7 (max_prot 7, if mmap honours it).
-- [C] sweeps the same values on a device window, whose original protection was 0x33.
-- Every rung is read back through 547 and then restored, so the matrix records what the vm_map
-- actually took, not what the syscall returned.
--
-- -- prior art:
--   results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt (prot 5/7 EACCES)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (0x33 -> 3 works)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the device windows)
--   docs/DEAD_ENDS.md (mprotect refuses the execute bit everywhere)

print("=== PROBE 1481g: 548 OP-2 PROTECTION MATRIX ===")

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
local sc477 = mk(477)
local sc73 = mk(73)
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

local function apply(addr, len, prot, op)
    set_entry(addr, 0, len, prot, op or 2)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    if not ok then return -999, -1 end
    local pr = 0
    pcall(function() pr = N(memory.read_dword(cnt)) end)
    return N(rv), pr
end

local function prot_of(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return nil end
    return N(memory.read_dword(rec + 0x10))
end

local function mmap_anon(prot)
    local ok, rv = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(prot), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local a = N(rv)
    if a < 0x1000 or a > 0x8000000000 then return nil end
    return a
end

local MATRIX = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 0x10, 0x20, 0x33}

local function sweep(label, addr, restore)
    print(string.format("--- %s at 0x%X ---", label, addr))
    local before = prot_of(addr)
    print(string.format("    prot before = %s", tostring(before)))
    local accepted = {}
    for _, prot in ipairs(MATRIX) do
        local rv, proc = apply(addr, 0x4000, prot)
        local after = prot_of(addr)
    local rd_ok, rd_v = false, nil
    if prot == 0x10 or prot == 0x20 or prot == 0x4 then
        pcall(function() rd_v = N(memory.read_dword(addr)) ; rd_ok = true end)
    end
        local mark = ""
        if rv == 0 and after == prot then mark = "  <<< TAKEN"
        elseif rv == 0 then mark = "  (rv 0, prot unchanged)" end
        local extra = ""
        if rd_ok then extra = string.format("  read=%08X", rd_v) end
        if (prot == 0x10 or prot == 0x20 or prot == 0x4) and not rd_ok then extra = "  read=FAULT" end
        print(string.format("    prot 0x%-3X -> rv=%-4s processed=%-4s 547=%s%s%s",
            prot, tostring(rv), tostring(proc), tostring(after), mark, extra))
        if rv == 0 and after == prot then accepted[#accepted + 1] = prot end
        -- restore between rungs so one rung cannot gate the next
        apply(addr, 0x4000, before or restore)
    end
    apply(addr, 0x4000, before or restore)
    local list = ""
    for _, p in ipairs(accepted) do list = list .. string.format("0x%X ", p) end
    print(string.format("    accepted: %s", (list == "") and "(none)" or list))
    return accepted
end

-- ---------------------------------------------------------------- [A] anon max_prot 3
print("")
local A = mmap_anon(3)
if not A then
    print("[A] mmap prot 3 FAILED")
else
    pcall(function() memory.write_dword(A, uint64(0x41424344)) end)
    print(string.format("[A] anon page 0x%X, value %s", A, tostring(prot_of(A))))
    sweep("[A] anon mmap(prot 3)", A, 3)
end

-- ---------------------------------------------------------------- [B] anon max_prot 7
print("")
local B = mmap_anon(7)
if not B then
    print("[B] mmap prot 7 FAILED")
else
    pcall(function() memory.write_dword(B, uint64(0x51525354)) end)
    local w = nil
    pcall(function() w = N(memory.read_dword(B)) end)
    print(string.format("[B] anon page 0x%X prot=%s, store+read -> %s",
        B, tostring(prot_of(B)), w and string.format("%08X", w) or "unreadable"))
    sweep("[B] anon mmap(prot 7)", B, 3)
end

-- ---------------------------------------------------------------- [C] a device window
print("")
local DEV = 0xF00004000   -- SceGnmTrapData, 16 KiB aligned, currently prot 3
local d0 = prot_of(DEV)
print(string.format("[C] device window SceGnmTrapData prot before = %s", tostring(d0)))
if d0 then
    sweep("[C] device SceGnmTrapData", DEV, 3)
else
    print("[C] 547 has no entry there; skipped")
end

-- ---------------------------------------------------------------- [D] what the refusals say
print("")
print("--- [D] the same refusals through 548 with a bad size, for the errno text ---")
local rv, _ = apply(DEV, 0x1000, 3)
print(string.format("[D] len 0x1000 (unaligned) -> rv=%s %s", tostring(rv), es()))

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481g COMPLETE ===")
