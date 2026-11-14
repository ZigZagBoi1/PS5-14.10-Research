-- CRASH_CLASS: MODERATE -- writes 8 bytes at a chosen offset inside a named region, then restores
-- the original bytes immediately. Offsets are chosen well past the header, inside the region.
-- PROBE 1495a: is any named region shared with another process?
--
-- 1489a/1489b/1489c established the full shape for ONE region: ./AOSharedState is prot 1, 548 op 2
-- raises it to prot 3, a store lands, and after a relaunch both the address and the content are
-- regenerated - so that one is per process. Nobody tested the other six named regions, which is the
-- interesting question: if a named heap is a vm_object that a DIFFERENT, more privileged process
-- also maps, then 548 op 2 is a cross process write channel and the game process can corrupt a
-- daemon's heap with attacker bytes.
--
-- The detector needs no knowledge of the other process: write a magic qword deep inside the region
-- (well past the header, and restored afterwards), then on a LATER run of the same probe find the
-- same region BY NAME and look for the magic. Addresses move per process, names do not.
--   magic present after a relaunch -> the object outlives the process -> it is shared
--   magic absent                    -> the object was created for this process
--
-- [A] 674, collect every entry that has a name
-- [B] for each: 547 prot, scan [0x1000, 0x40000) for a previous magic, print what is found
-- [C] for each prot-1 region: read the qword at a deep offset, 548 op 2 -> prot 3, store the magic,
--     read it back, restore the original qword, 548 op 2 -> prot 1
-- [D] for each prot-3 region: same, but no protection change is needed
-- [E] re-read every marker through a fresh 674 record and re-check 547, then the final canary
--
-- -- prior art:
--   results/phase36_realargs/1489a_ao_shared_prot_20261109_215505.txt (./AOSharedState is prot 1)
--   results/phase36_realargs/1489b_ao_shared_write_20261109_215541.txt (548 op 2 makes it writable)
--   results/phase36_realargs/1489c_ao_state_persist_20261109_215707.txt (regenerated per process)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the named regions)

print("=== PROBE 1495a: NAMED REGION CROSS-PROCESS TEST ===")

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
local MAGIC_LO = 0xC0FFEE00
local MAGIC_HI = 0xDEADBEEF

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
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

-- ---------------------------------------------------------------- [A] collect named entries
print("")
print("--- [A] named entries from 674 ---")
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
        if okn and #name > 0 then
            REGS[#REGS + 1] = {addr = math.floor(s / 65536) * 65536, len = e - s, prot = p, name = name}
        end
    end
end
print(string.format("  %d named entries", #REGS))

-- ---------------------------------------------------------------- [B] look for a previous magic
print("")
print("--- [B] scanning each named region for a magic written by an earlier run ---")
local function scan_magic(base, len)
    local lim = len
    if lim > 0x20000 then lim = 0x20000 end
    if lim > 0x1000 then
        local found = nil
        pcall(function()
            local i = 0x1000
            while i + 8 < lim do
                if dw(base + i) == MAGIC_LO and dw(base + i + 4) == MAGIC_HI then
                    found = base + i
                    break
                end
                i = i + 8
            end
        end)
        return found
    end
    return nil
end

for _, r in ipairs(REGS) do
    local hit = nil
    if r.prot == 1 or r.prot == 3 then
        local ok = pcall(function() hit = scan_magic(r.addr, r.len) end)
        if not ok then hit = "FAULT" end
    end
    print(string.format("  %-32s 0x%010X len 0x%-8X prot %-3d previous magic: %s",
        r.name, r.addr, r.len, r.prot,
        hit == nil and "none" or (hit == "FAULT" and "scan faulted" or string.format("FOUND at 0x%X", hit))))
end

-- ---------------------------------------------------------------- [C] write markers
print("")
print("--- [C] store a magic deep inside each named region, then restore it ---")
local written = {}
for _, r in ipairs(REGS) do
    if r.len >= 0x20000 and (r.prot == 1 or r.prot == 3) then
        local off = 0x10000
        while off + 8 < r.len and off < 0x400000 do off = off + 0x10000 end
        off = off - 0x10000
        if off < 0x1000 then off = 0x1000 end
        local at = r.addr + off
        local page = math.floor(at / 16384) * 16384
        local p0 = map547(r.addr)
        local pp = map547(page)
        local note = ""
        local lifted = false
        if pp ~= 3 then
            local rvp, prp = protect(page, 0x4000, 3)
            note = string.format(" [lift page 0x%X rv=%s processed=%d]", page, tostring(rvp), prp)
            if rvp == 0 and prp == 1 then lifted = true end
        end
        if map547(page) == 3 then
            local ok_old = pcall(function() return dw(at) end)
            local oldlo = nil
            local ok_old2 = pcall(function() return dw(at + 4) end)
            local oldhi = nil
            if ok_old then oldlo = dw(at) end
            if ok_old2 then oldhi = dw(at + 4) end
            if oldlo == nil or oldhi == nil then
                print(string.format("  %-32s 0x%010X +0x%X read faulted, skipped", r.name, r.addr, off))
            else
                pcall(function() memory.write_dword(at, uint64(MAGIC_LO)) end)
                pcall(function() memory.write_dword(at + 4, uint64(MAGIC_HI)) end)
                local nlo, nhi = nil, nil
                pcall(function() nlo = dw(at) end)
                pcall(function() nhi = dw(at + 4) end)
                local stuck = nlo == MAGIC_LO and nhi == MAGIC_HI
                print(string.format("  %-32s 0x%010X +0x%X prot %d page %d stored=%s%s",
                    r.name, r.addr, off, p0, map547(page), tostring(stuck), note))
                if stuck then written[#written + 1] = r end
                pcall(function() memory.write_dword(at, uint64(oldlo)) end)
                pcall(function() memory.write_dword(at + 4, uint64(oldhi)) end)
            end
        else
            print(string.format("  %-32s 0x%010X prot 1, lift refused%s", r.name, r.addr, note))
        end
        if lifted then
            local rvq = protect(page, 0x4000, 1)
            print(string.format("      page protection restored (rv=%s, prot now %d)", tostring(rvq), map547(page)))
        end
    end
end

-- ---------------------------------------------------------------- [E] verdict
print("")
print("--- [E] verdict ---")
print(string.format("  regions where a store landed: %d", #written))
for _, r in ipairs(written) do
    print(string.format("    %s at 0x%X", r.name, r.addr))
end
print("  a magic that is still present on a LATER run means the object outlives this process")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1495a COMPLETE ===")
