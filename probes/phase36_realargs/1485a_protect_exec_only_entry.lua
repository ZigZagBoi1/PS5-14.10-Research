-- CRASH_CLASS: HIGH -- if 548 accepts the protect, the target page loses PROT_EXEC permanently (548
-- refuses any value carrying bit 0x4, so exec can never be put back). libkernel.sprx is therefore
-- skipped entirely: de-exec'ing it would kill the interpreter before anything could be printed.
-- Every step prints before it calls, so a death still leaves the last line as a datum.
-- PROBE 1485a: can 548 rewrite an execute-only entry
--
-- 1481g proved 548 op 2 accepts prot 0/1/2/3 and refuses 4/5/6/7/8/9/A/C/F on an ANONYMOUS page.
-- Every 548 experiment so far targeted an entry we created. Nobody has pointed it at an entry whose
-- CURRENT protection is 4, which is what every .sprx text segment and sigtramp_alias are.
--
-- If 548 accepts prot 3 there, execute-only module text becomes readable, which no probe in this
-- tree has ever managed (377a: a read of a p=0x1 .rodata region kills past pcall; 378a: XO text is
-- a hard wall). And if it accepts prot 3 on text, the same call can write it.
--
-- [0] 674, collect every entry with prot == 4
-- [A] the list, plus the first value at libSceSsl.sprx's text if it is in the list
-- [B] for each prot-4 entry except libkernel: try prot 3, then 2, then 1 on the first one only.
--     Stop at the first success and read 16 bytes from the now-readable page.
-- [C] 547 on whatever changed, to confirm the vm_map really moved
--
-- -- prior art:
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202102.txt (the prot matrix)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (which entries are prot 4)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (device windows moved)
--   docs/DEAD_ENDS.md: "Module data is unreadable" (377a/378a)

print("=== PROBE 1485a: PROTECT AN EXECUTE-ONLY ENTRY ===")

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

local sc674 = mk(674)
local cnt = memory.alloc(0x10)
local CAP = 512
local buf = memory.alloc(CAP * 72 + 0x1000)
for i = 0, CAP * 72, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(CAP), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[0] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then print("=== PROBE 1485a INCOMPLETE ===") return end
if nrec > CAP then nrec = CAP end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end
local function nameat(b)
    local s = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        s = s .. string.char(ch)
    end
    return s
end

local prot4 = {}
for i = 0, nrec - 1 do
    local b = buf + i * 72
    local s = u64at(b, 0x00)
    local e = u64at(b, 0x08)
    local pr = N(memory.read_dword(b + 0x18))
    if pr == 4 then
        prot4[#prot4 + 1] = { s = s, e = e, nm = nameat(b) }
    end
end

print("")
print(string.format("--- [A] %d execute-only entries ---", #prot4))
for i = 1, math.min(#prot4, 40) do
    local p = prot4[i]
    print(string.format("    #%-2d 0x%-10X-0x%-10X len 0x%-7X %s", i, p.s, p.e, p.e - p.s, p.nm))
end
if #prot4 == 0 then
    print("[A] none - nothing to test")
    print("=== PROBE 1485a COMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] the protect
local sc548 = mk(548)
local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)

local function protect(addr, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

local function rd16(addr)
    local t = {}
    for i = 0, 15 do
        local v = nil
        pcall(function() v = N(memory.read_byte(addr + i)) end)
        if v == nil then t[#t + 1] = "??" else t[#t + 1] = string.format("%02X", v) end
    end
    return table.concat(t, " ")
end

local function q547(addr)
    local r = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(r + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(r), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return "547 rv=" .. tostring(ok and rv or "EXC") end
    return string.format("547 prot=%d start=0x%X", N(memory.read_dword(r + 0x10)), u64at(r, 0x00))
end

print("")
print("--- [B] protect attempts ---")
local winner = nil
local tried = 0
for i = 1, #prot4 do
    local p = prot4[i]
    local skip = false
    if p.nm:find("libkernel") then skip = true end
    if p.e - p.s < 0x4000 then skip = true end
    if not skip then
        tried = tried + 1
        local span = 0x4000
        if p.e - p.s < span then span = p.e - p.s end
        print(string.format("    TRY %-24s 0x%X len 0x%X prot 3", p.nm, p.s, span))
        local rv, dn = protect(p.s, span, 3)
        if rv == "EXC" then
            print("      -> EXC")
        elseif rv == 0 then
            print(string.format("      -> 0 processed=%d  *** ACCEPTED ***", dn))
            winner = p
            break
        else
            print(string.format("      -> %s %s processed=%d", tostring(rv), es(), dn))
        end
    end
    if tried >= 8 then break end
end

if winner == nil then
    print("")
    print("[B] no execute-only entry accepted prot 3")
    -- one more shape: does a prot-2 or prot-1 request behave differently on the first candidate?
    local p = prot4[1]
    if p and not p.nm:find("libkernel") and p.e - p.s >= 0x4000 then
        for _, pr in ipairs({2, 1}) do
            print(string.format("    TRY %s prot %d", p.nm, pr))
            local rv, dn = protect(p.s, 0x4000, pr)
            print(string.format("      -> %s %s", tostring(rv), rv == -1 and es() or ""))
        end
    end
    print("")
    local final0 = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("final canary: pid=%d (started %d)", final0, PID))
    print("=== PROBE 1485a COMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [C] read what we just freed
print("")
print(string.format("--- [C] %s is now prot 3 ---", winner.nm))
print("    " .. q547(winner.s))
print("    first 16 bytes: " .. rd16(winner.s))
print("    +0x1000:        " .. rd16(winner.s + 0x1000))
print("    " .. q547(winner.s))

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1485a COMPLETE ===")
