-- CRASH_CLASS: LOW -- read-only, and only inside mappings 674 already lists. Every read is guarded;
-- a page that faults costs a relaunch but prints nothing false (each rung prints before it reads).
-- PROBE 1486a: the GPU pool, finally readable
--
-- Before 548 op 2 could rewrite a device entry's protection, every one of these mappings was
-- read-fatal (376a/380a). 1480c moved them to prot 3 and 1481c/1483a read the named driver windows,
-- which turned out to be the GPU register-init table and an unused shader body.
--
-- The part nobody has ever read is the pool itself: 674 lists
--   0x200F74000-0x210F70000  0xFFFC000   (256 MB)  prot 0x33
--   0x212DE4000-0x310F70000  0xFE18C000  (3.9 GB)  prot 0x33
-- plus seven 16 KiB prot-3 heads. 348a scanned the pool a fresh process mmaps through 477, which is a
-- different mapping; the pre-existing pool entries were never touched because touching them killed
-- the process.
--
-- [0] 674, find every entry whose prot is 0x33 and whose extent is larger than 1 MB
-- [A] protect each of them to prot 3 and report rv
-- [B] sample every 1 MiB rung of each: read 16 dwords at the rung start, count non-zero
-- [C] deep-dump the first eight non-zero rungs (256 bytes each) and look for kernel-shaped qwords
-- [D] the seven 16 KiB prot-3 heads, first 64 bytes each
--
-- -- prior art:
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the pool extents)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (the protect that works)
--   results/phase36_realargs/348a (348a dense scan of the 477-mapped pool: all zero)
--   results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt (named windows only)
--   docs/DEAD_ENDS.md: "GPU device mappings ... reading any of them kills the process"

print("=== PROBE 1486a: THE GPU POOL ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))
local KIMG = nil

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
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(CAP), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[0] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then print("=== PROBE 1486a INCOMPLETE ===") return end
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

local pool = {}
local heads = {}
for i = 0, nrec - 1 do
    local b = buf + i * 72
    local s = u64at(b, 0x00)
    local e = u64at(b, 0x08)
    local pr = N(memory.read_dword(b + 0x18))
    if pr == 0x33 and (e - s) > 0x100000 then
        pool[#pool + 1] = { s = s, e = e, nm = nameat(b) }
    elseif pr == 3 and (e - s) == 0x4000 then
        heads[#heads + 1] = { s = s, e = e }
    end
end
print(string.format("[0] pool entries %d, 16 KiB prot-3 heads %d", #pool, #heads))
for i = 1, #pool do
    print(string.format("    pool #%d 0x%X-0x%X len 0x%X %s",
        i, pool[i].s, pool[i].e, pool[i].e - pool[i].s, pool[i].nm))
end

-- ---------------------------------------------------------------- [A] protect
local sc548 = mk(548)
local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
local function protect(addr, len)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(3)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    local ok, rv = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC" end
    return rv
end

print("")
print("--- [A] protect the pool to prot 3 ---")
-- One call for the whole entry if the length is accepted; otherwise 64 KiB chunks up to 16 MB.
-- Everything below reads only up to p.prot_end, because a page that was never protected still faults.
local live = {}
for i = 1, #pool do
    local p = pool[i]
    local span = p.e - p.s
    print(string.format("    #%d 0x%X whole-entry protect len 0x%X", i, p.s, span))
    local rv = protect(p.s, span)
    if rv == 0 then
        p.prot_end = p.e
        print("      -> 0  WHOLE ENTRY")
        live[#live + 1] = p
    else
        print(string.format("      -> %s %s; falling back to 64 KiB chunks", tostring(rv), rv == -1 and es() or ""))
        local okc2 = 0
        local lim = math.min(span, 0x1000000)
        for off = 0, lim - 0x4000, 0x4000 do
            if protect(p.s + off, 0x4000) == 0 then okc2 = okc2 + 1 end
        end
        print(string.format("      64 KiB: %d of %d ok", okc2, lim / 0x4000))
        if okc2 > 0 then
            p.prot_end = p.s + lim
            live[#live + 1] = p
        end
    end
end

-- ---------------------------------------------------------------- [B] sample
print("")
print("--- [B] 1 MiB sampling ---")
local function rd(a) local v = nil pcall(function() v = N(memory.read_dword(a)) end) return v end

local rung_hits = {}
for i = 1, #live do
    local p = live[i]
    local nz, total = 0, 0
    local span = p.prot_end - p.s
    for off = 0, span - 0x1000, 0x100000 do
        total = total + 1
        local hit = false
        for k = 0, 0x3C, 4 do
            local v = rd(p.s + off + k)
            if v and v ~= 0 then hit = true break end
        end
        if hit then
            nz = nz + 1
            if #rung_hits < 40 then rung_hits[#rung_hits + 1] = p.s + off end
        end
    end
    print(string.format("    pool #%d 0x%X: %d of %d rungs non-zero", i, p.s, nz, total))
end

-- ---------------------------------------------------------------- [C] deep dump
print("")
print(string.format("--- [C] %d first non-zero rungs, 256 bytes each ---", #rung_hits))
for i = 1, math.min(#rung_hits, 8) do
    local a = rung_hits[i]
    print(string.format("    rung 0x%X", a))
    for row = 0, 0xF0, 0x10 do
        local t = {}
        for k = 0, 0x0C, 4 do
            local v = rd(a + row + k)
            t[#t + 1] = v and string.format("%08X", v) or "????????"
        end
        local any = false
        for _, s in ipairs(t) do if s ~= "00000000" then any = true end end
        if any then print(string.format("      +0x%02X  %s", row, table.concat(t, " "))) end
    end
end

-- ---------------------------------------------------------------- [D] heads
print("")
print("--- [D] 16 KiB prot-3 heads ---")
for i = 1, math.min(#heads, 12) do
    local t = {}
    for k = 0, 0x3C, 4 do
        local v = rd(heads[i].s + k)
        t[#t + 1] = v and string.format("%08X", v) or "????????"
    end
    print(string.format("    0x%X  %s", heads[i].s, table.concat(t, " ")))
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1486a COMPLETE ===")
