-- CRASH_CLASS: MODERATE
-- PROBE 114a: GPU mmap aliasing + munmap race + stale TLB attack
--
-- Context: GPU mmap via sys 477 (MAP_ANON|MAP_PRIVATE, fd=-1) gives us
-- R/W pages that are GPU-backed (unified GDDR6). The kernel handles
-- device-backed pages differently than anonymous memory.
--
-- CREATIVE ANGLE (PS3/PS4 hypervisor bypass thinking):
-- 1. Map GPU region at addr A
-- 2. Map ANOTHER GPU region at addr B (different VA, same backing?)
-- 3. munmap A while B still alive — does kernel properly invalidate?
-- 4. Remap something else at A's old address — type confusion?
-- 5. Test if writes to B affect the new mapping at A (stale physical page)
--
-- Also: mmap with MAP_FIXED to force overlapping regions, test if kernel
-- coalesces or creates separate vm_entry objects.
--
-- Section A: Double GPU mmap + cross-region write test
-- Section B: munmap + remap race (unmap region, immediately remap)
-- Section C: MAP_FIXED overlapping regions
-- Section D: GPU mmap + anonymous mmap at adjacent addresses
-- Section E: Rapid mmap/munmap cycle with sys 624 counter

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 114a: GPU MMAP ALIASING + RACE ===")
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

local sc477  = make_syscall(477)  -- mmap
local sc73   = make_syscall(73)   -- munmap
local sc624  = make_syscall(624)  -- VM op counter
local sc74   = make_syscall(74)   -- mprotect
local sc75   = make_syscall(75)   -- madvise
local sc203  = make_syscall(203)  -- mlock
local sc204  = make_syscall(204)  -- munlock

local PAGE_SIZE = 0x4000  -- 16KB
local GPU_FLAGS = 0x33    -- MAP_ANON|MAP_PRIVATE|MAP_...
local GPU_FDFLAGS = 0x1002  -- MAP_ANON flag + ...
local GPU_FD = 0xFFFFFFFF

local function gpu_mmap(npages)
    local ok, ret = pcall(function()
        return sc477(uint64(0), uint64(npages * PAGE_SIZE), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        if l ~= 0xFFFFFFFF or h ~= 0xFFFFFFFF then
            return ret
        end
    end
    return nil
end

local function gpu_mmap_fixed(addr, npages)
    local ok, ret = pcall(function()
        return sc477(addr, uint64(npages * PAGE_SIZE), uint64(0x33),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
        -- 0x1012 = MAP_FIXED | MAP_ANON | MAP_PRIVATE
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        if l ~= 0xFFFFFFFF or h ~= 0xFFFFFFFF then
            return ret
        end
    end
    return nil
end

local function do_munmap(addr, size)
    local ok, ret = pcall(function()
        return sc73(addr, uint64(size))
    end)
    return ok and to_num(ret) == 0
end


-- ======================================================
-- SECTION A: Double GPU mmap + cross-region write test
-- ======================================================
if TEST_SECTION == "A" then
    print("--- SECTION A: Double GPU mmap aliasing test ---")
    print("")

    -- Allocate two separate GPU regions
    local region_a = gpu_mmap(8)
    local region_b = gpu_mmap(8)

    if not region_a or not region_b then
        print("[A] Failed to allocate GPU regions")
        print("=== PROBE 114a COMPLETE ===")
        return
    end

    local ah, al = get_hi_lo(region_a)
    local bh, bl = get_hi_lo(region_b)
    print(string.format("[A] Region A: 0x%08X_%08X (8 pages)", ah, al))
    print(string.format("[A] Region B: 0x%08X_%08X (8 pages)", bh, bl))
    print(string.format("[A] Separation: 0x%X bytes", bl - al))

    -- A1: Write distinct sentinels to each region
    print("")
    print("[A1] Writing sentinels: A=0xAAAAxxxx, B=0xBBBBxxxx")
    for pg = 0, 7 do
        safe_wd(region_a + pg * PAGE_SIZE, 0xAAAA0000 + pg)
        safe_wd(region_b + pg * PAGE_SIZE, 0xBBBB0000 + pg)
    end

    -- Verify isolation
    local shared = false
    for pg = 0, 7 do
        local va = safe_rd(region_a + pg * PAGE_SIZE)
        local vb = safe_rd(region_b + pg * PAGE_SIZE)
        if va ~= 0xAAAA0000 + pg then
            print(string.format("  *** A[%d] CHANGED: expected 0x%08X got 0x%08X ***",
                pg, 0xAAAA0000 + pg, va or 0))
            shared = true
        end
        if vb ~= 0xBBBB0000 + pg then
            print(string.format("  *** B[%d] CHANGED: expected 0x%08X got 0x%08X ***",
                pg, 0xBBBB0000 + pg, vb or 0))
            shared = true
        end
    end
    if not shared then
        print("  Regions properly isolated (expected)")
    end

    -- A2: Check adjacency — is there unmapped gap or guard page?
    print("")
    print("[A2] Adjacency probe (read between regions):")
    local end_a = region_a + 8 * PAGE_SIZE
    local gap_size = bl - (al + 8 * PAGE_SIZE)
    print(string.format("  Region A end: 0x%X, Region B start: 0x%X, gap: 0x%X",
        al + 8 * PAGE_SIZE, bl, gap_size))

    if gap_size == 0 then
        print("  *** REGIONS ARE ADJACENT — NO GUARD PAGE ***")
        -- This is the gold case: adjacent GPU regions = heap R/W across boundary
    elseif gap_size > 0 and gap_size <= 4 * PAGE_SIZE then
        print("  Small gap — probe for guard pages")
        local gap_readable = safe_rd(end_a)
        print(string.format("  Read at gap start: %s", gap_readable and string.format("0x%08X", gap_readable) or "UNREADABLE"))
    end

    -- A3: Allocate many GPU regions, measure spacing
    print("")
    print("[A3] GPU region spacing analysis (10 regions):")
    local regions = {region_a, region_b}
    for i = 3, 10 do
        local r = gpu_mmap(4)
        if r then
            regions[#regions + 1] = r
        end
    end

    -- Sort by address
    for i = 1, #regions do
        for j = i + 1, #regions do
            local ih, il = get_hi_lo(regions[i])
            local jh, jl = get_hi_lo(regions[j])
            if il > jl then
                regions[i], regions[j] = regions[j], regions[i]
            end
        end
    end

    print(string.format("  Allocated %d regions:", #regions))
    for i = 1, #regions do
        local rh, rl = get_hi_lo(regions[i])
        local gap = ""
        if i > 1 then
            local ph, pl = get_hi_lo(regions[i-1])
            local g = rl - pl
            gap = string.format(" (gap from prev: 0x%X)", g)
        end
        print(string.format("  [%d] 0x%08X_%08X%s", i, rh, rl, gap))
    end

    -- Check for any zero gaps (adjacent)
    local adjacent_count = 0
    for i = 2, #regions do
        local ph, pl = get_hi_lo(regions[i-1])
        local ch, cl = get_hi_lo(regions[i])
        -- prev region is 4 pages (first two are 8)
        local prev_size = (i <= 2) and (8 * PAGE_SIZE) or (4 * PAGE_SIZE)
        if cl == pl + prev_size then
            adjacent_count = adjacent_count + 1
        end
    end
    if adjacent_count > 0 then
        print(string.format("  *** %d ADJACENT REGION PAIRS (no guard pages) ***", adjacent_count))
    end


-- ======================================================
-- SECTION B: munmap + remap race
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: munmap + remap race ---")
    print("")

    local region = gpu_mmap(16)
    if not region then
        print("[B] GPU mmap failed")
        print("=== PROBE 114a COMPLETE ===")
        return
    end

    local rh, rl = get_hi_lo(region)
    print(string.format("[B] GPU region: 0x%08X_%08X (16 pages)", rh, rl))

    -- Write sentinels
    for pg = 0, 15 do
        safe_wd(region + pg * PAGE_SIZE, 0xFACE0000 + pg)
    end

    -- B1: munmap first half, keep second half
    print("")
    print("[B1] munmap first 8 pages, keep last 8:")
    local unmap_ok = do_munmap(region, 8 * PAGE_SIZE)
    print(string.format("  munmap(first 8 pages): %s", tostring(unmap_ok)))

    -- Can we still read the second half?
    local second_half = region + 8 * PAGE_SIZE
    local still_alive = safe_rd(second_half)
    print(string.format("  Read second half[0]: %s (expected 0xFACE0008)",
        still_alive and string.format("0x%08X", still_alive) or "UNREADABLE"))

    -- Can we read the unmapped first half? (should fail)
    local dead_read = safe_rd(region)
    print(string.format("  Read unmapped first half: %s (should be nil/crash)",
        dead_read and string.format("0x%08X", dead_read) or "UNREADABLE (expected)"))

    -- B2: mmap something NEW at the old address with MAP_FIXED
    print("")
    print("[B2] MAP_FIXED remap at unmapped address:")
    local remap = gpu_mmap_fixed(region, 8)
    if remap then
        local rmh, rml = get_hi_lo(remap)
        print(string.format("  Remapped at: 0x%08X_%08X", rmh, rml))

        -- Write new sentinel
        safe_wd(remap, 0xDEAD0000)
        local new_val = safe_rd(remap)
        print(string.format("  New region[0] = 0x%08X (wrote 0xDEAD0000)", new_val or 0))

        -- Does the second half still work?
        local second_check = safe_rd(second_half)
        print(string.format("  Second half[0] still = %s",
            second_check and string.format("0x%08X", second_check) or "UNREADABLE"))

        -- CRITICAL: check if writing to new region affects second half
        -- (would indicate shared physical backing or TLB confusion)
        safe_wd(remap + 7 * PAGE_SIZE, 0xCROSS01)
        local cross_check = safe_rd(second_half)
        print(string.format("  After writing remap[end]: second_half[0] = %s",
            cross_check and string.format("0x%08X", cross_check) or "UNREADABLE"))
        if cross_check and cross_check ~= 0xFACE0008 then
            print("  *** CROSS-REGION WRITE DETECTED — STALE MAPPING ***")
        end
    else
        print("  MAP_FIXED remap failed (kernel may not support it for GPU)")
    end

    -- B3: Rapid unmap-remap cycle
    print("")
    print("[B3] Rapid unmap-remap cycle (10 rounds):")
    for round = 1, 10 do
        local r = gpu_mmap(4)
        if r then
            safe_wd(r, 0xCYCLE000 + round)
            local before = safe_rd(r)
            do_munmap(r, 4 * PAGE_SIZE)
            -- Immediately try to read the unmapped page
            local after = safe_rd(r)
            if after then
                print(string.format("  Round %d: STALE READ 0x%08X after munmap!", round, after))
            else
                if round <= 3 or round == 10 then
                    print(string.format("  Round %d: properly unmapped", round))
                end
            end
        end
    end


-- ======================================================
-- SECTION C: MAP_FIXED overlapping regions
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: MAP_FIXED overlap test ---")
    print("")

    -- Allocate a large region
    local base = gpu_mmap(32)
    if not base then
        print("[C] GPU mmap failed")
        print("=== PROBE 114a COMPLETE ===")
        return
    end
    local bh, bl = get_hi_lo(base)
    print(string.format("[C] Base region: 0x%08X_%08X (32 pages)", bh, bl))

    -- Write sentinels across all pages
    for pg = 0, 31 do
        safe_wd(base + pg * PAGE_SIZE, 0xBASE0000 + pg)
    end

    -- C1: MAP_FIXED in the middle of existing region
    print("")
    print("[C1] MAP_FIXED inside existing region (pages 8-15):")
    local mid = base + 8 * PAGE_SIZE
    local overlap = gpu_mmap_fixed(mid, 8)
    if overlap then
        local oh, ol = get_hi_lo(overlap)
        print(string.format("  Overlapped at: 0x%08X_%08X", oh, ol))

        -- Check what happened to surrounding pages
        for pg = 0, 31 do
            local v = safe_rd(base + pg * PAGE_SIZE)
            local expected = 0xBASE0000 + pg
            if not v then
                print(string.format("  page %d: UNREADABLE (was 0x%08X)", pg, expected))
            elseif v ~= expected then
                print(string.format("  page %d: 0x%08X (expected 0x%08X) *** CHANGED ***", pg, v, expected))
            end
        end

        -- Write to overlapped region
        safe_wd(overlap, 0xOVER0000)
        local ov = safe_rd(overlap)
        local orig = safe_rd(base + 8 * PAGE_SIZE)
        print(string.format("  overlap[0] = 0x%08X, base[8] = 0x%08X", ov or 0, orig or 0))
        if ov and orig and ov == orig then
            print("  Same address — MAP_FIXED replaced the original mapping")
        end
    else
        print("  MAP_FIXED overlap FAILED (kernel rejected)")
    end

    -- C2: MAP_FIXED anonymous over GPU
    print("")
    print("[C2] MAP_FIXED anonymous mmap over GPU pages (pages 16-19):")
    local anon_over_gpu = nil
    local ok_anon, ret_anon = pcall(function()
        return sc477(base + 16 * PAGE_SIZE, uint64(4 * PAGE_SIZE), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
        -- 0x1012 = MAP_FIXED | MAP_ANON | MAP_PRIVATE (without GPU flags)
    end)
    if ok_anon then
        local ah, al = get_hi_lo(ret_anon)
        if al ~= 0xFFFFFFFF then
            anon_over_gpu = ret_anon
            print(string.format("  Anonymous over GPU at: 0x%08X_%08X", ah, al))

            -- Read: is it zeroed (new anonymous) or GPU sentinel?
            local new_val = safe_rd(anon_over_gpu)
            print(string.format("  Value: 0x%08X (GPU sentinel was 0x%08X)",
                new_val or 0, 0xBASE0010))
            if new_val == 0 then
                print("  Zeroed — anonymous mapping replaced GPU backing")
            elseif new_val == 0xBASE0010 then
                print("  *** STILL GPU SENTINEL — backing unchanged ***")
            end

            -- Check surrounding GPU pages
            local pg15 = safe_rd(base + 15 * PAGE_SIZE)
            local pg20 = safe_rd(base + 20 * PAGE_SIZE)
            print(string.format("  Neighbor check: page15=0x%08X page20=0x%08X",
                pg15 or 0, pg20 or 0))
        else
            print("  MAP_FIXED anonymous over GPU failed")
        end
    else
        print("  PCALL failed for anonymous over GPU")
    end


-- ======================================================
-- SECTION D: GPU + anonymous adjacent allocation
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: GPU + anonymous adjacent allocation ---")
    print("")

    -- Allocate GPU region
    local gpu = gpu_mmap(16)
    if not gpu then
        print("[D] GPU mmap failed")
        print("=== PROBE 114a COMPLETE ===")
        return
    end
    local gh, gl = get_hi_lo(gpu)
    print(string.format("[D] GPU region: 0x%08X_%08X", gh, gl))

    -- Try anonymous mmap immediately after
    print("")
    print("[D1] Anonymous mmap after GPU (kernel chooses address):")
    local anon = nil
    local ok_a, ret_a = pcall(function()
        return sc477(uint64(0), uint64(8 * PAGE_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok_a then
        local ah, al = get_hi_lo(ret_a)
        if al ~= 0xFFFFFFFF then
            anon = ret_a
            print(string.format("  Anonymous at: 0x%08X_%08X", ah, al))
            local gap = al - (gl + 16 * PAGE_SIZE)
            print(string.format("  Gap from GPU end: 0x%X (%d pages)", gap, gap / PAGE_SIZE))
            if gap == 0 then
                print("  *** ADJACENT TO GPU — potential cross-type boundary ***")
            end
        end
    end

    -- D2: GPU write + read from adjacent anonymous
    if gpu and anon then
        print("")
        print("[D2] Cross-type boundary write test:")
        -- Write to last GPU page
        local last_gpu_page = gpu + 15 * PAGE_SIZE
        safe_wd(last_gpu_page, 0xGPU_LAST)
        -- Write to first anon page
        safe_wd(anon, 0xANON_1ST)

        -- Try writing past GPU boundary
        local past_gpu = gpu + 16 * PAGE_SIZE
        local ok_past = safe_wd(past_gpu, 0xPAST_GPU)
        local read_past = safe_rd(past_gpu)
        print(string.format("  Write past GPU end: ok=%s read=0x%08X",
            tostring(ok_past), read_past or 0))

        local ah2, al2 = get_hi_lo(anon)
        if al2 == gl + 16 * PAGE_SIZE then
            -- Adjacent! Check if GPU write affected anon
            local anon_val = safe_rd(anon)
            print(string.format("  Anon[0] = 0x%08X (expected 0xANON_1ST)", anon_val or 0))
        end
    end

    -- D3: Sys 624 counter deltas for GPU vs anon mmap
    print("")
    print("[D3] sys 624 counter: GPU vs anonymous mmap:")
    local sc624_fn = make_syscall(624)

    local c1 = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    local gpu2 = gpu_mmap(4)
    local c2 = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil

    local c3 = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    local ok_a2, anon2 = pcall(function()
        return sc477(uint64(0), uint64(4 * PAGE_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local c4 = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil

    print(string.format("  GPU mmap delta: %s", (c1 and c2) and tostring(c2 - c1) or "?"))
    print(string.format("  Anon mmap delta: %s", (c3 and c4) and tostring(c4 - c3) or "?"))


-- ======================================================
-- SECTION E: Rapid mmap/munmap cycle + counter
-- ======================================================
elseif TEST_SECTION == "E" then
    print("--- SECTION E: Rapid mmap/munmap + sys 624 oracle ---")
    print("")

    local sc624_fn = make_syscall(624)
    local c_start = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil

    -- E1: 50 rounds of mmap+munmap
    print("[E1] 50 rounds mmap+munmap (4 pages each):")
    local cycle_ok = 0
    local cycle_fail = 0
    for i = 1, 50 do
        local r = gpu_mmap(4)
        if r then
            safe_wd(r, 0xCYCL0000 + i)
            local unmap = do_munmap(r, 4 * PAGE_SIZE)
            if unmap then cycle_ok = cycle_ok + 1 else cycle_fail = cycle_fail + 1 end
        else
            cycle_fail = cycle_fail + 1
        end
    end
    print(string.format("  Completed: %d ok, %d fail", cycle_ok, cycle_fail))

    local c_after_cycles = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    if c_start and c_after_cycles then
        local delta = c_after_cycles - c_start
        print(string.format("  sys 624 delta: %d (%.1f per cycle)", delta, delta / 50))
    end

    -- E2: mmap without munmap (accumulate)
    print("")
    print("[E2] 50 mmap without munmap (leak test):")
    local c_before_leak = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    local leaked = {}
    for i = 1, 50 do
        local r = gpu_mmap(1)
        if r then leaked[#leaked + 1] = r end
    end
    local c_after_leak = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    print(string.format("  Allocated %d single-page regions", #leaked))
    if c_before_leak and c_after_leak then
        print(string.format("  sys 624 delta: %d (%.1f per alloc)",
            c_after_leak - c_before_leak, (c_after_leak - c_before_leak) / 50))
    end

    -- E3: Now munmap all at once
    print("")
    print("[E3] munmap all %d regions:")
    local c_before_free = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    local free_ok = 0
    for _, r in ipairs(leaked) do
        if do_munmap(r, PAGE_SIZE) then free_ok = free_ok + 1 end
    end
    local c_after_free = pcall(function() return to_num(sc624_fn()) end) and to_num(sc624_fn()) or nil
    print(string.format("  Freed %d/%d regions", free_ok, #leaked))
    if c_before_free and c_after_free then
        print(string.format("  sys 624 delta: %d (%.1f per free)",
            c_after_free - c_before_free, (c_after_free - c_before_free) / #leaked))
    end

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 114a COMPLETE ===")
