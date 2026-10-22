-- Isolated TEST_SECTION=C live run.
TEST_SECTION = "C"
-- CRASH_CLASS: MODERATE
-- PROBE 95a: AIO subsystem — init, submit, poll, cancel, delete
--
-- Context: The "AIO hard wall" was an n=1 generalization. Only sys 661 kills.
-- Deep handler analysis reveals 662-670 are separate real syscalls:
--   670: __aio_init   — AIO context initialization (NO priv_check visible)
--   669: _aio_submit_cmd — AIO read/write submission (creates type-0x160 handles)
--   664: _aio_multi_poll — batch poll (modifies kernel state on first observation)
--   663: _aio_multi_wait — batch wait with timeout
--   662: _aio_multi_delete — batch delete
--   666: _aio_multi_cancel — batch cancel
--
-- Handler 669 publishes a handle ID to userspace BEFORE completing queue setup.
-- Handler 670 has a partial-update bug: invalid group 2 data can error out AFTER
-- group 1 values were already written (no rollback).
--
-- This probe tests the full AIO lifecycle without touching sys 661.
--
-- Section A: sys 670 AIO init (null config = default, then with struct)
-- Section B: sys 669 AIO submit read request (need initialized context + valid fd)
-- Section C: sys 664/662/666 poll/delete/cancel on submitted IDs
-- Section D: sys 670 partial-update bug — trigger inconsistent context state

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 95a: AIO SUBSYSTEM ===")
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

local sc662 = make_syscall(662)  -- aio_multi_delete
local sc663 = make_syscall(663)  -- aio_multi_wait
local sc664 = make_syscall(664)  -- aio_multi_poll
local sc666 = make_syscall(666)  -- aio_multi_cancel
local sc669 = make_syscall(669)  -- aio_submit_cmd
local sc670 = make_syscall(670)  -- aio_init
local sc20  = make_syscall(20)   -- getpid

if TEST_SECTION == "A" then
    print("--- Section A: sys 670 AIO init ---")
    print("")

    -- Test 1: null config pointer = default initialization
    -- Args: (config_ptr=NULL, config_len=0, reserved=0, reserved=0)
    print("[A1] sys 670 with null config (default init):")
    local ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local r = to_num(rv)
        if r == 0 then
            print("  *** SUCCESS — AIO CONTEXT INITIALIZED ***")
        elseif r == 16 then
            print("  ret=16: context already initialized (expected for fallback)")
        elseif r == 22 then
            print("  ret=22: EINVAL (reserved args?)")
        else
            print("  ret=" .. r)
        end
    end
    print("")

    -- Test 2: call again (should return 0 or 16 if already init)
    print("[A2] sys 670 again (test re-init):")
    ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    -- Test 3: with config struct (0x3c = 60 bytes)
    -- Three groups of 5 uint32 each = 60 bytes
    -- Each group: scan_limit(0-128), age_limit(0-128), split_mode(0/1),
    --             chunk_size(1-0x1000000), other_chunk_size(1-0x1000000)
    print("[A3] sys 670 with valid 0x3c config (mode=0 for all groups):")
    local cfg = memory.alloc(0x40)
    for i = 0, 59 do
        pcall(function() memory.write_byte(cfg + i, 0) end)
    end
    -- Group 0: scan=32, age=32, mode=0 (sizes ignored in mode 0)
    safe_wd(cfg + 0, 32)
    safe_wd(cfg + 4, 32)
    safe_wd(cfg + 8, 0)
    safe_wd(cfg + 12, 0)
    safe_wd(cfg + 16, 0)
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

    ok, rv = pcall(function()
        return sc670(uint64(cfg), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local r = to_num(rv)
        if r == 0 then print("  *** CONFIG ACCEPTED ***")
        elseif r == 16 then print("  context already init (config path skipped)")
        elseif r == 22 then print("  EINVAL — config rejected or already init")
        end
    end
    print("")

    -- Test 4: with mode=1 config (split mode, needs valid chunk sizes)
    print("[A4] sys 670 with mode=1 config (split chunking):")
    local cfg2 = memory.alloc(0x40)
    for i = 0, 59 do
        pcall(function() memory.write_byte(cfg2 + i, 0) end)
    end
    safe_wd(cfg2 + 0, 32)       -- scan_limit
    safe_wd(cfg2 + 4, 32)       -- age_limit
    safe_wd(cfg2 + 8, 1)        -- split_mode=1
    safe_wd(cfg2 + 12, 0x100000) -- chunk_size (1MB)
    safe_wd(cfg2 + 16, 0x100000) -- other_chunk_size (1MB)
    safe_wd(cfg2 + 20, 32)
    safe_wd(cfg2 + 24, 32)
    safe_wd(cfg2 + 28, 1)
    safe_wd(cfg2 + 32, 0x100000)
    safe_wd(cfg2 + 36, 0x100000)
    safe_wd(cfg2 + 40, 32)
    safe_wd(cfg2 + 44, 32)
    safe_wd(cfg2 + 48, 0)       -- group 2 mode=0
    safe_wd(cfg2 + 52, 0)
    safe_wd(cfg2 + 56, 0)

    ok, rv = pcall(function()
        return sc670(uint64(cfg2), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    -- Test 5: wrong reserved args (should fail)
    print("[A5] sys 670 with nonzero reserved arg2 (expect EINVAL):")
    ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0), uint64(1), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("[A6] sys 670 with wrong config length:")
    ok, rv = pcall(function()
        return sc670(uint64(cfg), uint64(0x20), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 669 AIO submit ---")
    print("")

    -- First: ensure AIO context is initialized
    print("[B0] Init AIO context:")
    local ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("  init ret=" .. (ok and fmt(rv) or "FAIL"))
    print("")

    -- We need a valid file descriptor. Let's use the socket we have
    -- or create a pipe. The Lua loader already has an open socket.
    -- Use mmap to get an fd (sys 477 returns an fd for /dev/zero style)
    -- Actually, let's create a pipe via make_syscall(42) — but that's dead.
    -- Let's try to open /dev/null via sys 5 (open)
    print("[B1] Creating fd via socket (sys 97 = socket):")
    local sc97 = make_syscall(97)  -- socket
    ok, rv = pcall(function()
        return sc97(uint64(2), uint64(1), uint64(0))  -- AF_INET, SOCK_STREAM, 0
    end)
    local sock_fd = -1
    if ok then
        sock_fd = to_num(rv)
        print("  socket fd=" .. sock_fd)
    else
        print("  socket FAIL")
    end

    -- Also try AF_UNIX socketpair for a readable fd
    print("[B2] Creating socketpair (sys 135):")
    local sc135 = make_syscall(135)  -- socketpair
    local sv = memory.alloc(16)
    safe_wd(sv, 0xFFFFFFFF)
    safe_wd(sv + 4, 0xFFFFFFFF)
    ok, rv = pcall(function()
        return sc135(uint64(1), uint64(1), uint64(0), uint64(sv))
    end)
    local sp0, sp1 = -1, -1
    if ok and to_num(rv) == 0 then
        sp0 = safe_rd(sv) or -1
        sp1 = safe_rd(sv + 4) or -1
        print("  socketpair: fd0=" .. sp0 .. " fd1=" .. sp1)
    else
        print("  socketpair ret=" .. (ok and fmt(rv) or "FAIL"))
    end
    print("")

    -- Build a request descriptor (0x28 = 40 bytes)
    -- +0x00: I/O offset (64-bit signed) = 0
    -- +0x08: byte count (64-bit) = 64
    -- +0x10: data pointer (64-bit) = user buffer
    -- +0x18: result pointer (64-bit) = 0 (optional)
    -- +0x20: file descriptor (32-bit)
    local data_buf = memory.alloc(256)
    local result_buf = memory.alloc(64)
    local req = memory.alloc(0x30)
    local out_ids = memory.alloc(32)

    -- Fill data buffer with pattern
    for i = 0, 63 do
        pcall(function() memory.write_byte(data_buf + i, 0x41 + (i % 26)) end)
    end

    -- Choose best fd
    local test_fd = sp0
    if test_fd < 0 then test_fd = sock_fd end
    if test_fd < 0 then test_fd = 3 end  -- guess a low fd
    print("[B3] Using fd=" .. test_fd .. " for AIO request")

    -- Build request descriptor
    safe_wq(req + 0, uint64(0))          -- offset = 0
    safe_wq(req + 8, uint64(64))         -- count = 64 bytes
    safe_wq(req + 0x10, uint64(data_buf)) -- data pointer
    safe_wq(req + 0x18, uint64(0))       -- result pointer (optional)
    safe_wd(req + 0x20, test_fd)         -- file descriptor
    safe_wd(req + 0x24, 0)              -- padding

    -- Submit AIO write request: cmd=2 (write), count=1, class=1
    print("[B4] sys 669 submit WRITE: cmd=2, count=1, class=1:")
    safe_wd(out_ids, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc669(uint64(2), uint64(req), uint64(1), uint64(1), uint64(out_ids))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local r = to_num(rv)
        local id = safe_rd(out_ids)
        print("  out_id=" .. (id and string.format("0x%08X", id) or "nil"))
        if r == 0 then
            print("  *** AIO WRITE SUBMITTED ***")
            print("  handle id: " .. (id and string.format("0x%08X", id) or "nil"))
        elseif r == 22 then
            print("  EINVAL — check cmd/count/class args")
        elseif r == 35 then
            print("  EAGAIN — slot reservation failed")
        end
    end
    print("")

    -- Submit AIO read request: cmd=1 (read)
    print("[B5] sys 669 submit READ: cmd=1, count=1, class=1:")
    local req2 = memory.alloc(0x30)
    local read_buf = memory.alloc(256)
    safe_wq(req2 + 0, uint64(0))
    safe_wq(req2 + 8, uint64(64))
    safe_wq(req2 + 0x10, uint64(read_buf))
    safe_wq(req2 + 0x18, uint64(0))
    safe_wd(req2 + 0x20, test_fd)
    safe_wd(req2 + 0x24, 0)

    local out_ids2 = memory.alloc(32)
    safe_wd(out_ids2, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc669(uint64(1), uint64(req2), uint64(1), uint64(1), uint64(out_ids2))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local id = safe_rd(out_ids2)
        print("  out_id=" .. (id and string.format("0x%08X", id) or "nil"))
        if to_num(rv) == 0 then print("  *** AIO READ SUBMITTED ***") end
    end
    print("")

    -- Submit with flag 0x1000 (per-item IDs mode)
    print("[B6] sys 669 submit with flag 0x1000 (per-item IDs):")
    local out_ids3 = memory.alloc(32)
    safe_wd(out_ids3, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc669(uint64(0x1001), uint64(req), uint64(1), uint64(1), uint64(out_ids3))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local id = safe_rd(out_ids3)
        print("  out_id=" .. (id and string.format("0x%08X", id) or "nil"))
    end
    print("")

    -- Test with count=0 (should fail, handler requires 1-128)
    print("[B7] sys 669 with count=0 (expect EINVAL):")
    ok, rv = pcall(function()
        return sc669(uint64(1), uint64(req), uint64(0), uint64(1), uint64(out_ids))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    -- Test with invalid class (0 or 4)
    print("[B8] sys 669 with class=0 (expect EINVAL):")
    ok, rv = pcall(function()
        return sc669(uint64(1), uint64(req), uint64(1), uint64(0), uint64(out_ids))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("[B9] sys 669 with class=4 (expect EINVAL):")
    ok, rv = pcall(function()
        return sc669(uint64(1), uint64(req), uint64(1), uint64(4), uint64(out_ids))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: sys 664 poll / 662 delete / 666 cancel ---")
    print("")

    -- Init context first
    print("[C0] Init AIO context:")
    local ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "FAIL"))

    -- Create a socket for the AIO fd
    local sc97 = make_syscall(97)
    ok, rv = pcall(function() return sc97(uint64(2), uint64(1), uint64(0)) end)
    local fd = ok and to_num(rv) or 3
    print("[C1] fd=" .. fd)

    -- Submit a request to get a handle
    local req = memory.alloc(0x30)
    local buf = memory.alloc(256)
    local out_ids = memory.alloc(32)
    safe_wq(req + 0, uint64(0))
    safe_wq(req + 8, uint64(64))
    safe_wq(req + 0x10, uint64(buf))
    safe_wq(req + 0x18, uint64(0))
    safe_wd(req + 0x20, fd)
    safe_wd(req + 0x24, 0)

    print("[C2] Submit AIO read to get handle:")
    safe_wd(out_ids, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc669(uint64(1), uint64(req), uint64(1), uint64(1), uint64(out_ids))
    end)
    local submitted_id = safe_rd(out_ids) or 0
    print("  submit ret=" .. (ok and fmt(rv) or "FAIL"))
    print("  id=" .. string.format("0x%08X", submitted_id))
    print("")

    -- Poll the submitted ID
    local id_arr = memory.alloc(16)
    local states = memory.alloc(16)
    safe_wd(id_arr, submitted_id)
    safe_wd(states, 0xDEADDEAD)

    print("[C3] sys 664 POLL (1 ID):")
    ok, rv = pcall(function()
        return sc664(uint64(id_arr), uint64(1), uint64(states))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    local state = safe_rd(states)
    if state then
        print("  state=" .. string.format("0x%08X", state))
        if state == 1 then print("  STATE=1: QUEUED")
        elseif state == 2 then print("  STATE=2: IN PROGRESS")
        elseif state == 3 then print("  STATE=3: COMPLETED")
        elseif state == 4 then print("  STATE=4: CANCELLED")
        end
    end
    print("")

    -- Poll again to check if state changes (first-observation behavior)
    print("[C4] sys 664 POLL again (check first-observation flag):")
    safe_wd(states, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc664(uint64(id_arr), uint64(1), uint64(states))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    state = safe_rd(states)
    if state then
        print("  state=" .. string.format("0x%08X", state))
        if state ~= 0xDEADDEAD and state >= 0x10000 then
            print("  *** FLAG 0x10000 SET = PREVIOUSLY OBSERVED ***")
        end
    end
    print("")

    -- Cancel the request
    print("[C5] sys 666 CANCEL:")
    local cancel_result = memory.alloc(16)
    safe_wd(cancel_result, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc666(uint64(id_arr), uint64(1), uint64(cancel_result))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    local cr = safe_rd(cancel_result)
    if cr then print("  result=" .. string.format("0x%08X", cr)) end
    print("")

    -- Delete the request
    print("[C6] sys 662 DELETE:")
    local del_result = memory.alloc(16)
    safe_wd(del_result, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc662(uint64(id_arr), uint64(1), uint64(del_result))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    local dr = safe_rd(del_result)
    if dr then print("  result=" .. string.format("0x%08X", dr)) end
    print("")

    -- Poll a bogus/deleted ID
    print("[C7] sys 664 POLL deleted ID:")
    safe_wd(states, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc664(uint64(id_arr), uint64(1), uint64(states))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    state = safe_rd(states)
    if state then print("  state=" .. string.format("0x%08X", state)) end
    print("")

    -- Poll with invalid ID (0 low bits)
    print("[C8] sys 664 POLL with id=0:")
    safe_wd(id_arr, 0)
    safe_wd(states, 0xDEADDEAD)
    ok, rv = pcall(function()
        return sc664(uint64(id_arr), uint64(1), uint64(states))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    state = safe_rd(states)
    if state then print("  state=" .. string.format("0x%08X", state)) end

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: sys 670 partial-update bug ---")
    print("")

    -- The handler writes config groups sequentially. If group 0 is valid
    -- but group 1 has invalid values, group 0 gets written but the handler
    -- returns EINVAL without rollback. The context stays uninitialized
    -- (ctx+0x4a0 != 1) but has custom policy values in the group 0 slots.

    -- This only works if context is not yet initialized (ctx+0x4a0 == 0)
    -- Since we may have already init'd, try on a fresh connection.

    print("[D1] Test partial-update: valid group 0, INVALID group 1:")
    local cfg = memory.alloc(0x40)
    for i = 0, 59 do
        pcall(function() memory.write_byte(cfg + i, 0) end)
    end
    -- Group 0: VALID (mode=0, limits within range)
    safe_wd(cfg + 0, 32)   -- scan_limit = 32
    safe_wd(cfg + 4, 32)   -- age_limit = 32
    safe_wd(cfg + 8, 0)    -- mode = 0
    safe_wd(cfg + 12, 0)
    safe_wd(cfg + 16, 0)
    -- Group 1: INVALID (scan_limit = 200 > 128)
    safe_wd(cfg + 20, 200)  -- scan_limit > 128 = INVALID
    safe_wd(cfg + 24, 32)
    safe_wd(cfg + 28, 0)
    safe_wd(cfg + 32, 0)
    safe_wd(cfg + 36, 0)
    -- Group 2: valid (doesn't matter, handler should reject at group 1)
    safe_wd(cfg + 40, 32)
    safe_wd(cfg + 44, 32)
    safe_wd(cfg + 48, 0)
    safe_wd(cfg + 52, 0)
    safe_wd(cfg + 56, 0)

    local ok, rv = pcall(function()
        return sc670(uint64(cfg), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok and to_num(rv) == 22 then
        print("  EINVAL as expected — but group 0 may already be written!")
    end
    print("")

    -- Now try null-config init — if the partial write left stale values
    -- but ctx+0x4a0 is still 0, this should still work
    print("[D2] Attempt null-config init after partial update:")
    ok, rv = pcall(function()
        return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    if ok then
        local r = to_num(rv)
        if r == 0 then
            print("  *** INIT SUCCEEDED AFTER PARTIAL UPDATE ***")
            print("  Context has group 0 custom values + default init")
        elseif r == 16 then
            print("  Already initialized (context was set by prior call)")
        end
    end
    print("")

    -- Test 3: invalid mode value (mode=2 should fail)
    print("[D3] Invalid split_mode=2 in group 0:")
    local cfg2 = memory.alloc(0x40)
    for i = 0, 59 do
        pcall(function() memory.write_byte(cfg2 + i, 0) end)
    end
    safe_wd(cfg2 + 0, 32)
    safe_wd(cfg2 + 4, 32)
    safe_wd(cfg2 + 8, 2)    -- mode=2 = INVALID
    safe_wd(cfg2 + 12, 0x100000)
    safe_wd(cfg2 + 16, 0x100000)
    -- rest doesn't matter
    safe_wd(cfg2 + 20, 32)
    safe_wd(cfg2 + 24, 32)
    safe_wd(cfg2 + 28, 0)
    safe_wd(cfg2 + 40, 32)
    safe_wd(cfg2 + 44, 32)
    safe_wd(cfg2 + 48, 0)

    ok, rv = pcall(function()
        return sc670(uint64(cfg2), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    -- Test 4: mode=1 with chunk_size=0 (below range, should fail)
    print("[D4] mode=1 with chunk_size=0 (underflow):")
    local cfg3 = memory.alloc(0x40)
    for i = 0, 59 do
        pcall(function() memory.write_byte(cfg3 + i, 0) end)
    end
    safe_wd(cfg3 + 0, 32)
    safe_wd(cfg3 + 4, 32)
    safe_wd(cfg3 + 8, 1)    -- mode=1
    safe_wd(cfg3 + 12, 0)   -- chunk_size=0 = INVALID (need 1-0x1000000)
    safe_wd(cfg3 + 16, 0x100000)
    safe_wd(cfg3 + 20, 32)
    safe_wd(cfg3 + 24, 32)
    safe_wd(cfg3 + 28, 0)
    safe_wd(cfg3 + 40, 32)
    safe_wd(cfg3 + 44, 32)
    safe_wd(cfg3 + 48, 0)

    ok, rv = pcall(function()
        return sc670(uint64(cfg3), uint64(0x3C), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 95a COMPLETE ===")
