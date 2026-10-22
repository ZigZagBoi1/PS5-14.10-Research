-- CRASH_CLASS: LOW
-- PROBE 113a: Three untested handlers — sys 615 VM introspection, sys 559 alloc
--             context query, sys 636 table lookup read path
--
-- Context: These three handlers have ZERO probes despite having decompiled
-- analysis available. Each has a specific untested angle:
--
-- sys 615 (narg=3): VM Introspection — has priv_check for cross-process but
--   self-process may bypass. rdtsc-based iteration timeout creates TOCTOU.
--   Complex mmap sub-handler at offset 0x940.
--
-- sys 559 (narg=1): Scheduling class + memory map — arg=-1 returns current
--   process+0x5c0 value WITHOUT priv_check (query path). Args 0/1 need
--   priv_check(0x2ad). The returned value is the allocation context index.
--
-- sys 636 (narg=2): Privileged table lookup — write path has priv_check
--   (credential bit 62). BUT: "Read sub-handlers may lack priv_check."
--   Array of 16-byte records, capacity 512, with global count.
--
-- Section A: sys 559 query via arg -1 (FREE info leak of proc+0x5c0)
-- Section B: sys 615 VM introspection (self-process, various cmds)
-- Section C: sys 636 read-path probing (various arg combos)
-- Section D: Combined info leak cross-reference

local TEST_SECTION = TEST_SECTION or "D"

print("=== PROBE 113a: UNTESTED HANDLER TRIO ===")
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

local sc559 = make_syscall(559)
local sc615 = make_syscall(615)
local sc636 = make_syscall(636)
local sc20  = make_syscall(20)   -- getpid


-- ======================================================
-- SECTION A: sys 559 — free query path via arg -1
-- ======================================================
if TEST_SECTION == "A" then
    print("--- SECTION A: sys 559 allocation context query ---")
    print("")

    -- Get our PID for context
    local ok_pid, pid = pcall(function() return sc20() end)
    local pidv = ok_pid and to_num(pid) or 0
    print("[A] Our PID: " .. pidv)

    -- A1: Query current value with -1 (should bypass priv_check)
    print("")
    print("[A1] sys 559(-1) — query without priv_check:")
    local ok1, ret1 = pcall(function()
        return sc559(uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
    end)
    if ok1 then
        local h, l = get_hi_lo(ret1)
        print(string.format("  ret: 0x%08X_%08X (low32=%d)", h, l, l))
        -- The return value goes to td->td_retval[0] at +0x408
        -- Analysis says: -1 returns directly, 0/1 go through priv_check first
        if l == 0xFFFFFFFF and h == 0xFFFFFFFF then
            print("  Got -1 back: field is currently -1 (uninitialized?)")
        elseif l <= 1 then
            print("  Got " .. l .. ": field is a valid allocation context index")
        else
            print("  Unexpected value: 0x" .. string.format("%X", l))
        end
    else
        print("  PCALL FAILED — handler crashed or is blocked")
    end

    -- A2: Try arg=0 (should need priv_check 0x2ad — expect failure)
    print("")
    print("[A2] sys 559(0) — mutation attempt (needs priv_check):")
    local ok2, ret2 = pcall(function() return sc559(uint64(0)) end)
    if ok2 then
        local h, l = get_hi_lo(ret2)
        print(string.format("  ret: 0x%08X_%08X", h, l))
    else
        print("  PCALL FAILED")
    end

    -- A3: Try arg=1
    print("")
    print("[A3] sys 559(1) — mutation attempt:")
    local ok3, ret3 = pcall(function() return sc559(uint64(1)) end)
    if ok3 then
        local h, l = get_hi_lo(ret3)
        print(string.format("  ret: 0x%08X_%08X", h, l))
    else
        print("  PCALL FAILED")
    end

    -- A4: Try arg=2 (out of range, should return 0x16)
    print("")
    print("[A4] sys 559(2) — out of range (expect error 0x16=22):")
    local ok4, ret4 = pcall(function() return sc559(uint64(2)) end)
    if ok4 then
        local h, l = get_hi_lo(ret4)
        print(string.format("  ret: 0x%08X_%08X (decimal=%d)", h, l, l))
    else
        print("  PCALL FAILED")
    end

    -- A5: Try large values to see error handling
    print("")
    print("[A5] sys 559 with large values:")
    local large_vals = {100, 0x1000, 0x7FFFFFFF, 0x80000000}
    for _, v in ipairs(large_vals) do
        local ok, ret = pcall(function() return sc559(uint64(v)) end)
        if ok then
            local h, l = get_hi_lo(ret)
            print(string.format("  559(0x%X): ret=0x%08X_%08X", v, h, l))
        else
            print(string.format("  559(0x%X): PCALL FAILED", v))
        end
    end

    -- A6: Repeated -1 queries for consistency
    print("")
    print("[A6] Repeated -1 queries (5 rounds, check consistency):")
    local results = {}
    for i = 1, 5 do
        local ok, ret = pcall(function()
            return sc559(uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
        end)
        if ok then
            local h, l = get_hi_lo(ret)
            results[#results + 1] = string.format("0x%08X_%08X", h, l)
            print(string.format("  #%d: 0x%08X_%08X", i, h, l))
        else
            results[#results + 1] = "FAIL"
            print(string.format("  #%d: PCALL FAIL", i))
        end
    end
    local all_same = true
    for i = 2, #results do
        if results[i] ~= results[1] then all_same = false end
    end
    print("[A6] All same: " .. tostring(all_same))


-- ======================================================
-- SECTION B: sys 615 — VM introspection
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: sys 615 VM introspection ---")
    print("")

    -- sys 615 has narg=3: likely (target_pid, outbuf, size) or (cmd, arg1, arg2)
    local outbuf = memory.alloc(0x2000)
    local ok_pid, pid = pcall(function() return sc20() end)
    local pidv = ok_pid and to_num(pid) or 0
    print("[B] Our PID: " .. pidv)

    -- B1: Self-process query — various arg layouts
    print("")
    print("[B1] sys 615 self-process arg layouts:")

    local layouts = {
        -- {name, arg1, arg2, arg3}
        {"pid,outbuf,size", uint64(pidv), uint64(outbuf), uint64(0x2000)},
        {"0,outbuf,size", uint64(0), uint64(outbuf), uint64(0x2000)},
        {"-1,outbuf,size", uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)), uint64(outbuf), uint64(0x2000)},
        {"outbuf,size,pid", uint64(outbuf), uint64(0x2000), uint64(pidv)},
        {"outbuf,pid,size", uint64(outbuf), uint64(pidv), uint64(0x2000)},
        {"cmd=0,outbuf,size", uint64(0), uint64(outbuf), uint64(0x1000)},
        {"cmd=1,outbuf,size", uint64(1), uint64(outbuf), uint64(0x1000)},
        {"cmd=2,outbuf,size", uint64(2), uint64(outbuf), uint64(0x1000)},
        {"cmd=3,outbuf,size", uint64(3), uint64(outbuf), uint64(0x1000)},
    }

    for _, lay in ipairs(layouts) do
        -- Fill output with sentinel
        for j = 0, 0x1FFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

        local ok, ret = pcall(function()
            return sc615(lay[2], lay[3], lay[4])
        end)
        local rv = -999
        if ok then rv = to_num(ret) end

        -- Check for modification
        local first_mod = nil
        local mod_count = 0
        for off = 0, 0x1FC, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0xDEADDEAD then
                if not first_mod then first_mod = off end
                mod_count = mod_count + 1
            end
        end

        local mod_str = first_mod
            and string.format("MODIFIED@+0x%X (%d dwords)", first_mod, mod_count)
            or "unchanged"
        print(string.format("  [%s]: ret=%d %s", lay[1], rv, mod_str))

        -- If modified, dump first 32 bytes and scan for kernel pointers
        if first_mod then
            local hex_line = "    data: "
            for off = first_mod, math.min(first_mod + 31, 0x1FFC), 4 do
                local v = safe_rd(outbuf + off)
                hex_line = hex_line .. string.format("%08X ", v or 0)
            end
            print(hex_line)

            -- Kernel pointer scan
            for off = 0, 0x1FFC, 8 do
                local val = safe_rq(outbuf + off)
                if val then
                    local vh, vl = get_hi_lo(val)
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        print(string.format("    *** KPTR +0x%X: 0x%08X_%08X ***", off, vh, vl))
                    end
                end
            end
        end
    end

    -- B2: Struct-based arg1 (pointer to control struct)
    print("")
    print("[B2] sys 615 with struct-based arg1:")
    local ctrl = memory.alloc(0x100)
    for cmd = 0, 7 do
        for j = 0, 0xFC, 4 do safe_wd(ctrl + j, 0) end
        safe_wd(ctrl, cmd)
        safe_wd(ctrl + 4, 0)
        safe_wd(ctrl + 8, pidv)
        safe_wd(ctrl + 12, 0)
        for j = 0, 0x1FFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

        local ok, ret = pcall(function()
            return sc615(uint64(ctrl), uint64(outbuf), uint64(0x1000))
        end)
        local rv = ok and to_num(ret) or -999

        local first_mod = nil
        for off = 0, 0xFF, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0xDEADDEAD then first_mod = off break end
        end
        print(string.format("  ctrl.cmd=%d: ret=%d outbuf=%s",
            cmd, rv, first_mod and string.format("MOD@+0x%X", first_mod) or "unchanged"))
    end


-- ======================================================
-- SECTION C: sys 636 — table lookup read path
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: sys 636 table lookup read path ---")
    print("")

    -- sys 636 narg=2: arg1=pointer, arg2 is either count or command
    -- Write path: copyin(input_pointer, global_table, count*16)
    -- Read path: "Read sub-handlers may lack priv_check"
    -- The credential gate checks bit 62 at authority+0x60

    local outbuf = memory.alloc(0x2000)

    -- C1: Test basic reachability
    print("[C1] sys 636 basic reachability:")
    local basic_args = {
        {"0, 0", uint64(0), uint64(0)},
        {"outbuf, 0", uint64(outbuf), uint64(0)},
        {"outbuf, 1", uint64(outbuf), uint64(1)},
        {"outbuf, 512", uint64(outbuf), uint64(512)},
        {"outbuf, 513", uint64(outbuf), uint64(513)},
        {"0, outbuf", uint64(0), uint64(outbuf)},
        {"1, outbuf", uint64(1), uint64(outbuf)},
    }
    for _, a in ipairs(basic_args) do
        for j = 0, 0x1FFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

        local ok, ret = pcall(function() return sc636(a[2], a[3]) end)
        local rv = ok and to_num(ret) or -999

        local first_mod = nil
        for off = 0, 0x1FC, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0xDEADDEAD then first_mod = off break end
        end

        print(string.format("  636(%s): ret=%d outbuf=%s", a[1], rv,
            first_mod and string.format("MOD@+0x%X", first_mod) or "unchanged"))
    end

    -- C2: Struct-based arg1 with embedded cmd/count
    print("")
    print("[C2] sys 636 struct-based arg1:")
    local inbuf = memory.alloc(0x200)
    local struct_layouts = {
        -- {name, ptr_off, ptr_val, count_off, count_val}
        {"ptr@0 count@8=1", 0, outbuf, 8, 1},
        {"ptr@0 count@8=10", 0, outbuf, 8, 10},
        {"ptr@0 count@8=512", 0, outbuf, 8, 512},
        {"count@0=1 ptr@8", 0, 1, 8, outbuf},
        {"cmd@0=0 ptr@8 cnt@16=1", 0, 0, 8, outbuf},
    }

    for _, s in ipairs(struct_layouts) do
        for j = 0, 0x1FC, 4 do safe_wd(inbuf + j, 0) end
        for j = 0, 0x1FFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

        if type(s[3]) == "number" then
            safe_wd(inbuf + s[2], s[3])
        else
            safe_wq(inbuf + s[2], s[3])
        end
        if type(s[5]) == "number" then
            safe_wd(inbuf + s[4], s[5])
        else
            safe_wq(inbuf + s[4], s[5])
        end

        local ok, ret = pcall(function()
            return sc636(uint64(inbuf), uint64(1))
        end)
        local rv = ok and to_num(ret) or -999

        local first_mod = nil
        for off = 0, 0x1FC, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0xDEADDEAD then first_mod = off break end
        end

        print(string.format("  [%s]: ret=%d outbuf=%s", s[1], rv,
            first_mod and string.format("MOD@+0x%X", first_mod) or "unchanged"))
    end

    -- C3: Return value analysis — is ret=1 the credential gate?
    print("")
    print("[C3] Return value classification:")
    local ret_counts = {}
    for cnt = 0, 20 do
        for j = 0, 0x1FFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end
        local ok, ret = pcall(function()
            return sc636(uint64(outbuf), uint64(cnt))
        end)
        local rv = ok and to_num(ret) or -999
        ret_counts[rv] = (ret_counts[rv] or 0) + 1
        if cnt <= 5 or cnt == 20 then
            print(string.format("  636(outbuf, %d): ret=%d", cnt, rv))
        end
    end
    print("")
    print("[C3] Return value distribution:")
    for rv, cnt in pairs(ret_counts) do
        print(string.format("  ret=%d: %d times", rv, cnt))
    end


-- ======================================================
-- SECTION D: Cross-reference info leaks
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: Cross-reference info leaks ---")
    print("")

    local outbuf = memory.alloc(0x2000)

    -- D1: sys 559(-1) query + sys 624 counter correlation
    print("[D1] sys 559(-1) + sys 624 counter:")
    local sc624 = make_syscall(624)
    local c1 = pcall(function() return to_num(sc624()) end) and to_num(sc624()) or nil

    local ok559, ret559 = pcall(function()
        return sc559(uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
    end)
    local v559 = ok559 and to_num(ret559) or -999

    local c2 = pcall(function() return to_num(sc624()) end) and to_num(sc624()) or nil
    print(string.format("  559(-1) = %d, 624 delta = %s",
        v559, (c1 and c2) and tostring(c2 - c1) or "?"))

    -- D2: sys 606 status query (also no priv_check per VERIFIED analysis)
    print("")
    print("[D2] sys 606 status query (side-channel oracle):")
    local sc606 = make_syscall(606)
    for i = 1, 5 do
        local ok, ret = pcall(function() return sc606() end)
        if ok then
            local h, l = get_hi_lo(ret)
            print(string.format("  606() #%d: 0x%08X_%08X", i, h, l))
        else
            print(string.format("  606() #%d: PCALL FAIL", i))
        end
    end

    -- D3: sys 559 timing side channel
    print("")
    print("[D3] sys 559(-1) timing (10 samples):")
    local times = {}
    for i = 1, 10 do
        local t1 = os.clock()
        for j = 1, 100 do
            pcall(function()
                sc559(uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
            end)
        end
        local t2 = os.clock()
        local elapsed = (t2 - t1) * 1000
        times[#times + 1] = elapsed
        print(string.format("  sample %d: 100 calls in %.1f ms", i, elapsed))
    end

    -- D4: sys 615 with self-PID using all three arg slots
    print("")
    print("[D4] sys 615 comprehensive self-query:")
    local ok_pid, pid = pcall(function() return sc20() end)
    local pidv = ok_pid and to_num(pid) or 0

    for j = 0, 0x1FFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end
    local ok615, ret615 = pcall(function()
        return sc615(uint64(pidv), uint64(outbuf), uint64(0x2000))
    end)
    local rv615 = ok615 and to_num(ret615) or -999
    print(string.format("  615(pid=%d, outbuf, 0x2000): ret=%d", pidv, rv615))

    -- Scan entire output for any kernel pointers
    local kptr_count = 0
    for off = 0, 0x1FFC, 8 do
        local val = safe_rq(outbuf + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print(string.format("  *** KPTR +0x%X: 0x%08X_%08X ***", off, vh, vl))
                if kptr_count >= 10 then break end
            end
        end
    end
    if kptr_count == 0 then
        print("  No kernel pointers in output")
    end

    -- Check first 64 bytes if any data was written
    local any_written = false
    for off = 0, 252, 4 do
        local v = safe_rd(outbuf + off)
        if v and v ~= 0xDEADDEAD then any_written = true break end
    end
    if any_written then
        print("  First 64 bytes of output:")
        for off = 0, 60, 4 do
            local v = safe_rd(outbuf + off)
            print(string.format("    +0x%02X: 0x%08X", off, v or 0))
        end
    end

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 113a COMPLETE ===")

