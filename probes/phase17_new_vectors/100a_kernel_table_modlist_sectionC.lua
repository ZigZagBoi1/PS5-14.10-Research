-- CRASH_CLASS: LOW
-- PROBE 100a: sys 638/639 kernel table lookup + sys 659/660 module enumeration v2
--
-- Context: Handler analysis reveals 4 never-tested syscalls with NO visible
-- credential checks in their root bodies:
--
-- sys 638 (4 args): Global kernel table lookup with signed arithmetic.
--   Searches a global 16-byte-record table sorted by signed key. Returns
--   input + offset + correction. Copies 8/16/4 bytes to user destinations.
--   No credential check visible. Paired with sys 639 (inverse operation).
--   Race: mode global re-read after lock release can produce mixed snapshots.
--
-- sys 639 (5 args): Inverse of 638. Returns input - offset - correction.
--   Has policy argument (signed dword) that affects overlap resolution.
--   No credential check visible.
--
-- sys 659 (3 args): Dynamic module handle enumeration (copyout_module_handle_list).
--   Returns list of ALL module handles + count. No credential comparison visible.
--   3 args: handles_output_ptr, capacity, count_output_ptr.
--
-- sys 660 (2 args): dynlib_get_info2 — returns 0x160 bytes per module.
--   Possibly contains metadata not in sys 593 (0x160 format). Has visibility
--   gate that controls whether segment addresses are published.
--
-- Section A: sys 638 basic table lookup
-- Section B: sys 639 inverse lookup with policy sweep
-- Section C: sys 659 module handle enumeration
-- Section D: sys 660 info2 for all discovered handles

local TEST_SECTION = "C"

print("=== PROBE 100a: KERNEL TABLE + MODULE ENUM V2 ===")
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

local sc624 = make_syscall(624)
local sc20  = make_syscall(20)

if TEST_SECTION == "A" then
    print("--- Section A: sys 638 kernel table lookup ---")
    print("  4 args: input(s64), result_ptr(8B), record_ptr(16B), correction_ptr(4B)")
    print("  No credential check in handler body")
    print("")

    local sc638 = make_syscall(638)

    local result_buf = memory.alloc(0x100)
    local record_buf = memory.alloc(0x100)
    local corr_buf   = memory.alloc(0x100)

    -- Test with various input values
    local test_inputs = {
        {0, 0},                    -- zero
        {0, 1},                    -- small positive
        {0, 1000},                 -- medium
        {0, 0x5F5E100},            -- 100M (plausible timestamp delta)
        {0, 0x3B9ACA00},           -- 1B (1 second in nanoseconds?)
        {0x15, 0xCD5B0780},        -- ~current epoch seconds approx
        {0x7FFFFFFF, 0xFFFFFFFF},  -- max positive
    }

    for _, pair in ipairs(test_inputs) do
        -- Clear output buffers
        for i = 0, 7 do safe_wd(result_buf + i * 4, 0xDEAD0000 + i) end
        for i = 0, 7 do safe_wd(record_buf + i * 4, 0xBEEF0000 + i) end
        safe_wd(corr_buf, 0xCAFE0000)

        local input_val = uint64(string.format("0x%X%08X", pair[1], pair[2]))
        local ok, rv = pcall(function()
            return sc638(input_val, uint64(result_buf), uint64(record_buf), uint64(corr_buf))
        end)
        local ret = ok and to_num(rv) or -999

        if ok then
            local r_lo = safe_rd(result_buf) or 0
            local r_hi = safe_rd(result_buf + 4) or 0
            local rec0 = safe_rd(record_buf) or 0
            local rec4 = safe_rd(record_buf + 4) or 0
            local rec8 = safe_rd(record_buf + 8) or 0
            local recC = safe_rd(record_buf + 12) or 0
            local corr = safe_rd(corr_buf) or 0

            local result_modified = (r_lo ~= 0xDEAD0000) or (r_hi ~= 0xDEAD0001)
            local record_modified = (rec0 ~= 0xBEEF0000)

            print(string.format("  input=0x%X%08X: ret=%d", pair[1], pair[2], ret))
            if result_modified then
                print(string.format("    result: 0x%08X%08X", r_hi, r_lo))
            end
            if record_modified then
                print(string.format("    record: key=0x%08X%08X off=0x%08X corr=0x%08X",
                    rec4, rec0, rec8, recC))
            end
            if corr ~= 0xCAFE0000 then
                print(string.format("    correction: 0x%08X", corr))
            end
            if not result_modified and not record_modified then
                print("    (no output modified)")
            end
        else
            print(string.format("  input=0x%X%08X: PCALL-FAIL", pair[1], pair[2]))
        end
    end
    print("")

    -- Test with NULL output pointers (only input, rest zero)
    print("[A2] Minimal call — input only, zero output ptrs:")
    local ok, rv = pcall(function()
        return sc638(uint64(1000), uint64(0), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("")

    -- Stability
    print("[A3] Stability:")
    ok, rv = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 639 inverse lookup + policy ---")
    print("  5 args: input(s64), policy(s32), result_ptr(8B), record_ptr(16B), corr_ptr(4B)")
    print("  Inverse of 638 (subtraction instead of addition)")
    print("")

    local sc639 = make_syscall(639)

    local result_buf = memory.alloc(0x100)
    local record_buf = memory.alloc(0x100)
    local corr_buf   = memory.alloc(0x100)

    -- Test with policy sweep
    local policies = {-1, 0, 1, 2, 3, 0x7FFFFFFF}

    print("[B1] Policy sweep with input=1000000000:")
    for _, policy in ipairs(policies) do
        for i = 0, 7 do safe_wd(result_buf + i * 4, 0xDEAD0000 + i) end
        for i = 0, 7 do safe_wd(record_buf + i * 4, 0xBEEF0000 + i) end
        safe_wd(corr_buf, 0xCAFE0000)

        local p_val
        if policy < 0 then
            p_val = uint64(string.format("0xFFFFFFFF%08X", 0x100000000 + policy))
        else
            p_val = uint64(policy)
        end

        local ok, rv = pcall(function()
            return sc639(uint64(0x3B9ACA00), p_val,
                uint64(result_buf), uint64(record_buf), uint64(corr_buf))
        end)
        local ret = ok and to_num(rv) or -999

        if ok then
            local r_lo = safe_rd(result_buf) or 0
            local r_hi = safe_rd(result_buf + 4) or 0
            local result_modified = (r_lo ~= 0xDEAD0000) or (r_hi ~= 0xDEAD0001)

            print(string.format("  policy=%d: ret=%d%s", policy, ret,
                result_modified and string.format(" result=0x%08X%08X", r_hi, r_lo) or " (no output)"))
        else
            print(string.format("  policy=%d: PCALL-FAIL", policy))
        end
    end
    print("")

    -- Test roundtrip: 638(x) then 639(result) should give back x
    print("[B2] Roundtrip test: 638(1B) then 639(result):")
    local sc638 = make_syscall(638)

    for i = 0, 7 do safe_wd(result_buf + i * 4, 0) end
    local ok1, rv1 = pcall(function()
        return sc638(uint64(0x3B9ACA00), uint64(result_buf), uint64(0), uint64(0))
    end)
    if ok1 then
        local fwd_lo = safe_rd(result_buf) or 0
        local fwd_hi = safe_rd(result_buf + 4) or 0
        print(string.format("  638(1B) = 0x%08X%08X (ret=%s)", fwd_hi, fwd_lo, fmt(rv1)))

        if fwd_lo ~= 0 or fwd_hi ~= 0 then
            local fwd_val = uint64(string.format("0x%X%08X", fwd_hi, fwd_lo))
            for i = 0, 7 do safe_wd(result_buf + i * 4, 0) end
            local ok2, rv2 = pcall(function()
                return sc639(fwd_val, uint64(0), uint64(result_buf), uint64(0), uint64(0))
            end)
            if ok2 then
                local inv_lo = safe_rd(result_buf) or 0
                local inv_hi = safe_rd(result_buf + 4) or 0
                print(string.format("  639(result) = 0x%08X%08X (ret=%s)", inv_hi, inv_lo, fmt(rv2)))
                if inv_lo == 0x3B9ACA00 and inv_hi == 0 then
                    print("  *** ROUNDTRIP CONFIRMED — functions are inverse pair ***")
                end
            end
        end
    else
        print("  638 failed: PCALL-FAIL")
    end
    print("")

    -- Stability
    print("[B3] Stability:")
    ok, rv = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: sys 659 module handle enumeration ---")
    print("  3 args: handles_ptr, capacity, count_ptr")
    print("  Returns list of ALL module handles (no credential check)")
    print("")

    local sc659 = make_syscall(659)

    local handles_buf = memory.alloc(0x1000)  -- room for 1024 handles (4 bytes each)
    local count_buf   = memory.alloc(0x10)

    -- Zero buffers
    for i = 0, 0x3FF do safe_wd(handles_buf + i * 4, 0) end
    safe_wq(count_buf, uint64(0))

    -- Call with capacity=256
    print("[C1] Enumerate handles (capacity=256):")
    local ok, rv = pcall(function()
        return sc659(uint64(handles_buf), uint64(256), uint64(count_buf))
    end)
    local ret = ok and to_num(rv) or -999
    print("  ret=" .. ret)

    if ok and ret == 0 then
        local count_val = safe_rq(count_buf)
        local count = count_val and to_num(count_val) or 0
        print("  count=" .. count)

        if count > 0 and count <= 256 then
            print("  handles:")
            for i = 0, math.min(count - 1, 49) do
                local h = safe_rd(handles_buf + i * 4) or 0
                print(string.format("    [%d] handle=0x%X", i, h))
            end
            if count > 50 then
                print("    ... (" .. (count - 50) .. " more)")
            end
        end
    elseif ok then
        -- Try with error code interpretation
        if ret == 1 then
            print("  Error 1: not a dynamically linked program")
        elseif ret == 0x0c then
            print("  Error 0x0c: capacity too small (try larger)")
        elseif ret == 0x22 then
            print("  Error 0x22: invalid argument")
        end
    end
    print("")

    -- Compare with sys 593 known handles (0-38)
    print("[C2] Cross-reference: test handles 0-5 with sys 593:")
    local sc593 = make_syscall(593)
    local info_buf = memory.alloc(0x200)

    for handle = 0, 5 do
        safe_wd(info_buf, 0x160)  -- size field
        local ok2, rv2 = pcall(function()
            return sc593(uint64(handle), uint64(info_buf))
        end)
        local ret2 = ok2 and to_num(rv2) or -999
        if ok2 and ret2 == 0 then
            local name_bytes = {}
            for j = 0, 15 do
                local b = safe_rd(info_buf + 8 + j) or 0
                local c = b % 256
                if c >= 32 and c <= 126 then
                    table.insert(name_bytes, string.char(c))
                else
                    break
                end
            end
            print(string.format("    handle=%d: 593 OK, name=%s", handle,
                table.concat(name_bytes)))
        else
            print(string.format("    handle=%d: 593 ret=%d", handle, ret2))
        end
    end
    print("")

    -- Stability
    print("[C3] Stability:")
    local ok3, rv3 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok3 and fmt(rv3) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: sys 660 dynlib_get_info2 ---")
    print("  2 args: handle(u32), info_struct_ptr (exact 0x160 bytes)")
    print("  May contain metadata not in sys 593")
    print("")

    local sc660 = make_syscall(660)
    local sc593 = make_syscall(593)

    local info2_buf = memory.alloc(0x200)
    local info1_buf = memory.alloc(0x200)

    -- Test handles 0-9
    print("[D1] Info2 for handles 0-9:")
    for handle = 0, 9 do
        -- Clear and set size
        for i = 0, 0x57 do safe_wd(info2_buf + i * 4, 0) end
        safe_wq(info2_buf, uint64(0x160))  -- size field (8 bytes)

        local ok, rv = pcall(function()
            return sc660(uint64(handle), uint64(info2_buf))
        end)
        local ret = ok and to_num(rv) or -999

        if ok and ret == 0 then
            -- Read name at +8
            local name_bytes = {}
            for j = 0, 31 do
                local b = safe_rd(info2_buf + 8 + j) or 0
                local c = b % 256
                if c >= 32 and c <= 126 then
                    table.insert(name_bytes, string.char(c))
                else
                    break
                end
            end
            local name = table.concat(name_bytes)

            -- Read segment count at +0x148
            local seg_count = safe_rd(info2_buf + 0x148) or 0

            -- Read segments at +0x108 (up to 4 x 16-byte records)
            print(string.format("  handle=%d: name=%s segments=%d", handle, name, seg_count))

            -- Dump segment addresses
            for s = 0, math.min(seg_count - 1, 3) do
                local seg_base = info2_buf + 0x108 + s * 16
                local addr_val = safe_rq(seg_base)
                local size_val = safe_rq(seg_base + 8)
                if addr_val then
                    local ah, al = get_hi_lo(addr_val)
                    local sh, sl = get_hi_lo(size_val)
                    print(string.format("    seg[%d]: addr=%s size=%s",
                        s, fmt(addr_val), fmt(size_val)))
                    if ah >= 0xFFFF8000 and ah ~= 0xFFFFFFFF then
                        print("    *** KERNEL POINTER IN SEGMENT ADDRESS ***")
                    end
                end
            end

            -- Check tail bytes at +0x14C (20-byte tail area)
            print("    tail[+0x14C]:")
            for i = 0, 4 do
                local tv = safe_rd(info2_buf + 0x14C + i * 4) or 0
                if tv ~= 0 then
                    print(string.format("      +0x%X: 0x%08X", 0x14C + i * 4, tv))
                end
            end

            -- Compare with sys 593 output
            safe_wd(info1_buf, 0x160)
            local ok2, rv2 = pcall(function()
                return sc593(uint64(handle), uint64(info1_buf))
            end)
            if ok2 and to_num(rv2) == 0 then
                -- Check for differences in segment area
                local diffs = 0
                for off = 0x108, 0x15F, 4 do
                    local v1 = safe_rd(info1_buf + off) or 0
                    local v2 = safe_rd(info2_buf + off) or 0
                    if v1 ~= v2 then diffs = diffs + 1 end
                end
                if diffs > 0 then
                    print(string.format("    *** %d DWORD DIFFERENCES vs sys 593 ***", diffs))
                end
            end
        else
            if ret == 1 then
                print(string.format("  handle=%d: ret=1 (not dynamic or filtered)", handle))
            elseif ret == 3 then
                print(string.format("  handle=%d: ret=3 (handle not found)", handle))
            elseif ret ~= -999 then
                print(string.format("  handle=%d: ret=%d", handle, ret))
            else
                print(string.format("  handle=%d: PCALL-FAIL", handle))
            end
        end
    end
    print("")

    -- Deep scan: look for kernel pointers in full 0x160 output
    print("[D2] Kernel pointer scan in info2 output (handle 0):")
    for i = 0, 0x57 do safe_wd(info2_buf + i * 4, 0) end
    safe_wq(info2_buf, uint64(0x160))

    local ok, rv = pcall(function()
        return sc660(uint64(0), uint64(info2_buf))
    end)
    if ok and to_num(rv) == 0 then
        for off = 0, 0x158, 8 do
            local val = safe_rq(info2_buf + off)
            if val then
                local h, l = get_hi_lo(val)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print(string.format("  *** KERNEL PTR at +0x%03X: %s ***", off, fmt(val)))
                end
            end
        end
        print("  (scan complete)")
    else
        print("  handle 0 failed")
    end
    print("")

    -- Stability
    print("[D3] Stability:")
    local ok3, rv3 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok3 and fmt(rv3) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 100a COMPLETE ===")
