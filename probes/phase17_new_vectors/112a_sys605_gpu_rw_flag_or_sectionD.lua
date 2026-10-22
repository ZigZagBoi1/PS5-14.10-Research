-- Isolated TEST_SECTION=D live run.
TEST_SECTION = "D"
-- CRASH_CLASS: MODERATE
-- PROBE 112a: sys 605 GPU Page R/W + Process Flag OR — NEVER TESTED
--
-- Context: VERIFIED_HANDLER_ANALYSIS.md states sys 605 (narg=1) has:
--   - Function at offset 0xb60 ORs user-supplied bitmask into process+0xa34
--     with ZERO privilege check (same primitive as sys 643)
--   - GPU page read/write — information disclosure + potential arbitrary write
--     to GPU-mapped memory (unified GDDR6 on PS5 APU)
--   - Device ID whitelist includes crypto processor (0x3cc80700)
--
-- ONLY test was 51b which tried sc605(0) and got ret=-1.
-- This probe systematically explores the handler's sub-function space.
--
-- Section A: Arg sweep (ret mapping for 0-255, key constants, device IDs)
-- Section B: Proc flag test (compare with sys 643 behavior at proc+0xa34)
-- Section C: GPU mmap address as arg (does it R/W GPU pages?)
-- Section D: Device ID probing (crypto processor 0x3cc80700 etc)
-- Section E: Struct-based arg (pointer to control struct in heap)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 112a: SYS 605 GPU R/W + FLAG OR ===")
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

local sc605 = make_syscall(605)
local sc643 = make_syscall(643)
local sc477 = make_syscall(477)   -- mmap
local sc624 = make_syscall(624)   -- VM op counter

local function try_605(arg_val)
    local ok, ret = pcall(function() return sc605(arg_val) end)
    if ok then
        local h, l = get_hi_lo(ret)
        return true, h, l
    else
        return false, 0, 0
    end
end

-- ======================================================
-- SECTION A: Argument sweep — map the return landscape
-- ======================================================
if TEST_SECTION == "A" then
    print("--- SECTION A: sys 605 argument sweep ---")
    print("")

    -- A1: Small integers 0-31
    print("[A1] Small integer args 0-31:")
    local ret_map = {}
    for i = 0, 31 do
        local ok, h, l = try_605(uint64(i))
        local rv = ok and string.format("0x%08X_%08X", h, l) or "PCALL_FAIL"
        ret_map[i] = rv
        print(string.format("  605(%d): %s", i, rv))
    end

    -- A2: Powers of 2
    print("")
    print("[A2] Powers of 2:")
    local pows = {0x40, 0x80, 0x100, 0x200, 0x400, 0x800,
                  0x1000, 0x2000, 0x4000, 0x8000, 0x10000,
                  0x100000, 0x1000000, 0x10000000, 0x80000000}
    for _, p in ipairs(pows) do
        local ok, h, l = try_605(uint64(p))
        local rv = ok and string.format("0x%08X_%08X", h, l) or "PCALL_FAIL"
        print(string.format("  605(0x%X): %s", p, rv))
    end

    -- A3: Special constants (device IDs, flags)
    print("")
    print("[A3] Special constants:")
    local specials = {
        {0x3cc80700, "crypto_processor_device_id"},
        {0xFFFFFFFF, "all_bits"},
        {0x00000001, "bit_0"},
        {0x80000000, "bit_31"},
        {0xDEADBEEF, "sentinel"},
        {0x00010000, "page_shift"},
    }
    for _, s in ipairs(specials) do
        local ok, h, l = try_605(uint64(s[1]))
        local rv = ok and string.format("0x%08X_%08X", h, l) or "PCALL_FAIL"
        print(string.format("  605(0x%08X) [%s]: %s", s[1], s[2], rv))
    end

    -- A4: 64-bit args with high bits
    print("")
    print("[A4] 64-bit args with high bits:")
    local hi_args = {
        {1, 0, "0x1_00000000"},
        {0x10, 0, "0x10_00000000"},
        {0x3cc8, 0x0700, "0x3cc80700 as split"},
        {0xFFFF, 0xFFFF, "0xFFFF_FFFF"},
    }
    for _, a in ipairs(hi_args) do
        local arg = uint64(string.format("0x%X%08X", a[1], a[2]))
        local ok, h, l = try_605(arg)
        local rv = ok and string.format("0x%08X_%08X", h, l) or "PCALL_FAIL"
        print(string.format("  605(%s): %s", a[3], rv))
    end

    -- Cluster analysis: how many unique return values?
    print("")
    print("[A1-A4] Unique returns in 0-31 sweep:")
    local unique = {}
    for i = 0, 31 do
        if not unique[ret_map[i]] then
            unique[ret_map[i]] = {i}
        else
            unique[ret_map[i]][#unique[ret_map[i]] + 1] = i
        end
    end
    for rv, args in pairs(unique) do
        local args_str = {}
        for _, a in ipairs(args) do args_str[#args_str + 1] = tostring(a) end
        print(string.format("  %s: args={%s}", rv, table.concat(args_str, ",")))
    end


-- ======================================================
-- SECTION B: Process flag OR comparison with sys 643
-- ======================================================
elseif TEST_SECTION == "B" then
    print("--- SECTION B: proc flag OR comparison ---")
    print("")

    -- sys 643 is known to OR bits into process+0xa34
    -- Test if sys 605 has a similar path for specific arg patterns

    -- B1: sys 643 baseline (known working)
    print("[B1] sys 643 baseline (known to work):")
    for _, bit in ipairs({1, 2, 4, 8, 0x10, 0x20}) do
        local ok, ret = pcall(function() return sc643(uint64(bit)) end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  643(0x%X): ret=%d", bit, rv))
    end

    -- B2: sys 605 with same bit patterns
    print("")
    print("[B2] sys 605 with same flag bits:")
    for _, bit in ipairs({1, 2, 4, 8, 0x10, 0x20}) do
        local ok, h, l = try_605(uint64(bit))
        local rv = ok and string.format("h=0x%X l=0x%X (=%d)", h, l, l) or "PCALL_FAIL"
        print(string.format("  605(0x%X): %s", bit, rv))
    end

    -- B3: Try struct-style arg where first field is a subcmd
    print("")
    print("[B3] Struct-style arg (pointer to heap buffer):")
    local buf = memory.alloc(0x100)
    local subcmds = {0, 1, 2, 3, 4, 5, 6, 0xb60, 0x100, 0x200}
    for _, cmd in ipairs(subcmds) do
        for j = 0, 0xFC, 4 do safe_wd(buf + j, 0) end
        safe_wd(buf, cmd)
        safe_wd(buf + 8, 0x3cc80700)  -- device ID in second qword

        local ok, h, l = try_605(uint64(buf))
        local rv = ok and string.format("h=0x%X l=0x%X", h, l) or "PCALL_FAIL"
        print(string.format("  605(ptr, cmd=%d/0x%X): %s", cmd, cmd, rv))
    end

    -- B4: sys 624 counter check — does 605 cause VM ops?
    print("")
    print("[B4] sys 624 counter around 605 calls:")
    local c1 = pcall(function() return to_num(sc624()) end) and to_num(sc624()) or nil
    for i = 1, 5 do
        pcall(function() return sc605(uint64(i)) end)
    end
    local c2 = pcall(function() return to_num(sc624()) end) and to_num(sc624()) or nil
    print(string.format("  counter before: %s, after: %s, delta: %s",
        tostring(c1), tostring(c2),
        (c1 and c2) and tostring(c2 - c1) or "?"))


-- ======================================================
-- SECTION C: GPU mmap address as argument
-- ======================================================
elseif TEST_SECTION == "C" then
    print("--- SECTION C: GPU mmap + sys 605 ---")
    print("")

    -- Allocate GPU mmap region
    local gpu = nil
    local ok_gpu, ret_gpu = pcall(function()
        return sc477(uint64(0), uint64(16 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok_gpu then
        local gh, gl = get_hi_lo(ret_gpu)
        if gl ~= 0xFFFFFFFF and gh ~= 0xFFFFFFFF then
            gpu = ret_gpu
            print(string.format("[C] GPU mmap at: 0x%08X_%08X", gh, gl))
        else
            print("[C] GPU mmap failed: MAP_FAILED")
        end
    else
        print("[C] GPU mmap pcall failed")
    end

    if not gpu then
        print("[C] No GPU region, aborting section C")
        print("=== PROBE 112a COMPLETE ===")
        return
    end

    -- Write sentinel pattern to GPU pages
    print("[C] Writing sentinel to GPU pages...")
    for pg = 0, 15 do
        local base = gpu + pg * 0x4000
        safe_wd(base, 0xCAFE0000 + pg)
        safe_wd(base + 4, 0xBABE0000 + pg)
    end

    -- C1: Pass GPU address as arg to 605
    print("")
    print("[C1] sys 605 with GPU base address:")
    local ok1, h1, l1 = try_605(gpu)
    print(string.format("  ret: ok=%s h=0x%X l=0x%X", tostring(ok1), h1, l1))

    -- C2: Pass GPU address + offsets
    print("")
    print("[C2] sys 605 with GPU address + offsets:")
    local offsets = {0, 0x4000, 0x8000, 0xC000, 0x10000}
    for _, off in ipairs(offsets) do
        local addr = gpu + off
        local ok, h, l = try_605(addr)
        print(string.format("  605(gpu+0x%X): ok=%s h=0x%X l=0x%X", off, tostring(ok), h, l))
    end

    -- C3: Check if GPU sentinels were modified by 605 calls
    print("")
    print("[C3] GPU sentinel check after 605 calls:")
    local modified = 0
    for pg = 0, 15 do
        local base = gpu + pg * 0x4000
        local v0 = safe_rd(base)
        local v4 = safe_rd(base + 4)
        local expected0 = 0xCAFE0000 + pg
        local expected4 = 0xBABE0000 + pg
        if v0 ~= expected0 or v4 ~= expected4 then
            modified = modified + 1
            print(string.format("  PAGE %d MODIFIED: [+0]=0x%08X (exp 0x%08X) [+4]=0x%08X (exp 0x%08X)",
                pg, v0 or 0, expected0, v4 or 0, expected4))
        end
    end
    if modified == 0 then
        print("  All 16 pages unchanged")
    else
        print(string.format("  *** %d PAGES MODIFIED BY SYS 605 ***", modified))
    end

    -- C4: Scan GPU pages for kernel pointers (post-605-calls)
    print("")
    print("[C4] GPU page kernel pointer scan:")
    local kptr_count = 0
    for pg = 0, 15 do
        local base = gpu + pg * 0x4000
        for off = 0, 0x3FF8, 8 do
            local val = safe_rq(base + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    kptr_count = kptr_count + 1
                    print(string.format("  KPTR page %d +0x%X: 0x%08X_%08X", pg, off, vh, vl))
                    if kptr_count >= 20 then break end
                end
            end
        end
        if kptr_count >= 20 then break end
    end
    if kptr_count == 0 then
        print("  No kernel pointers found")
    end


-- ======================================================
-- SECTION D: Device ID probing
-- ======================================================
elseif TEST_SECTION == "D" then
    print("--- SECTION D: Device ID sweep ---")
    print("")

    -- The verified analysis mentions device ID whitelist including
    -- crypto processor 0x3cc80700
    local device_ids = {
        {0x3cc80700, "crypto_processor"},
        {0x3cc80100, "GPU_main"},
        {0x3cc80200, "GPU_compute"},
        {0x3cc80300, "GPU_display"},
        {0x3cc80400, "GPU_media"},
        {0x3cc80500, "GPU_reserved_5"},
        {0x3cc80600, "GPU_reserved_6"},
        {0x3cc80000, "GPU_base"},
        {0x3cc8FFFF, "GPU_max"},
        {0x00000000, "null"},
        {0x00000001, "one"},
        {0x100, "0x100"},
        {0x200, "0x200"},
        {0x400, "0x400"},
        {0x800, "0x800"},
    }

    -- D1: Direct arg = device ID
    print("[D1] Direct device ID as arg1:")
    for _, d in ipairs(device_ids) do
        local ok, h, l = try_605(uint64(d[1]))
        local rv = ok and string.format("h=0x%X l=0x%X", h, l) or "PCALL_FAIL"
        print(string.format("  605(0x%08X) [%s]: %s", d[1], d[2], rv))
    end

    -- D2: Struct with device ID at various offsets
    print("")
    print("[D2] Struct with crypto device ID at various offsets:")
    local buf = memory.alloc(0x100)
    for off = 0, 0x40, 8 do
        for j = 0, 0xFC, 4 do safe_wd(buf + j, 0) end
        safe_wd(buf + off, 0x3cc80700)
        safe_wd(buf + off + 4, 0)

        local ok, h, l = try_605(uint64(buf))
        local rv = ok and string.format("h=0x%X l=0x%X", h, l) or "PCALL_FAIL"
        print(string.format("  605(ptr, devid@+0x%02X): %s", off, rv))
    end

    -- D3: Struct with subcmd + device ID combos
    print("")
    print("[D3] Subcmd + device ID combos:")
    local combos = {
        {0, 0x3cc80700},
        {1, 0x3cc80700},
        {2, 0x3cc80700},
        {3, 0x3cc80700},
        {4, 0x3cc80700},
        {0x10, 0x3cc80700},
        {0x20, 0x3cc80700},
    }
    for _, c in ipairs(combos) do
        for j = 0, 0xFC, 4 do safe_wd(buf + j, 0) end
        safe_wd(buf, c[1])       -- subcmd at +0x00
        safe_wd(buf + 4, 0)
        safe_wd(buf + 8, c[2])   -- device ID at +0x08
        safe_wd(buf + 12, 0)

        local ok, h, l = try_605(uint64(buf))
        local rv = ok and string.format("h=0x%X l=0x%X", h, l) or "PCALL_FAIL"
        print(string.format("  605(ptr, cmd=%d devid=0x%08X): %s", c[1], c[2], rv))
    end


-- ======================================================
-- SECTION E: Struct-based control with output buffer
-- ======================================================
elseif TEST_SECTION == "E" then
    print("--- SECTION E: Struct arg with output buffer ---")
    print("")

    local inbuf = memory.alloc(0x200)
    local outbuf = memory.alloc(0x1000)

    -- Fill output with sentinels
    for j = 0, 0xFFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

    -- E1: Pointer arg with output buffer pointer inside struct
    print("[E1] Struct with embedded output pointer:")
    local layouts = {
        -- {name, cmd_off, cmd_val, outbuf_off, size_off, size_val}
        {"cmd=0 out@+8 sz@+16", 0, 0, 8, 16, 0x1000},
        {"cmd=1 out@+8 sz@+16", 0, 1, 8, 16, 0x1000},
        {"cmd=2 out@+8 sz@+16", 0, 2, 8, 16, 0x1000},
        {"cmd=0 out@+16 sz@+24", 0, 0, 16, 24, 0x1000},
        {"cmd=0 out@+8 sz@+10", 0, 0, 8, 0x10, 0x100},
    }

    for _, layout in ipairs(layouts) do
        for j = 0, 0x1FC, 4 do safe_wd(inbuf + j, 0) end
        for j = 0, 0xFFC, 4 do safe_wd(outbuf + j, 0xDEADDEAD) end

        safe_wd(inbuf + layout[2], layout[3])     -- cmd
        safe_wq(inbuf + layout[4], outbuf)         -- output buf ptr
        safe_wd(inbuf + layout[5], layout[6])      -- size

        local ok, h, l = try_605(uint64(inbuf))
        local rv = ok and string.format("h=0x%X l=0x%X", h, l) or "PCALL_FAIL"

        -- Check if outbuf was modified
        local first_modified = nil
        for off = 0, 0x3FC, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0xDEADDEAD then
                first_modified = off
                break
            end
        end

        local mod_str = first_modified and string.format("MODIFIED@+0x%X", first_modified) or "unchanged"
        print(string.format("  [%s]: %s outbuf=%s", layout[1], rv, mod_str))

        if first_modified then
            print("  Output dump (first 64 bytes from modification):")
            for off = first_modified, math.min(first_modified + 63, 0xFFC) do
                -- byte-level not available, use dword
                if off % 4 == 0 then
                    local v = safe_rd(outbuf + off) or 0
                    print(string.format("    +0x%03X: 0x%08X", off, v))
                end
            end
        end
    end

    -- E2: Scan outbuf for kernel pointers after all calls
    print("")
    print("[E2] Final output buffer kernel pointer scan:")
    local kptr_count = 0
    for off = 0, 0xFFC, 8 do
        local val = safe_rq(outbuf + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print(string.format("  KPTR +0x%X: 0x%08X_%08X", off, vh, vl))
                if kptr_count >= 20 then break end
            end
        end
    end
    if kptr_count == 0 then
        print("  No kernel pointers in output")
    end

else
    print("Unknown section: " .. TEST_SECTION)
end

print("")
print("=== PROBE 112a COMPLETE ===")
