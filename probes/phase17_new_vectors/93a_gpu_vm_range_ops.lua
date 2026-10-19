-- CRASH_CLASS: MODERATE
-- PROBE 93a: GPU VM object range operations — sys 654/655/657 (NO credential check)
--
-- Context: Handler analysis reveals three related VM page management syscalls
-- that operate on TYPE-11 objects (GPU mmap backing objects) with NO credential
-- predicate anywhere in their handler bodies:
--
--   654 (narg=5): Single range operation. Args: address, length, operation(0-20),
--                 flags(bits 0x33), reserved=0. 64KB alignment required.
--                 Modifies per-page metadata on GPU-mapped pages.
--   655 (narg=3): Range reset companion. Args: address, length, reserved=0.
--                 Resets per-page state on type-11 objects.
--   657 (narg=4): Batched memory commands. Args: record_ptr, count, processed_out,
--                 flags=0. Records are 0x20 bytes: opcode(1-5) at +0, address at +8.
--                 Five operation opcodes via jump table.
--
-- All three require: entry flag +0x60 &2 clear, object type +0x9d == 11.
-- Our GPU mmap creates type-11 objects, so these should work on our pages.
--
-- CRITICAL: sys 548 (batch VM ops) returned -1 for ALL codes, but it targets
-- regular VM objects. These three target TYPE-11 specifically — different handler!
--
-- This could enable: page protection changes, cache attribute modification,
-- or W^X bypass on GPU-mapped pages.
--
-- Section A: Basic reachability of 654/655/657 on GPU mmap pages
-- Section B: sys 654 operation sweep (ops 0-20 + flag combos)
-- Section C: sys 657 batched commands (opcodes 1-5 on GPU pages)
-- Section D: Protection modification attempt (W^X bypass test)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 93a: GPU VM RANGE OPERATIONS ===")
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

local sc654 = make_syscall(654)
local sc655 = make_syscall(655)
local sc657 = make_syscall(657)
local sc477 = make_syscall(477)  -- mmap
local sc624 = make_syscall(624)  -- VM op counter

if TEST_SECTION == "A" then
    print("--- Section A: Reachability on GPU mmap pages ---")
    print("")

    -- Step 1: Create GPU mmap region (type-11 backing object)
    print("[A1] Creating GPU mmap region (64 pages = 1MB):")
    local PAGE = 0x4000  -- 16KB
    local NPAGES = 64
    local ok, gpu_base = pcall(function()
        return sc477(uint64(0), uint64(NPAGES * PAGE), uint64(0x33),
                     uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then
        print("  mmap FAILED")
        print("[DONE] Section A aborted")
        return
    end
    print("  gpu_base = " .. fmt(gpu_base))

    -- Verify it's readable/writable
    local h, l = get_hi_lo(gpu_base)
    if h == 0 and l == 0 then
        print("  ERROR: mmap returned NULL")
        print("[DONE] Section A aborted")
        return
    end

    -- Write a marker to verify
    local test_ok = safe_wd(gpu_base, 0xDEADBEEF)
    local readback = safe_rd(gpu_base)
    print("  write test: " .. (test_ok and "OK" or "FAIL"))
    print("  readback:   " .. (readback and string.format("0x%X", readback) or "nil"))
    print("")

    -- Step 2: Test sys 654 (single range operation)
    -- Args: address(uint64), length(uint64), operation(uint32), flags(uint32), reserved(uint32)
    -- 64KB alignment required. Operation 0 with flags 0.
    print("[A2] sys 654 (single range op) on GPU page:")

    -- The address must be 64KB aligned (low 16 bits = 0)
    -- GPU mmap base should already be page-aligned
    -- Round up to 64KB boundary
    local align64k = 0x10000
    local gpu_lo = l
    local gpu_aligned = gpu_lo
    if gpu_lo % align64k ~= 0 then
        gpu_aligned = gpu_lo + (align64k - (gpu_lo % align64k))
    end
    local gpu_addr = uint64(string.format("0x%X%08X", h, gpu_aligned))
    print("  aligned addr: " .. fmt(gpu_addr))

    -- Test operation 0 (appears in special route)
    print("  op=0, flags=0, reserved=0:")
    ok, rv = pcall(function()
        return sc654(gpu_addr, uint64(align64k), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print("    ret=" .. fmt(rv) .. (to_num(rv) == 0 and " *** SUCCESS ***" or ""))
    else
        print("    PCALL-FAIL")
    end

    -- Test operation 3 (also special route)
    print("  op=3, flags=0:")
    ok, rv = pcall(function()
        return sc654(gpu_addr, uint64(align64k), uint64(3), uint64(0), uint64(0))
    end)
    if ok then
        print("    ret=" .. fmt(rv) .. (to_num(rv) == 0 and " *** SUCCESS ***" or ""))
    else
        print("    PCALL-FAIL")
    end

    -- Test operation 10 (special route, must not have flag 0x22)
    print("  op=10, flags=0:")
    ok, rv = pcall(function()
        return sc654(gpu_addr, uint64(align64k), uint64(10), uint64(0), uint64(0))
    end)
    if ok then
        print("    ret=" .. fmt(rv) .. (to_num(rv) == 0 and " *** SUCCESS ***" or ""))
    else
        print("    PCALL-FAIL")
    end

    -- Test operations 11-15 (bounded route)
    for op = 11, 15 do
        ok, rv = pcall(function()
            return sc654(gpu_addr, uint64(align64k), uint64(op), uint64(0), uint64(0))
        end)
        if ok then
            print(string.format("  op=%d: ret=%s%s", op, fmt(rv),
                to_num(rv) == 0 and " ***" or ""))
        else
            print(string.format("  op=%d: PCALL-FAIL", op))
        end
    end
    print("")

    -- Step 3: Test sys 655 (range reset)
    print("[A3] sys 655 (range reset) on GPU page:")
    print("  addr=" .. fmt(gpu_addr) .. ", len=64KB, reserved=0:")
    ok, rv = pcall(function()
        return sc655(gpu_addr, uint64(align64k), uint64(0))
    end)
    if ok then
        print("    ret=" .. fmt(rv) .. (to_num(rv) == 0 and " *** SUCCESS ***" or ""))
    else
        print("    PCALL-FAIL")
    end
    print("")

    -- Step 4: Test sys 657 (batched commands)
    -- Record format: 0x20 bytes total
    --   +0x00: opcode (uint32, 1-5)
    --   +0x04: sub/flags (uint32, 0)
    --   +0x08: address (uint64)
    --   +0x10: length (uint64)
    --   +0x18: protection/flags (uint64, bits 0x33)
    print("[A4] sys 657 (batched commands) on GPU page:")

    local rec = memory.alloc(0x40)  -- room for 2 records
    local processed = memory.alloc(8)

    -- Build one record: opcode=1, addr=gpu_addr, len=64KB, prot=0x33
    safe_wd(rec, 1)           -- opcode 1
    safe_wd(rec + 4, 0)       -- sub/flags
    safe_wq(rec + 8, gpu_addr)  -- address
    safe_wq(rec + 0x10, uint64(align64k))  -- length
    safe_wq(rec + 0x18, uint64(0x33))      -- protection

    for opcode = 1, 5 do
        safe_wd(rec, opcode)
        safe_wd(processed, 0)
        ok, rv = pcall(function()
            return sc657(uint64(rec), uint64(1), uint64(processed), uint64(0))
        end)
        local proc_count = safe_rd(processed)
        if ok then
            print(string.format("  opcode=%d: ret=%s processed=%s%s",
                opcode, fmt(rv), proc_count or "nil",
                to_num(rv) == 0 and " *** SUCCESS ***" or ""))
        else
            print(string.format("  opcode=%d: PCALL-FAIL", opcode))
        end
    end
    print("")

    -- Verify GPU memory still accessible after operations
    print("[A5] Post-operation GPU memory check:")
    test_ok = safe_wd(gpu_base, 0xCAFEBABE)
    readback = safe_rd(gpu_base)
    print("  write: " .. (test_ok and "OK" or "FAIL"))
    print("  read:  " .. (readback and string.format("0x%X", readback) or "nil"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 654 full operation sweep ---")
    print("")

    -- Create GPU region
    local PAGE = 0x4000
    local NPAGES = 64
    local ok, gpu_base = pcall(function()
        return sc477(uint64(0), uint64(NPAGES * PAGE), uint64(0x33),
                     uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then
        print("  mmap FAILED"); return
    end
    print("[B0] gpu_base = " .. fmt(gpu_base))

    local h, l = get_hi_lo(gpu_base)
    local align64k = 0x10000
    local gpu_aligned = l
    if l % align64k ~= 0 then
        gpu_aligned = l + (align64k - (l % align64k))
    end
    local gpu_addr = uint64(string.format("0x%X%08X", h, gpu_aligned))
    print("  aligned: " .. fmt(gpu_addr))
    print("")

    -- Sweep all operations 0-20 with flags=0
    print("[B1] Operation sweep 0-20, flags=0:")
    local success_ops = {}
    for op = 0, 20 do
        ok, rv = pcall(function()
            return sc654(gpu_addr, uint64(align64k), uint64(op), uint64(0), uint64(0))
        end)
        if ok then
            local r = to_num(rv)
            local tag = ""
            if r == 0 then tag = " *** SUCCESS ***"; table.insert(success_ops, op) end
            print(string.format("  op=%2d: ret=%s%s", op, fmt(rv), tag))
        else
            print(string.format("  op=%2d: PCALL-FAIL", op))
        end
    end
    print("")

    -- For successful operations, test flag sensitivity
    if #success_ops > 0 then
        print("[B2] Flag sensitivity for successful ops:")
        local flag_vals = {0x01, 0x02, 0x10, 0x11, 0x20, 0x21, 0x22, 0x30, 0x31, 0x33}
        for _, op in ipairs(success_ops) do
            print(string.format("  op=%d:", op))
            for _, fl in ipairs(flag_vals) do
                ok, rv = pcall(function()
                    return sc654(gpu_addr, uint64(align64k), uint64(op),
                                 uint64(fl), uint64(0))
                end)
                if ok then
                    print(string.format("    flags=0x%02X: ret=%s%s",
                        fl, fmt(rv), to_num(rv) == 0 and " OK" or ""))
                else
                    print(string.format("    flags=0x%02X: PCALL-FAIL", fl))
                end
            end
            break  -- only first successful op to limit output
        end
    end
    print("")

    -- Test with different lengths
    print("[B3] Length sensitivity (op=0, flags=0):")
    local lengths = {0, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000}
    for _, len in ipairs(lengths) do
        ok, rv = pcall(function()
            return sc654(gpu_addr, uint64(len), uint64(0), uint64(0), uint64(0))
        end)
        if ok then
            print(string.format("  len=0x%X: ret=%s", len, fmt(rv)))
        else
            print(string.format("  len=0x%X: PCALL-FAIL", len))
        end
    end

    -- Test non-64KB-aligned address (should fail)
    print("")
    print("[B4] Alignment check (should fail):")
    ok, rv = pcall(function()
        return sc654(gpu_base, uint64(align64k), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print("  unaligned: ret=" .. fmt(rv) .. " (expect error if not 64KB aligned)")
    else
        print("  unaligned: PCALL-FAIL")
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: sys 657 batched commands deep probe ---")
    print("")

    -- Create GPU region
    local PAGE = 0x4000
    local NPAGES = 128  -- larger region for batch ops
    local ok, gpu_base = pcall(function()
        return sc477(uint64(0), uint64(NPAGES * PAGE), uint64(0x33),
                     uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then
        print("  mmap FAILED"); return
    end
    print("[C0] gpu_base = " .. fmt(gpu_base))

    local h, l = get_hi_lo(gpu_base)
    local align64k = 0x10000
    local gpu_aligned = l
    if l % align64k ~= 0 then
        gpu_aligned = l + (align64k - (l % align64k))
    end
    local gpu_addr = uint64(string.format("0x%X%08X", h, gpu_aligned))
    print("  aligned: " .. fmt(gpu_addr))
    print("")

    local rec = memory.alloc(0x200)  -- room for 16 records
    local processed = memory.alloc(8)

    -- Test each opcode 1-5 with varying protection bits
    print("[C1] Opcode x protection matrix:")
    local prots = {0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x20, 0x21, 0x30, 0x33}
    for opcode = 1, 5 do
        print(string.format("  opcode %d:", opcode))
        for _, prot in ipairs(prots) do
            -- Build record
            safe_wd(rec, opcode)
            safe_wd(rec + 4, 0)
            safe_wq(rec + 8, gpu_addr)
            safe_wq(rec + 0x10, uint64(align64k))
            safe_wq(rec + 0x18, uint64(prot))
            safe_wd(processed, 0)

            ok, rv = pcall(function()
                return sc657(uint64(rec), uint64(1), uint64(processed), uint64(0))
            end)
            local proc_count = safe_rd(processed)
            if ok and to_num(rv) == 0 then
                print(string.format("    prot=0x%02X: OK processed=%d ***",
                    prot, proc_count or 0))
            elseif ok then
                print(string.format("    prot=0x%02X: ret=%s", prot, fmt(rv)))
            else
                print(string.format("    prot=0x%02X: FAIL", prot))
            end
        end
    end
    print("")

    -- Test multi-record batch (2 records, different addresses)
    print("[C2] Multi-record batch (2 records):")
    local addr2_lo = gpu_aligned + align64k
    local gpu_addr2 = uint64(string.format("0x%X%08X", h, addr2_lo))

    -- Record 1: opcode=1 at gpu_addr
    safe_wd(rec, 1)
    safe_wd(rec + 4, 0)
    safe_wq(rec + 8, gpu_addr)
    safe_wq(rec + 0x10, uint64(align64k))
    safe_wq(rec + 0x18, uint64(0x33))

    -- Record 2: opcode=1 at gpu_addr2
    safe_wd(rec + 0x20, 1)
    safe_wd(rec + 0x24, 0)
    safe_wq(rec + 0x28, gpu_addr2)
    safe_wq(rec + 0x30, uint64(align64k))
    safe_wq(rec + 0x38, uint64(0x33))

    safe_wd(processed, 0)
    ok, rv = pcall(function()
        return sc657(uint64(rec), uint64(2), uint64(processed), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    print("  processed=" .. (safe_rd(processed) or "nil"))
    print("")

    -- Test count sensitivity (0, 1, 2, 10, 100, -1)
    print("[C3] Count sensitivity:")
    safe_wd(rec, 1)
    safe_wd(rec + 4, 0)
    safe_wq(rec + 8, gpu_addr)
    safe_wq(rec + 0x10, uint64(align64k))
    safe_wq(rec + 0x18, uint64(0x33))

    local counts = {0, 1, 2, 10}
    for _, cnt in ipairs(counts) do
        safe_wd(processed, 0)
        ok, rv = pcall(function()
            return sc657(uint64(rec), uint64(cnt), uint64(processed), uint64(0))
        end)
        print(string.format("  count=%d: ret=%s processed=%s",
            cnt, ok and fmt(rv) or "FAIL", safe_rd(processed) or "nil"))
    end

    -- Negative count (should return 0x16=22)
    safe_wd(processed, 0)
    ok, rv = pcall(function()
        return sc657(uint64(rec), uint64(0xFFFFFFFF), uint64(processed), uint64(0))
    end)
    print("  count=-1: ret=" .. (ok and fmt(rv) or "FAIL") ..
          " (expect 0x16=22)")

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Protection modification + W^X test ---")
    print("")

    -- The key question: can sys 654/657 change page protections?
    -- If operations modify protection metadata (e.g., adding EXEC),
    -- we could bypass W^X on GPU pages.

    local PAGE = 0x4000
    local NPAGES = 64

    -- Create TWO GPU regions to test differential effects
    local ok, gpu1 = pcall(function()
        return sc477(uint64(0), uint64(NPAGES * PAGE), uint64(0x33),
                     uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local ok2, gpu2 = pcall(function()
        return sc477(uint64(0), uint64(NPAGES * PAGE), uint64(0x33),
                     uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok or not ok2 then
        print("  mmap FAILED"); return
    end
    print("[D0] gpu1 = " .. fmt(gpu1))
    print("     gpu2 = " .. fmt(gpu2))

    local h1, l1 = get_hi_lo(gpu1)
    local align64k = 0x10000
    local g1_aligned = l1
    if l1 % align64k ~= 0 then
        g1_aligned = l1 + (align64k - (l1 % align64k))
    end
    local addr1 = uint64(string.format("0x%X%08X", h1, g1_aligned))
    print("  addr1 aligned: " .. fmt(addr1))
    print("")

    -- Step 1: Try all operations that might change protection
    -- Flag 0x01 = read, 0x02 = write, 0x10 = exec (hypothesis)
    -- Flag 0x33 = RWX? Let's see what the handler accepts
    print("[D1] Protection-changing operations on gpu1:")

    -- Try operation 0 with exec-like flags
    local exec_flag_tests = {
        {op=0,  fl=0x10, desc="op0+EXEC?"},
        {op=0,  fl=0x13, desc="op0+RX?"},
        {op=0,  fl=0x33, desc="op0+RWX?"},
        {op=3,  fl=0x10, desc="op3+EXEC?"},
        {op=3,  fl=0x33, desc="op3+RWX?"},
        {op=10, fl=0x10, desc="op10+EXEC?"},
        {op=10, fl=0x11, desc="op10+RX?"},
        {op=11, fl=0x33, desc="op11+RWX?"},
        {op=12, fl=0x33, desc="op12+RWX?"},
        {op=15, fl=0x33, desc="op15+RWX?"},
        {op=19, fl=0x33, desc="op19+RWX?"},
        {op=20, fl=0x33, desc="op20+RWX?"},
    }
    for _, t in ipairs(exec_flag_tests) do
        ok, rv = pcall(function()
            return sc654(addr1, uint64(align64k), uint64(t.op),
                         uint64(t.fl), uint64(0))
        end)
        if ok then
            print(string.format("  %s: ret=%s%s", t.desc, fmt(rv),
                to_num(rv) == 0 and " *** SUCCESS ***" or ""))
        else
            print(string.format("  %s: PCALL-FAIL", t.desc))
        end
    end
    print("")

    -- Step 2: Check sys 674 VM map to see if protections changed
    local sc674 = make_syscall(674)
    print("[D2] VM map query (sys 674) to check protection changes:")
    local outbuf = memory.alloc(0x8000)
    local outlen = memory.alloc(8)
    safe_wd(outlen, 0x8000)

    ok, rv = pcall(function()
        return sc674(uint64(outbuf), uint64(outlen))
    end)
    if ok and to_num(rv) == 0 then
        local actual_len = safe_rd(outlen) or 0
        print("  VM map returned " .. actual_len .. " bytes")

        -- Search for our GPU page in the map
        -- Each record is 72 bytes: +0x00 start, +0x08 end, +0x18 protection
        local found_gpu = false
        local off = 0
        while off + 72 <= actual_len do
            local start_q = safe_rq(outbuf + off)
            if start_q then
                local sh, sl = get_hi_lo(start_q)
                if sh == h1 and sl >= (l1 - 0x100000) and sl <= (l1 + 0x100000) then
                    local end_q = safe_rq(outbuf + off + 8)
                    local prot = safe_rd(outbuf + off + 0x18)
                    print(string.format("  FOUND: start=%s end=%s prot=0x%X",
                        fmt(start_q), end_q and fmt(end_q) or "nil", prot or 0))
                    found_gpu = true
                end
            end
            off = off + 72
        end
        if not found_gpu then
            print("  GPU region not found in VM map")
        end
    else
        print("  VM map query failed: " .. (ok and fmt(rv) or "PCALL-FAIL"))
    end
    print("")

    -- Step 3: Test sys 655 reset on modified page
    print("[D3] sys 655 reset test:")
    ok, rv = pcall(function()
        return sc655(addr1, uint64(align64k), uint64(0))
    end)
    print("  reset: ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

    -- Verify memory still works after reset
    local test_ok = safe_wd(gpu1, 0xBEEFCAFE)
    local readback = safe_rd(gpu1)
    print("  post-reset write: " .. (test_ok and "OK" or "FAIL"))
    print("  post-reset read:  " .. (readback and string.format("0x%X", readback) or "nil"))

    -- Step 4: sys 624 counter check (operations should increment VM ops)
    print("")
    print("[D4] sys 624 counter delta from VM range ops:")
    local ok_c1, c1 = pcall(function() return sc624() end)
    -- Do 10 range operations
    for i = 1, 10 do
        pcall(function()
            sc654(addr1, uint64(align64k), uint64(0), uint64(0), uint64(0))
        end)
    end
    local ok_c2, c2 = pcall(function() return sc624() end)
    if ok_c1 and ok_c2 then
        local h1c, l1c = get_hi_lo(c1)
        local h2c, l2c = get_hi_lo(c2)
        print("  before: " .. fmt(c1))
        print("  after:  " .. fmt(c2))
        print("  delta:  " .. (l2c - l1c) .. " (reveals if ops are VM operations)")
    end

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 93a COMPLETE ===")
