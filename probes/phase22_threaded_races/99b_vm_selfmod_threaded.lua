-- CRASH_CLASS: MODERATE
-- PROBE 99b: sys 620 VM self-modification — THREADED VARIANT
--
-- sys 620 reads saved RIP from td->trapframe+0x100 (the syscall return
-- address), computes (saved_address - 0x80) & ~0x3fff to get a 16KB-
-- aligned code page, and calls a kernel VM operation with MODE 5 on it.
-- No args, no credential check.
--
-- KEY INSIGHT: a child thread created via thr_create(430) has its OWN
-- trapframe. Its saved RIP is the instruction after the child's syscall
-- entry — which lives in libkernel, NOT in eboot. So sys 620 from the
-- main thread targets an eboot page, but from a child thread it targets
-- a LIBKERNEL page. Different page, different VM object, potentially
-- different protection outcome.
--
-- Section A: sys 620 reachability from main thread + VM region query
-- Section B: sys 620 + mprotect(RWX) retest
-- Section C: sys 620 from CHILD THREAD (different target page)
-- Section D: sys 617 byte sweep + sys 620 combined
--
-- Threading layout per docs/THR_CREATE_430_CONTEXT.md §5 and probe 157a:
--   +0x108 = mc_len (0x480)
--   +0x0D0 = uc_flags (0)
--   +0x110 = mc_fpformat (0x10000)
--   +0x0C0 = CS (0x43)
--   +0x0E0 = RIP
--   +0x0F8 = RSP
--   +0x100 = SS (0x3B)
--   +0x048 = RDI, +0x050 = RSI, +0x058 = RDX, +0x078 = RAX

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 99b: VM SELF-MOD THREADED ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20   = make_syscall(20)   -- getpid
local sc74   = make_syscall(74)   -- mprotect
local sc477  = make_syscall(477)  -- mmap
local sc547  = make_syscall(547)  -- VM region query
local sc617  = make_syscall(617)  -- HW MMIO write
local sc620  = make_syscall(620)  -- VM self-mod
local sc624  = make_syscall(624)  -- VM op counter
local sc430  = make_syscall(430)  -- thr_create
local sc433  = make_syscall(433)  -- thr_kill
local sc240  = make_syscall(240)  -- nanosleep
local sc432  = make_syscall(432)  -- thr_self

-- ucontext field offsets (from buffer start, per 157a/THR_CREATE docs)
local C_MAGIC = 0x108   -- mc_len = 0x480
local C_FLAGS = 0x0D0   -- uc_flags = 0
local C_TYPE  = 0x110   -- mc_fpformat = 0x10000
local C_CS    = 0x0C0
local C_RIP   = 0x0E0
local C_RSP   = 0x0F8
local C_SS    = 0x100
local C_RDI   = 0x048
local C_RSI   = 0x050
local C_RDX   = 0x058
local C_RAX   = 0x078

collectgarbage("stop")

local function canary()
    local ok, p = pcall(function() return sc20() end)
    return ok and to_num(p) or 0
end

local function read624()
    local ok, ret = pcall(function() return sc624() end)
    if not ok or ret == nil then return nil end
    local h, l = get_hi_lo(ret)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return h * 4294967296 + l
end

local function vm_region_query(addr)
    local out = memory.alloc(0x40)
    zero(out, 0x40)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(out)) end)
    if ok and to_num(rv) == 0 then
        local results = {}
        for i = 0, 5 do
            results[i] = rq(out + i * 8)
        end
        return results
    end
    return nil
end

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(ms * 1000000))
    pcall(function() sc240(uint64(ts), uint64(0)) end)
end

local pid = canary()
print("[0] pid=" .. pid)

-- Resolve libkernel syscall wrapper (same as 157a)
local SW = syscall.syscall_address
if SW == nil then
    print("[!] syscall.syscall_address not available")
    print("=== PROBE 99b COMPLETE ===")
    return
end
local sw_hi, sw_lo = get_hi_lo(SW)
if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
-- wrapper = syscall_address - 7 (skip past "mov rax, <num>")
if sw_lo < 7 then sw_lo = sw_lo + 0x100000000 - 7; sw_hi = sw_hi - 1
else sw_lo = sw_lo - 7 end
local wrapper_str = string.format("0x%X%08X", sw_hi, sw_lo)
local wrapper = uint64(wrapper_str)
print("[0] syscall_address=" .. q(SW) .. " wrapper=" .. q(wrapper))

-- Get eboot base
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = rd(info + 0x108) or 0
local eboot_hi = rd(info + 0x10C) or 0
local eboot_str = string.format("0x%X%08X", eboot_hi, eboot_lo)
print("[0] eboot text=" .. eboot_str)

-- ============================================================
if TEST_SECTION == "A" then
-- ============================================================
    print("--- Section A: sys 620 reachability from main thread ---")
    print("  0 args, NO credential check")
    print("  Derives 16KB page from saved RIP, calls VM op mode 5")
    print("")

    -- VM region query on eboot .text BEFORE
    print("[A1] VM region query on eboot BEFORE sys 620:")
    local before_vr = vm_region_query(eboot_str)
    if before_vr then
        for i = 0, 5 do
            print(string.format("    [%d] %s", i, q(before_vr[i])))
        end
    else
        print("    (query failed)")
    end

    local c_before = read624()
    print("[A2] VM counter BEFORE: " .. tostring(c_before))
    print("")

    -- Call sys 620 from main thread
    print("[A3] Calling sys 620 (main thread):")
    local ok, rv = pcall(function() return sc620() end)
    print("  ret=" .. (ok and q(rv) or "PCALL-FAIL"))

    local c_after = read624()
    print("[A4] VM counter AFTER: " .. tostring(c_after))
    if c_before and c_after then
        local delta = c_after - c_before
        if delta ~= 0 then
            print("  *** VM COUNTER CHANGED BY " .. delta .. " ***")
        else
            print("  (no change)")
        end
    end
    print("")

    -- VM region query AFTER
    print("[A5] VM region query on eboot AFTER sys 620:")
    local after_vr = vm_region_query(eboot_str)
    if after_vr then
        for i = 0, 5 do
            local changed = before_vr and before_vr[i] and
                to_num(after_vr[i]) ~= to_num(before_vr[i])
            print(string.format("    [%d] %s%s", i, q(after_vr[i]),
                changed and " *** CHANGED ***" or ""))
        end
    else
        print("    (query failed)")
    end
    print("")

    -- Rapid fire to detect cumulative effect
    print("[A6] sys 620 x10 rapid:")
    local c_pre = read624()
    for i = 1, 10 do
        local ok2, rv2 = pcall(function() return sc620() end)
        if i <= 3 or i == 10 then
            print(string.format("  call %d: ret=%s", i, ok2 and q(rv2) or "FAIL"))
        end
    end
    local c_post = read624()
    print("  VM counter delta: " .. tostring(c_pre and c_post and (c_post - c_pre) or "n/a"))

    print("")
    print("canary=" .. canary())
    print("[DONE] Section A complete")

-- ============================================================
elseif TEST_SECTION == "B" then
-- ============================================================
    print("--- Section B: sys 620 + mprotect RWX retest ---")
    print("")

    -- Allocate GPU mmap pages as test target
    local ok_gpu, gpu = pcall(function()
        return sc477(uint64(0), uint64(16 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("[B1] GPU mmap: " .. (ok_gpu and q(gpu) or "FAIL"))

    -- Also allocate normal RW pages for comparison
    local ok_rw, rw_page = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    print("  RW page: " .. (ok_rw and q(rw_page) or "FAIL"))

    -- Baseline: mprotect RWX should fail on both (W^X policy)
    print("")
    print("[B2] mprotect RWX BEFORE sys 620:")
    if ok_gpu then
        local ok2, rv = pcall(function() return sc74(uint64(gpu), uint64(0x4000), uint64(7)) end)
        print("  GPU page: ret=" .. (ok2 and q(rv) or "FAIL") .. " (expect -1)")
    end
    if ok_rw then
        local ok2, rv = pcall(function() return sc74(uint64(rw_page), uint64(0x4000), uint64(7)) end)
        print("  RW page:  ret=" .. (ok2 and q(rv) or "FAIL") .. " (expect -1)")
    end

    -- Call sys 620 multiple times
    print("")
    print("[B3] Calling sys 620 x5:")
    for i = 1, 5 do
        local ok3, rv = pcall(function() return sc620() end)
        print(string.format("  call %d: ret=%s", i, ok3 and q(rv) or "FAIL"))
    end

    -- Retry mprotect RWX
    print("")
    print("[B4] mprotect RWX AFTER sys 620:")
    if ok_gpu then
        local ok2, rv = pcall(function() return sc74(uint64(gpu), uint64(0x4000), uint64(7)) end)
        print("  GPU page: ret=" .. (ok2 and q(rv) or "FAIL"))
        if ok2 and to_num(rv) == 0 then
            print("  *** W^X BYPASS ON GPU PAGE! ***")
            wd(gpu, 0x41414141)
            local verify = rd(gpu)
            print("  RW verify: " .. (verify == 0x41414141 and "OK" or "FAIL"))
        end
    end
    if ok_rw then
        local ok2, rv = pcall(function() return sc74(uint64(rw_page), uint64(0x4000), uint64(7)) end)
        print("  RW page:  ret=" .. (ok2 and q(rv) or "FAIL"))
        if ok2 and to_num(rv) == 0 then
            print("  *** W^X BYPASS ON RW PAGE! ***")
        end
    end

    -- Also try R+X (no W)
    print("")
    print("[B5] mprotect R+X AFTER sys 620:")
    if ok_gpu then
        local ok2, rv = pcall(function() return sc74(uint64(gpu), uint64(0x4000), uint64(5)) end)
        print("  GPU page: ret=" .. (ok2 and q(rv) or "FAIL"))
        if ok2 and to_num(rv) == 0 then print("  *** EXEC GRANTED ***") end
    end

    print("")
    print("canary=" .. canary())
    print("[DONE] Section B complete")

-- ============================================================
elseif TEST_SECTION == "C" then
-- ============================================================
    print("--- Section C: sys 620 from CHILD THREAD ---")
    print("  Child's trapframe has different saved RIP (libkernel, not eboot)")
    print("  → sys 620 targets libkernel 16KB page instead of eboot page")
    print("")

    -- Build a child thread that calls sys 620 in a loop, then exits.
    -- Strategy: make the wrapper entry point load rax=620, then syscall.
    -- But we can't control the wrapper — it always does "mov rax, 116".
    -- Instead: use the native.fcall_with_rax stub pattern. The child
    -- calls gettimeofday(620-as-RDI) and we observe the timeval page.
    --
    -- ACTUALLY: to make the child call sys 620, we need a different
    -- approach. The 157a trick hardcodes the wrapper which always calls
    -- syscall 116 (gettimeofday). For sys 620 we need the child to
    -- execute "mov rax, 620; syscall".
    --
    -- Two options:
    -- (a) Build the instruction bytes at a writable page (need W+X or JIT)
    -- (b) Use the make_syscall pattern where sc620.fn_addr IS the call
    --     gate and sc620.syscall_no is the number. The Lua loader's
    --     fn_addr points into eboot, and the eboot dispatch function
    --     reads the number from the closure's field. We can't replicate
    --     this from a raw thread.
    --
    -- Cleanest approach: have the MAIN thread call sys 620 in a tight
    -- loop, but from a child thread's context. We can do this by having
    -- the child write a "request" value and the main thread polls it.
    --
    -- Simpler: just have the child loop gettimeofday (proving it's alive
    -- and its RIP lives in libkernel), then have the MAIN thread check
    -- what page the child's saved RIP targets.
    --
    -- For the VM self-mod test: we call sys 620 from main, but ALSO
    -- measure what happens to the libkernel page where the child runs.
    -- If mode 5 is page-global, it may change ALL pages; if it's only
    -- the derived page, only eboot is affected.

    -- Step 1: allocate shared page for child's timeval output
    local ok_pg, page = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_pg then
        print("[!] page alloc failed"); return
    end
    zero(page, 0x4000)
    print("[C1] timeval page=" .. q(page))

    -- Step 2: build cycling stack (every slot = wrapper addr)
    local STACK_SIZE = 0x100000
    local ok_stk, stack = pcall(function()
        return sc477(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then
        print("[!] stack alloc failed"); return
    end
    for off = 0, STACK_SIZE - 8, 8 do
        wq(stack + off, wrapper)
    end
    print("[C1] stack=" .. q(stack))

    -- Step 3: build ucontext for child — gettimeofday(page, NULL) loop
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE,  uint64(0x10000))
    wq(ctx + C_CS,    uint64(0x43))
    wq(ctx + C_SS,    uint64(0x3B))
    wq(ctx + C_RIP,   wrapper)
    wq(ctx + C_RSP,   stack)
    wq(ctx + C_RAX,   uint64(116))
    wq(ctx + C_RDI,   page)
    wq(ctx + C_RSI,   uint64(0))

    -- Step 4: VM region query on LIBKERNEL page (where child's RIP lives)
    -- The wrapper address should be inside libkernel
    print("")
    print("[C2] VM region around libkernel wrapper BEFORE child + sys 620:")
    local lk_vr_before = vm_region_query(wrapper_str)
    if lk_vr_before then
        for i = 0, 3 do
            print(string.format("    [%d] %s", i, q(lk_vr_before[i])))
        end
    else
        print("    (query failed — execute-only?)")
    end

    -- Also check eboot
    print("[C2b] VM region around eboot BEFORE:")
    local eb_vr_before = vm_region_query(eboot_str)
    if eb_vr_before then
        for i = 0, 3 do
            print(string.format("    [%d] %s", i, q(eb_vr_before[i])))
        end
    end

    -- Step 5: launch child thread
    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0xDEADDEAD))

    local c_before = read624()
    print("")
    print("[C3] Launching child thread (gettimeofday loop)...")
    local ok_tc, rv_tc = pcall(function()
        return sc430(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = rq(tid_buf)
    print("  thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. to_num(rv_tc) ..
        " tid=" .. q(child_tid))

    if to_num(rv_tc) ~= 0 then
        print("[!] child creation failed")
        print("=== PROBE 99b COMPLETE ===")
        return
    end

    -- Let child run briefly
    sleep_ms(30)
    local sec1, usec1 = rd(page), rd(page + 8)
    print("[C3] timeval after 30ms: sec=" .. tostring(sec1) ..
        " usec=" .. tostring(usec1))
    if (sec1 or 0) ~= 0 or (usec1 or 0) ~= 0 then
        print("  *** CHILD IS ALIVE AND LOOPING SYSCALLS ***")
    end

    -- Step 6: call sys 620 from MAIN thread while child runs
    print("")
    print("[C4] Calling sys 620 from MAIN while child runs:")
    local c_mid = read624()
    for i = 1, 5 do
        local ok3, rv = pcall(function() return sc620() end)
        if i <= 3 or i == 5 then
            print(string.format("  call %d: ret=%s", i, ok3 and q(rv) or "FAIL"))
        end
    end
    local c_after = read624()
    print("  VM counter delta: " .. tostring(c_mid and c_after and (c_after - c_mid) or "n/a"))

    -- Step 7: check VM regions AFTER
    print("")
    print("[C5] VM region around libkernel AFTER sys 620:")
    local lk_vr_after = vm_region_query(wrapper_str)
    if lk_vr_after then
        for i = 0, 3 do
            local changed = lk_vr_before and lk_vr_before[i] and
                to_num(lk_vr_after[i]) ~= to_num(lk_vr_before[i])
            print(string.format("    [%d] %s%s", i, q(lk_vr_after[i]),
                changed and " *** CHANGED ***" or ""))
        end
    else
        print("    (query failed)")
    end

    print("[C5b] VM region around eboot AFTER:")
    local eb_vr_after = vm_region_query(eboot_str)
    if eb_vr_after then
        for i = 0, 3 do
            local changed = eb_vr_before and eb_vr_before[i] and
                to_num(eb_vr_after[i]) ~= to_num(eb_vr_before[i])
            print(string.format("    [%d] %s%s", i, q(eb_vr_after[i]),
                changed and " *** CHANGED ***" or ""))
        end
    end

    -- Step 8: mprotect RWX on child's page region
    print("")
    print("[C6] mprotect RWX on libkernel page after sys 620:")
    local lk_page = uint64(string.format("0x%X%08X", sw_hi, sw_lo))
    local ok_mp, rv_mp = pcall(function()
        return sc74(lk_page, uint64(0x4000), uint64(7))
    end)
    print("  ret=" .. (ok_mp and q(rv_mp) or "FAIL"))
    if ok_mp and to_num(rv_mp) == 0 then
        print("  *** W^X BYPASS ON LIBKERNEL PAGE! ***")
    end

    -- Kill child before exit (kills whole process, so this is last)
    print("")
    print("canary=" .. canary())
    print("[DONE] Section C complete — killing child")
    pcall(function() return sc433(child_tid, uint64(9)) end)

-- ============================================================
elseif TEST_SECTION == "D" then
-- ============================================================
    print("--- Section D: sys 617 byte sweep + sys 620 combined ---")
    print("  Test whether HW register state affects VM operation")
    print("")

    local function try_mprotect_rwx()
        local ok_p, test = pcall(function()
            return sc477(uint64(0), uint64(0x4000), uint64(3),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if not ok_p then return false, "mmap-fail" end
        local ok2, rv = pcall(function()
            return sc74(uint64(test), uint64(0x4000), uint64(7))
        end)
        return ok2 and to_num(rv) == 0, (ok2 and q(rv) or "fail")
    end

    -- Baseline: mprotect RWX should fail
    local base_rwx, base_rv = try_mprotect_rwx()
    print("[D1] Baseline mprotect(RWX): " .. tostring(base_rwx) .. " rv=" .. base_rv)
    print("")

    -- sys 617: try key byte values, after each one call sys 620 and retest
    print("[D2] sys 617 byte → sys 620 → mprotect sweep:")
    local interesting_bytes = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x0F, 0x10, 0x20,
        0x3F, 0x40, 0x7F, 0x80, 0xBF, 0xC0, 0xFE, 0xFF
    }

    for _, byte_val in ipairs(interesting_bytes) do
        -- Write HW register
        local ok617, rv617 = pcall(function()
            return sc617(uint64(byte_val))
        end)

        -- Call sys 620
        local ok620, rv620 = pcall(function()
            return sc620()
        end)

        -- Test mprotect
        local rwx_ok, rwx_rv = try_mprotect_rwx()

        local status = ""
        if not ok617 then status = "617-FAIL"
        elseif not ok620 then status = "620-FAIL"
        elseif rwx_ok then status = "*** W^X BYPASS ***"
        else status = "no-bypass"
        end

        print(string.format("  byte=0x%02X: 617=%s 620=%s mprotect=%s → %s",
            byte_val,
            ok617 and q(rv617) or "FAIL",
            ok620 and q(rv620) or "FAIL",
            rwx_rv, status))

        if rwx_ok then
            print("  !!! FOUND W^X BYPASS AT BYTE VALUE 0x" ..
                string.format("%02X", byte_val) .. " !!!")
            break
        end
    end

    -- Full 0-255 sweep if no hit from interesting set
    print("")
    print("[D3] Full 0-255 byte sweep (617 → 620 → mprotect check):")
    local found = false
    for byte_val = 0, 255 do
        local ok617 = pcall(function() sc617(uint64(byte_val)) end)
        local ok620 = pcall(function() sc620() end)
        local rwx_ok = try_mprotect_rwx()
        if rwx_ok then
            print("  *** HIT at byte=0x" .. string.format("%02X", byte_val) .. " ***")
            found = true
            break
        end
        if byte_val % 64 == 63 then
            print("  scanned 0x00-0x" .. string.format("%02X", byte_val) .. " — no hit")
        end
    end
    if not found then
        print("  (no bypass found across full range)")
    end

    print("")
    print("canary=" .. canary())
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 99b COMPLETE ===")
