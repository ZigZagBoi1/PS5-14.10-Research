-- CRASH_CLASS: LOW
-- PROBE 123a: sys 637 set_phys_fmem_limit kernel write test
--
-- 13.60 decompile shows sys 637 writes caller's value to child+0x280
-- where child = PTR(process, 0x200). With process_id=0 (self), there
-- is NO capability check. Value must be >= 17.
--
-- Risk: sub_8b051c70(child) after the write may block if value is
-- below current physical memory usage. Using 64GB (0x1000000000)
-- which should be far above any physical usage.
--
-- We test:
-- [A] Basic call with large value — does it return 0?
-- [B] sys 624 VM op counter before/after — any kernel state change?
-- [C] Multiple values — all succeed?
-- [D] Read-back attempt via calling again with different values
-- [E] Value boundary: 16 returns EINVAL(22), 17 should succeed

print("=== PROBE 123a: SYS 637 KERNEL WRITE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function fmt_ret(v)
    local n = N(v)
    if n < 0 then n = n + 0x100000000 end
    if n > 0x80000000 then
        return string.format("-%d (0x%X)", 0x100000000 - n, n)
    end
    return tostring(n)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc637 = mk(637)
local sc624 = mk(624)

-- Helper: get sys 624 VM op counter
local function vm_ops()
    local ok, rv = pcall(function() return sc624() end)
    if ok then return N(rv) end
    return -1
end

-- [A] Basic call: 637(0, 0x1000000000) — 64GB limit, self
print("[A] sys 637 basic: pid=0, value=64GB")
local ops_before = vm_ops()
print("  624 before=" .. ops_before)

local ok_a, rv_a = pcall(function()
    return sc637(uint64(0), uint64(0x1000000000))
end)
print("  pcall=" .. tostring(ok_a))
if ok_a then
    print("  ret=" .. fmt_ret(rv_a))
else
    print("  ERROR: " .. tostring(rv_a))
end

local ops_after = vm_ops()
print("  624 after=" .. ops_after .. " (delta=" .. (ops_after - ops_before) .. ")")

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end
print("  alive=YES")

-- [B] Boundary test: value=16 should fail (EINVAL=22), value=17 should succeed
print("")
print("[B] boundary test")
for _, val in ipairs({0, 1, 16, 17, 18, 100}) do
    local ok_b, rv_b = pcall(function()
        return sc637(uint64(0), uint64(val))
    end)
    local c2 = N(native.fcall_with_rax(stub, 20))
    if c2 ~= pid then
        print(string.format("  val=%d: KILLED PROCESS", val))
        return
    end
    if ok_b then
        print(string.format("  val=%d: ret=%s", val, fmt_ret(rv_b)))
    else
        print(string.format("  val=%d: PFAIL", val))
    end
end

-- [C] Different large values — do they all succeed?
print("")
print("[C] large value sweep")
local large_vals = {
    {0x11, "17"},
    {0x100, "256"},
    {0x10000, "64K"},
    {0x1000000, "16M"},
    {0x40000000, "1G"},
    {0x100000000, "4G"},
    {0x400000000, "16G"},
    {0x1000000000, "64G"},
}
for _, entry in ipairs(large_vals) do
    local val, label = entry[1], entry[2]
    local ok_c, rv_c = pcall(function()
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            local lo = val - hi * 0x100000000
            return sc637(uint64(0), uint64(string.format("0x%X%08X", hi, lo)))
        else
            return sc637(uint64(0), uint64(val))
        end
    end)
    local c3 = N(native.fcall_with_rax(stub, 20))
    if c3 ~= pid then
        print(string.format("  %s: KILLED", label))
        return
    end
    if ok_c then
        print(string.format("  %s: ret=%s", label, fmt_ret(rv_c)))
    else
        print(string.format("  %s: PFAIL", label))
    end
end

-- [D] Argument layout test: the 13.60 handler reads {int32 process_id, pad32, int64 value}
-- The make_syscall passes args positionally. Test if arg layout matters.
print("")
print("[D] arg layout variants")

-- Variant 1: two separate args (pid=0, value=64GB)
local ok_d1, rv_d1 = pcall(function()
    return sc637(uint64(0), uint64(0x1000000000))
end)
print("  two-arg: " .. (ok_d1 and ("ret=" .. fmt_ret(rv_d1)) or "PFAIL"))

-- Variant 2: pid as arg1, value as arg2 with explicit hi:lo
local ok_d2, rv_d2 = pcall(function()
    return sc637(uint64(0), uint64("0x1000000000"))
end)
print("  str-arg: " .. (ok_d2 and ("ret=" .. fmt_ret(rv_d2)) or "PFAIL"))

-- Variant 3: foreign pid (our own) — should hit the capability check
local ok_d3, rv_d3 = pcall(function()
    return sc637(uint64(pid), uint64(0x1000000000))
end)
print("  self-pid(" .. pid .. "): " .. (ok_d3 and ("ret=" .. fmt_ret(rv_d3)) or "PFAIL"))

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [E] 624 delta across a batch of 637 calls
print("")
print("[E] 624 delta for 10x 637 calls")
local ops_e1 = vm_ops()
for i = 1, 10 do
    pcall(function() sc637(uint64(0), uint64(0x1000000000)) end)
end
local ops_e2 = vm_ops()
print("  624 before=" .. ops_e1 .. " after=" .. ops_e2 .. " delta=" .. (ops_e2 - ops_e1))

-- [F] Does the process state word at +0xb0 gate us?
-- The handler checks (flags & 0x2200) and state != 1.
-- If our process has those flags set, we get ret=3.
-- Test: just report what we got from all the calls above.
print("")
print("[F] summary")
print("  All calls completed. Process alive.")

-- [G] Test with value=17 then immediately value=18 — if 17 blocks
-- because physical usage > 17 bytes, this won't reach 18.
-- Use a child thread for the blocking test.
print("")
print("[G] blocking test: value=17 via child thread")

-- Get eboot base for gadgets
local inf = memory.alloc(0x200)
pcall(function() memory.write_dword(inf, 0x160) end)
pcall(function() mk(593)(uint64(0), inf) end)
local elo = N(memory.read_dword(inf + 0x108)) or 0
local ehi = N(memory.read_dword(inf + 0x10C)) or 0
if ehi < 0 then ehi = ehi + 0x100000000 end
if elo < 0 then elo = elo + 0x100000000 end
local SA = syscall.syscall_address
local sc_tc = mk(430)

-- Shared result page
local sc_mmap = mk(477)
local shared = sc_mmap(uint64(0), uint64(0x8000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sh_h, sh_l = get_hi_lo(shared)
if sh_h < 0 then sh_h = sh_h + 0x100000000 end
if sh_h >= 0xFFFF8000 then
    print("  shared mmap fail")
else
    local SH = uint64(string.format("0x%X%08X", sh_h, sh_l))
    -- [0] = marker before call, [8] = return value, [16] = marker after
    pcall(function() memory.write_qword(SH, uint64(0)) end)
    pcall(function() memory.write_qword(SH + uint64(8), uint64(0xDEAD)) end)
    pcall(function() memory.write_qword(SH + uint64(16), uint64(0)) end)

    -- Child thread: call 637(0, 17), write return value, then spin
    -- ROP: pop rdi;ret -> 0 (pid)
    --       pop rax;ret -> 637 (syscall#)
    --       pop rsi;ret -> 17 (value)
    --       syscall;ret
    --       pop rdi;ret -> SH+8 (result addr)
    --       mov [rdi],rax;ret (store result)
    --       then mark SH+16 = 0xDONE and spin

    -- Gadgets
    local PRDI = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
    local PRAX = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
    local WMOV = uint64(string.format("0x%X%08X", ehi, elo + 0x92C67))

    -- We need pop rsi;ret for the second arg
    -- eboot+0x1532 is a common pop rsi gadget location, let's verify it exists
    -- Actually, syscall ABI: rdi=arg0, rsi=arg1 for the kernel.
    -- But make_syscall uses the Lua calling convention, not raw syscall ABI.
    -- The child thread via thr_create does raw syscall via SA (syscall;ret).
    -- For raw syscall: rax=syscall#, rdi=arg0, rsi=arg1

    -- Find pop rsi;ret in eboot
    local PRSI = nil
    -- Try common offsets for pop rsi; ret (0x5e c3)
    local prsi_candidates = {0x1532, 0x5F2E, 0x1C56, 0x30D6, 0xF22}
    for _, off in ipairs(prsi_candidates) do
        local addr = uint64(string.format("0x%X%08X", ehi, elo + off))
        local ok_r, b1 = pcall(function() return N(memory.read_dword(addr)) end)
        if ok_r then
            local lo_byte = b1 % 256
            local hi_byte = math.floor(b1 / 256) % 256
            if lo_byte == 0x5E and hi_byte == 0xC3 then
                PRSI = addr
                print(string.format("  pop_rsi;ret @ eboot+0x%X", off))
                break
            end
        end
    end

    if not PRSI then
        -- Scan for pop rsi;ret (5E C3) in first 256KB of eboot
        for off = 0, 0x40000, 1 do
            local addr = uint64(string.format("0x%X%08X", ehi, elo + off))
            local ok_r, w = pcall(function() return N(memory.read_dword(addr)) end)
            if ok_r then
                local b0 = w % 256
                local b1_v = math.floor(w / 256) % 256
                if b0 == 0x5E and b1_v == 0xC3 then
                    PRSI = addr
                    print(string.format("  pop_rsi;ret @ eboot+0x%X (scan)", off))
                    break
                end
            end
        end
    end

    if not PRSI then
        print("  no pop_rsi;ret gadget found, skipping child test")
    else
        -- Build context for child thread
        local stk_base = SH + uint64(0x4000)
        local ctx = SH + uint64(0x1000)

        -- Zero context
        for i = 0, 0x1FF, 4 do
            pcall(function() memory.write_dword(ctx + uint64(i), 0) end)
        end

        -- Sony gates
        pcall(function() memory.write_qword(ctx + uint64(0x108), uint64(0x480)) end)
        pcall(function() memory.write_dword(N(ctx) + 0x0D0, 0) end)
        pcall(function() memory.write_qword(ctx + uint64(0x110), uint64(0x10000)) end)
        -- CS/SS
        pcall(function() memory.write_qword(ctx + uint64(0x0C0), uint64(0x43)) end)
        pcall(function() memory.write_qword(ctx + uint64(0x100), uint64(0x3B)) end)

        -- Child entry: syscall;ret with rax=637, rdi=0, rsi=17
        pcall(function() memory.write_qword(ctx + uint64(0x0E0), SA) end) -- RIP
        pcall(function() memory.write_qword(ctx + uint64(0x0F8), stk_base + uint64(0x3000)) end) -- RSP
        pcall(function() memory.write_qword(ctx + uint64(0x078), uint64(637)) end) -- RAX
        pcall(function() memory.write_qword(ctx + uint64(0x048), uint64(0)) end) -- RDI = pid 0
        pcall(function() memory.write_qword(ctx + uint64(0x050), uint64(17)) end) -- RSI = value 17

        -- ROP after syscall;ret: store result, mark done, spin
        local sp = N(stk_base) + 0x3000
        -- After syscall;ret, rax = return value of 637
        -- pop rdi;ret -> SH+8
        pcall(function() memory.write_qword(sp, PRDI) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, SH + uint64(8)) end); sp = sp + 8
        -- mov [rdi], rax; ret -> store return value
        pcall(function() memory.write_qword(sp, WMOV) end); sp = sp + 8
        -- pop rdi;ret -> SH+16
        pcall(function() memory.write_qword(sp, PRDI) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, SH + uint64(16)) end); sp = sp + 8
        -- pop rax;ret -> 0xD0NE marker
        pcall(function() memory.write_qword(sp, PRAX) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, uint64(0xD04E)) end); sp = sp + 8
        -- mov [rdi], rax; ret -> mark done
        pcall(function() memory.write_qword(sp, WMOV) end); sp = sp + 8
        -- Then nanosleep spin
        local ts_addr = N(SH) + 0x800
        pcall(function() memory.write_qword(ts_addr, uint64(999)) end)
        pcall(function() memory.write_qword(ts_addr + 8, uint64(0)) end)
        pcall(function() memory.write_qword(sp, PRDI) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, uint64(ts_addr)) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, PRAX) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, uint64(240)) end); sp = sp + 8
        pcall(function() memory.write_qword(sp, SA) end); sp = sp + 8

        -- Mark "before call"
        pcall(function() memory.write_qword(SH, uint64(0xBEF0)) end)

        -- Create child
        local tb = memory.alloc(16)
        pcall(function() memory.write_qword(tb, uint64(0)) end)
        local ok_tc, rv_tc = pcall(function() return sc_tc(ctx, uint64(tb), uint64(0)) end)
        print("  child create=" .. tostring(ok_tc) .. " rv=" .. (ok_tc and tostring(N(rv_tc)) or "?"))

        -- Wait 500ms then check
        local sl = memory.alloc(16)
        pcall(function() memory.write_qword(sl, uint64(0)) end)
        pcall(function() memory.write_qword(N(sl) + 8, uint64(500000000)) end)
        native.fcall_with_rax(stub, 240, N(sl), 0)

        -- Check results
        local done_marker = N(memory.read_qword(SH + uint64(16)))
        local ret_val = N(memory.read_qword(SH + uint64(8)))
        print(string.format("  done_marker=0x%X", done_marker))
        print(string.format("  child_637_ret=0x%X", ret_val))
        if done_marker == 0xD04E then
            print("  CHILD COMPLETED — 637(0,17) returned " .. ret_val)
            if ret_val == 0 then
                print("  *** 637(0,17) SUCCEEDED IN CHILD — value <= phys mem ***")
            else
                print("  637(0,17) blocked or failed in child (expected if 17 < phys usage)")
            end
        else
            print("  child still running (637(0,17) likely BLOCKED as expected)")
        end
    end

    -- Cleanup shared mapping
    local sc_munmap = mk(73)
    pcall(function() sc_munmap(SH, uint64(0x8000)) end)
end

c = N(native.fcall_with_rax(stub, 20))
print("")
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 123a COMPLETE ===")
