-- CRASH_CLASS: MODERATE
-- PROBE 51b: Deep testing of accessible Sony syscalls
--
-- Context: Run AFTER 51a to identify which Sony syscalls are accessible.
-- This probe does deeper testing of promising ones:
-- - Passes output buffers and checks for kernel pointer leaks
-- - Varies argument values to understand parameter semantics
-- - Tests boundary conditions that might trigger bugs
--
-- IMPORTANT: Edit the "targets" table below based on 51a results
-- before sending this probe.

print("=== PROBE 51b: DEEP SONY SYSCALL TESTING ===")
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

local function hexdump(addr, len)
    local parts = {}
    for i = 0, len - 4, 4 do
        local v = safe_rd(addr + i)
        if v then
            table.insert(parts, string.format("%08X", v))
        else
            table.insert(parts, "????????")
        end
    end
    return table.concat(parts, " ")
end

local function scan_for_kptrs(addr, len)
    local found = {}
    for i = 0, len - 8, 8 do
        local val = safe_rq(addr + i)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                table.insert(found, {i, h, l})
            end
        end
    end
    return found
end

-- Allocate large output buffers
local outbuf = memory.alloc(0x4000)
local outbuf2 = memory.alloc(0x4000)
local outbuf3 = memory.alloc(0x4000)
local lenp = memory.alloc(8)

local sc_getpid = make_syscall(20)
local pid = to_num(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("PID: " .. pid)

-- ============================================================
-- SECTION A: Dynlib group deep test (591-599, 608, 612, 649, 656, 659, 660, 672)
-- These are near dynlib_get_info (593) which we know works.
-- They likely take module handles or return module info.
-- ============================================================
print("")
print("--- SECTION A: Dynlib group (near 593/dynlib_get_info) ---")

-- 596: narg=0 - just call it
local sc596 = make_syscall(596)
local ok, ret = pcall(function() return sc596() end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  596(): ret=0x%08X_%08X", h, l))
end

-- 599: narg=0
local sc599 = make_syscall(599)
ok, ret = pcall(function() return sc599() end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  599(): ret=0x%08X_%08X", h, l))
end

-- 591: narg=3 - likely dynlib_load_prx or similar
-- Try: (handle, buf, buflen)
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
safe_wd(lenp, 0x200)
local sc591 = make_syscall(591)
ok, ret = pcall(function() return sc591(uint64(0), uint64(outbuf), uint64(lenp)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  591(0, buf, lenp): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
        local kptrs = scan_for_kptrs(outbuf, 0x200)
        if #kptrs > 0 then
            print("    !!! KERNEL POINTERS FOUND:")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +%03X: 0x%08X_%08X", kp[1], kp[2], kp[3]))
            end
        end
    end
end

-- 592: narg=3 - try same pattern
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc592 = make_syscall(592)
ok, ret = pcall(function() return sc592(uint64(0), uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  592(0, buf, 0x200): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- 594: narg=4 - dynlib related with 4 args
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc594 = make_syscall(594)
ok, ret = pcall(function() return sc594(uint64(0), uint64(outbuf), uint64(0x200), uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  594(0, buf, 0x200, 0): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
        local kptrs = scan_for_kptrs(outbuf, 0x200)
        if #kptrs > 0 then
            print("    !!! KERNEL POINTERS FOUND:")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +%03X: 0x%08X_%08X", kp[1], kp[2], kp[3]))
            end
        end
    end
end

-- 595: narg=3
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc595 = make_syscall(595)
ok, ret = pcall(function() return sc595(uint64(0), uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  595(0, buf, 0x200): ret=0x%08X_%08X", h, l))
end

-- 608: narg=3
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc608 = make_syscall(608)
ok, ret = pcall(function() return sc608(uint64(0), uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  608(0, buf, 0x200): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- 612: narg=1
local sc612 = make_syscall(612)
ok, ret = pcall(function() return sc612(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  612(0): ret=0x%08X_%08X", h, l))
end

-- ============================================================
-- SECTION B: VM/memory group deep test
-- These likely handle memory mapping, budget, or similar
-- ============================================================
print("")
print("--- SECTION B: VM/memory group ---")

-- 585: narg=0 - simplest, just call
local sc585 = make_syscall(585)
ok, ret = pcall(function() return sc585() end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  585(): ret=0x%08X_%08X", h, l))
end

-- 624: narg=0
local sc624 = make_syscall(624)
ok, ret = pcall(function() return sc624() end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  624(): ret=0x%08X_%08X", h, l))
end

-- 559: narg=1
local sc559 = make_syscall(559)
ok, ret = pcall(function() return sc559(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  559(0): ret=0x%08X_%08X", h, l))
end

-- 547: narg=2 - try (buf, len) pattern
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc547 = make_syscall(547)
ok, ret = pcall(function() return sc547(uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  547(buf, 0x200): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
        local kptrs = scan_for_kptrs(outbuf, 0x200)
        if #kptrs > 0 then
            print("    !!! KERNEL POINTERS FOUND:")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +%03X: 0x%08X_%08X", kp[1], kp[2], kp[3]))
            end
        end
    end
end

-- 607: narg=2
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc607 = make_syscall(607)
ok, ret = pcall(function() return sc607(uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  607(buf, 0x200): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
        local kptrs = scan_for_kptrs(outbuf, 0x200)
        if #kptrs > 0 then
            print("    !!! KERNEL POINTERS:")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +%03X: 0x%08X_%08X", kp[1], kp[2], kp[3]))
            end
        end
    end
end

-- 637: narg=2
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc637 = make_syscall(637)
ok, ret = pcall(function() return sc637(uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  637(buf, 0x200): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
        local kptrs = scan_for_kptrs(outbuf, 0x200)
        if #kptrs > 0 then
            print("    !!! KERNEL POINTERS:")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +%03X: 0x%08X_%08X", kp[1], kp[2], kp[3]))
            end
        end
    end
end

-- 646: narg=1
local sc646 = make_syscall(646)
ok, ret = pcall(function() return sc646(uint64(outbuf)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  646(buf): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- 647: narg=1
local sc647 = make_syscall(647)
ok, ret = pcall(function() return sc647(uint64(outbuf)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  647(buf): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- ============================================================
-- SECTION C: Event/notification group (600-606, 611, 643)
-- ============================================================
print("")
print("--- SECTION C: Event/notification group ---")

-- 606: narg=0
local sc606 = make_syscall(606)
ok, ret = pcall(function() return sc606() end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  606(): ret=0x%08X_%08X", h, l))
end

-- 600: narg=1
local sc600 = make_syscall(600)
ok, ret = pcall(function() return sc600(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  600(0): ret=0x%08X_%08X", h, l))
end

-- 605: narg=1
local sc605 = make_syscall(605)
ok, ret = pcall(function() return sc605(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  605(0): ret=0x%08X_%08X", h, l))
end

-- 643: narg=1
local sc643 = make_syscall(643)
ok, ret = pcall(function() return sc643(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  643(0): ret=0x%08X_%08X", h, l))
end

-- ============================================================
-- SECTION D: Thread group (616, 632-634)
-- ============================================================
print("")
print("--- SECTION D: Thread group ---")

-- 632: narg=1
local sc632 = make_syscall(632)
ok, ret = pcall(function() return sc632(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  632(0): ret=0x%08X_%08X", h, l))
end

-- 633: narg=1
local sc633 = make_syscall(633)
ok, ret = pcall(function() return sc633(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  633(0): ret=0x%08X_%08X", h, l))
end

-- 616: narg=2
local sc616 = make_syscall(616)
ok, ret = pcall(function() return sc616(uint64(0), uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  616(0, 0): ret=0x%08X_%08X", h, l))
end

-- 634: narg=2
local sc634 = make_syscall(634)
ok, ret = pcall(function() return sc634(uint64(0), uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  634(0, 0): ret=0x%08X_%08X", h, l))
end

-- ============================================================
-- SECTION E: SysC group (549-556) - 8 tightly packed handlers
-- ============================================================
print("")
print("--- SECTION E: SysC group (549-556) ---")

for num = 549, 556 do
    local nargs = ({[549]=4,[550]=1,[551]=1,[552]=1,[553]=3,[554]=2,[555]=2,[556]=3})
    local na = nargs[num] or 1
    local sc = make_syscall(num)
    for i = 0, 0x100, 4 do safe_wd(outbuf + i, 0) end

    if na == 1 then
        ok, ret = pcall(function() return sc(uint64(0)) end)
    elseif na == 2 then
        ok, ret = pcall(function() return sc(uint64(outbuf), uint64(0x100)) end)
    elseif na == 3 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(outbuf), uint64(0x100)) end)
    elseif na == 4 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(outbuf), uint64(0x100), uint64(0)) end)
    end

    if ok then
        local h, l = get_hi_lo(ret)
        local extra = ""
        if to_num(ret) == 0 then
            local v = safe_rd(outbuf)
            if v and v ~= 0 then
                extra = string.format(" buf[0]=%08X", v)
            end
            local kptrs = scan_for_kptrs(outbuf, 0x100)
            if #kptrs > 0 then
                extra = extra .. " !!! KPTRS:"
                for _, kp in ipairs(kptrs) do
                    extra = extra .. string.format(" +%02X=%08X_%08X", kp[1], kp[2], kp[3])
                end
            end
        end
        print(string.format("  %d: ret=0x%08X_%08X%s", num, h, l, extra))
    else
        print(string.format("  %d: ERROR - %s", num, tostring(ret)))
    end
end

-- ============================================================
-- SECTION F: SysD group (538-546)
-- ============================================================
print("")
print("--- SECTION F: SysD group (538-546) ---")

for num = 538, 546 do
    local nargs = ({[538]=3,[539]=1,[540]=1,[541]=1,[542]=5,[543]=4,[544]=2,[545]=2,[546]=3})
    local na = nargs[num] or 1
    local sc = make_syscall(num)
    for i = 0, 0x100, 4 do safe_wd(outbuf + i, 0) end

    if na == 1 then
        ok, ret = pcall(function() return sc(uint64(0)) end)
    elseif na == 2 then
        ok, ret = pcall(function() return sc(uint64(outbuf), uint64(0x100)) end)
    elseif na == 3 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(outbuf), uint64(0x100)) end)
    elseif na == 4 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(outbuf), uint64(0x100), uint64(0)) end)
    elseif na == 5 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(outbuf), uint64(0x100), uint64(0), uint64(0)) end)
    end

    if ok then
        local h, l = get_hi_lo(ret)
        local extra = ""
        if to_num(ret) == 0 then
            local v = safe_rd(outbuf)
            if v and v ~= 0 then
                extra = string.format(" buf[0]=%08X", v)
            end
            local kptrs = scan_for_kptrs(outbuf, 0x100)
            if #kptrs > 0 then
                extra = extra .. " !!! KPTRS:"
                for _, kp in ipairs(kptrs) do
                    extra = extra .. string.format(" +%02X=%08X_%08X", kp[1], kp[2], kp[3])
                end
            end
        end
        print(string.format("  %d: ret=0x%08X_%08X%s", num, h, l, extra))
    else
        print(string.format("  %d: ERROR - %s", num, tostring(ret)))
    end
end

-- ============================================================
-- SECTION G: Miscellaneous high-value targets
-- ============================================================
print("")
print("--- SECTION G: High-value misc targets ---")

-- 640: narg=8 (!!) - most args of any syscall, likely complex operation
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc640 = make_syscall(640)
ok, ret = pcall(function() return sc640(uint64(0), uint64(outbuf), uint64(0x200),
    uint64(0), uint64(0), uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  640(0,buf,0x200,0,0,0): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- 622: narg=6 - another complex one
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc622 = make_syscall(622)
ok, ret = pcall(function() return sc622(uint64(0), uint64(0x1000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  622(mmap-like args): ret=0x%08X_%08X", h, l))
end

-- 628: narg=6
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc628 = make_syscall(628)
ok, ret = pcall(function() return sc628(uint64(outbuf), uint64(0x200), uint64(0),
    uint64(0), uint64(0), uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  628(buf,0x200,0,0,0,0): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- 648: narg=1 - near VM group
local sc648 = make_syscall(648)
ok, ret = pcall(function() return sc648(uint64(outbuf)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  648(buf): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
    end
end

-- 652: narg=2 - process group
for i = 0, 0x200, 4 do safe_wd(outbuf + i, 0) end
local sc652 = make_syscall(652)
ok, ret = pcall(function() return sc652(uint64(outbuf), uint64(0x200)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  652(buf, 0x200): ret=0x%08X_%08X", h, l))
    if to_num(ret) == 0 then
        print("    outbuf: " .. hexdump(outbuf, 64))
        local kptrs = scan_for_kptrs(outbuf, 0x200)
        if #kptrs > 0 then
            print("    !!! KERNEL POINTERS:")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +%03X: 0x%08X_%08X", kp[1], kp[2], kp[3]))
            end
        end
    end
end

-- 676: narg=0 - simple getter
local sc676 = make_syscall(676)
ok, ret = pcall(function() return sc676() end)
if ok then
    local h, l = get_hi_lo(ret)
    print(string.format("  676(): ret=0x%08X_%08X", h, l))
end

print("")
print("=== PROBE 51b COMPLETE ===")
