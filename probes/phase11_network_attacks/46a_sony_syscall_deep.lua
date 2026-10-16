-- CRASH_CLASS: LOW
-- PROBE 46a: Sony Syscall 557/620 Deep Investigation
--
-- Context: Phase 10 sweep (probe 43g) found syscall 557 returns 16901 and
-- syscall 620 returns 0 when called with zero args. Both are live Sony-specific
-- syscalls. 557's non-trivial return (0x4205) suggests it may be a query
-- function that returns data or a handle. We need to identify what these
-- do and whether they leak kernel pointers in output buffers.
--
-- On PS4, known Sony syscalls in this range include get_proc_type_info,
-- get_authinfo, budget ops, and others that sometimes expose internal state.

print("=== PROBE 46a: SONY SYSCALL 557/620 DEEP ===")
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

local pid = syscall.getpid():tonumber()
print("pid: " .. pid)

local function hexdump(addr, len, label)
    print(label .. ":")
    for row = 0, len - 1, 16 do
        local hex = ""
        for col = 0, 15 do
            if row + col < len then
                local ok_b, b = pcall(function()
                    return memory.read_byte(addr + row + col)
                end)
                if ok_b then
                    hex = hex .. string.format("%02x ", to_num(b))
                else
                    hex = hex .. "?? "
                end
            end
        end
        print(string.format("  +%03x: %s", row, hex))
    end
end

local function scan_kptrs(addr, len, label)
    local found = 0
    for off = 0, len - 8, 8 do
        local val = safe_rq(addr + off)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                print(string.format("  *** KERNEL PTR at +%03x: %08X_%08X", off, h, l))
                found = found + 1
            end
        end
    end
    if found == 0 then
        print("  " .. label .. ": no kernel pointers")
    end
    return found
end

local function fill_dead(addr, len)
    for i = 0, len - 1, 4 do safe_wd(addr + i, 0xDEADDEAD) end
end

local function check_modified(addr, len)
    for i = 0, len - 1, 4 do
        local v = safe_rd(addr + i)
        if v and v ~= 0xDEADDEAD then return true end
    end
    return false
end

-- ============================================
-- SECTION A: Syscall 557 — argument sweep
-- ============================================
print("")
print("=== A: SYSCALL 557 ARG SWEEP ===")

local sc557 = make_syscall(557)

local ok, ret = pcall(function() return sc557(uint64(0)) end)
print("557(0): ok=" .. tostring(ok) .. " ret=" .. (ok and tostring(to_num(ret)) or tostring(ret)))

local ok2, ret2 = pcall(function() return sc557(uint64(0)) end)
print("557(0) again: ret=" .. (ok2 and tostring(to_num(ret2)) or "-999"))

for _, arg in ipairs({1, 2, pid, 0x100, 0x1000, 0xFFFF, 0x10000, 0xFFFFFFFF}) do
    local ok_a, rv = pcall(function() return sc557(uint64(arg)) end)
    print(string.format("557(0x%X): ret=%s", arg, ok_a and tostring(to_num(rv)) or "CRASH"))
end

-- Multi-arg patterns
for _, args in ipairs({
    {0, 0},
    {1, 0},
    {0, 1},
    {pid, 0},
    {0, pid},
    {1, 1},
    {0, 0, 0},
    {pid, 0, 0},
    {0, 0, 0, 0},
}) do
    local a1 = uint64(args[1])
    local a2 = args[2] and uint64(args[2]) or nil
    local a3 = args[3] and uint64(args[3]) or nil
    local a4 = args[4] and uint64(args[4]) or nil
    local tag = "557("
    for i, v in ipairs(args) do
        if i > 1 then tag = tag .. "," end
        tag = tag .. tostring(v)
    end
    tag = tag .. ")"
    local ok_m, rv_m
    if a4 then
        ok_m, rv_m = pcall(function() return sc557(a1, a2, a3, a4) end)
    elseif a3 then
        ok_m, rv_m = pcall(function() return sc557(a1, a2, a3) end)
    elseif a2 then
        ok_m, rv_m = pcall(function() return sc557(a1, a2) end)
    else
        ok_m, rv_m = pcall(function() return sc557(a1) end)
    end
    print(tag .. ": ret=" .. (ok_m and tostring(to_num(rv_m)) or "CRASH"))
end

-- ============================================
-- SECTION B: Syscall 557 — output buffer tests
-- ============================================
print("")
print("=== B: 557 OUTPUT BUFFER TESTS ===")

local buf = memory.alloc(0x400)

-- Pattern 1: buf as arg1
fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc557(uint64(buf)) end)
print("557(buf): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** BUFFER MODIFIED (arg1=buf)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "557(buf)")
end

-- Pattern 2: buf, size
fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc557(uint64(buf), uint64(0x400)) end)
print("557(buf, 0x400): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** BUFFER MODIFIED (buf,size)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "557(buf,0x400)")
end

-- Pattern 3: pid, buf
fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc557(uint64(pid), uint64(buf)) end)
print("557(pid, buf): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** BUFFER MODIFIED (pid,buf)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "557(pid,buf)")
end

-- Pattern 4: pid, buf, size
fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc557(uint64(pid), uint64(buf), uint64(0x400)) end)
print("557(pid, buf, 0x400): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** BUFFER MODIFIED (pid,buf,size)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "557(pid,buf,0x400)")
end

-- Pattern 5: buf, &sizep (sysctl-style)
local sizep = memory.alloc(8)
fill_dead(buf, 0x400)
safe_wd(sizep, 0x400)
safe_wd(sizep + 4, 0)
ok, ret = pcall(function() return sc557(uint64(buf), uint64(sizep)) end)
local new_sz = safe_rd(sizep)
print("557(buf, &size): ret=" .. (ok and tostring(to_num(ret)) or "CRASH") ..
      " size_after=" .. (new_sz or "nil"))
if check_modified(buf, 0x100) then
    print("*** BUFFER MODIFIED (buf,&size)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "557(buf,&sizep)")
end

-- Pattern 6: pid, buf, &sizep
fill_dead(buf, 0x400)
safe_wd(sizep, 0x400)
ok, ret = pcall(function() return sc557(uint64(pid), uint64(buf), uint64(sizep)) end)
new_sz = safe_rd(sizep)
print("557(pid, buf, &size): ret=" .. (ok and tostring(to_num(ret)) or "CRASH") ..
      " size_after=" .. (new_sz or "nil"))
if check_modified(buf, 0x100) then
    print("*** BUFFER MODIFIED (pid,buf,&size)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "557(pid,buf,&sizep)")
end

-- ============================================
-- SECTION C: Syscall 557 — struct-input patterns
-- ============================================
print("")
print("=== C: 557 STRUCT-INPUT PATTERNS ===")

local st = memory.alloc(0x200)

-- Some Sony syscalls expect a struct with size/version at offset 0
-- Pattern: {.size = sizeof(struct)}
for i = 0, 0x1FF, 4 do safe_wd(st + i, 0) end
safe_wd(st, 0x200)
ok, ret = pcall(function() return sc557(uint64(st)) end)
print("557({size=0x200}): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
local st0 = safe_rd(st)
local st4 = safe_rd(st + 4)
local st8 = safe_rd(st + 8)
if st0 ~= 0x200 or st4 ~= 0 or st8 ~= 0 then
    print("  struct modified: [0]=" .. (st0 or "?") .. " [4]=" .. (st4 or "?") ..
          " [8]=" .. (st8 or "?"))
    hexdump(st, 64, "  struct dump")
    scan_kptrs(st, 0x200, "557 struct")
end

-- Pattern: {.version=1, .size=sizeof}
for i = 0, 0x1FF, 4 do safe_wd(st + i, 0) end
safe_wd(st, 1)
safe_wd(st + 4, 0x200)
ok, ret = pcall(function() return sc557(uint64(st)) end)
print("557({ver=1,size=0x200}): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))

-- Pattern: dynlib_get_info style (size at offset 0)
for i = 0, 0x1FF, 4 do safe_wd(st + i, 0) end
safe_wd(st, 0x160)
ok, ret = pcall(function() return sc557(uint64(0), uint64(st)) end)
print("557(0, {size=0x160}): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(st + 4, 0x50) then
    print("  struct modified after offset 4!")
    hexdump(st, 64, "  dump")
end

-- ============================================
-- SECTION D: Syscall 557 — return value analysis
-- ============================================
print("")
print("=== D: 557 RETURN VALUE ANALYSIS ===")

print("16901 = 0x" .. string.format("%X", 16901))
print("16901 / 16384 = " .. string.format("%.4f", 16901 / 16384) .. " (pages?)")
print("16901 / 4096 = " .. string.format("%.4f", 16901 / 4096))
print("16901 binary = " .. string.format("%016b", 16901))

-- Call 10x to check if return value is stable or changing
print("stability check:")
local vals = {}
for i = 1, 10 do
    ok, ret = pcall(function() return sc557(uint64(0)) end)
    local r = ok and to_num(ret) or -999
    vals[i] = r
    if i <= 5 or r ~= vals[1] then
        print("  call " .. i .. ": " .. r)
    end
end
local all_same = true
for i = 2, 10 do
    if vals[i] ~= vals[1] then all_same = false break end
end
print("return value " .. (all_same and "STABLE" or "VARIES") .. " across 10 calls")

-- ============================================
-- SECTION E: Syscall 620 — same treatment
-- ============================================
print("")
print("=== E: SYSCALL 620 INVESTIGATION ===")

local sc620 = make_syscall(620)

ok, ret = pcall(function() return sc620(uint64(0)) end)
print("620(0): ok=" .. tostring(ok) .. " ret=" .. (ok and tostring(to_num(ret)) or tostring(ret)))

for _, arg in ipairs({1, 2, pid, 0x100, 0xFFFF}) do
    local ok_a, rv = pcall(function() return sc620(uint64(arg)) end)
    print(string.format("620(0x%X): ret=%s", arg, ok_a and tostring(to_num(rv)) or "CRASH"))
end

-- Buffer tests
fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc620(uint64(buf)) end)
print("620(buf): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** 620 BUFFER MODIFIED! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "620(buf)")
end

fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc620(uint64(buf), uint64(0x400)) end)
print("620(buf, 0x400): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** 620 BUFFER MODIFIED (buf,size)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "620(buf,0x400)")
end

fill_dead(buf, 0x400)
ok, ret = pcall(function() return sc620(uint64(pid), uint64(buf), uint64(0x400)) end)
print("620(pid, buf, 0x400): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(buf, 0x100) then
    print("*** 620 BUFFER MODIFIED (pid,buf,size)! ***")
    hexdump(buf, 128, "  first 128B")
    scan_kptrs(buf, 0x400, "620(pid,buf,0x400)")
end

-- Struct input test
for i = 0, 0x1FF, 4 do safe_wd(st + i, 0) end
safe_wd(st, 0x200)
ok, ret = pcall(function() return sc620(uint64(st)) end)
print("620({size=0x200}): ret=" .. (ok and tostring(to_num(ret)) or "CRASH"))
if check_modified(st + 4, 0x50) then
    hexdump(st, 64, "  620 struct")
    scan_kptrs(st, 0x200, "620 struct")
end

-- ============================================
-- SECTION F: Neighbor sweep 550-625
-- ============================================
print("")
print("=== F: NEIGHBOR SWEEP 550-625 ===")

local known = {
    [538] = true, [539] = true,  -- evf
    [547] = true, [548] = true, [549] = true, [550] = true, [551] = true, [552] = true, -- dmem
    [557] = true, [620] = true,  -- already tested above
    [585] = true,  -- mtypeprotect
    [588] = true,  -- munmap
    [592] = true, [593] = true,  -- dynlib
}

local alive = {}
for num = 550, 625 do
    if not known[num] then
        local sc = make_syscall(num)
        local ok_s, rv_s = pcall(function() return sc(uint64(0)) end)
        if ok_s then
            local r = to_num(rv_s)
            if r ~= -1 then
                print(string.format("  syscall %d: ret=%d ***ALIVE***", num, r))
                alive[#alive + 1] = {num = num, ret = r}
            end
        end
    end
end

-- For any newly-found alive syscalls, try output buffer
if #alive > 0 then
    print("")
    print("=== G: ALIVE NEIGHBOR BUFFER TESTS ===")
    for _, entry in ipairs(alive) do
        local sc = make_syscall(entry.num)
        fill_dead(buf, 0x400)
        local ok_b, rv_b = pcall(function() return sc(uint64(buf), uint64(0x400)) end)
        print(string.format("  %d(buf, 0x400): ret=%s",
            entry.num, ok_b and tostring(to_num(rv_b)) or "CRASH"))
        if check_modified(buf, 0x100) then
            print("  *** BUFFER MODIFIED! ***")
            hexdump(buf, 64, "    " .. entry.num .. " output")
            scan_kptrs(buf, 0x400, tostring(entry.num))
        end
    end
end

print("")
print("=== PROBE 46a COMPLETE ===")
