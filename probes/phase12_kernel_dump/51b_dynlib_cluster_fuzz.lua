-- CRASH_CLASS: MODERATE
-- PROBE 51b: Fuzz the dynlib syscall cluster (661-670) identified from kernel dump
--
-- Context: Kernel dump analysis revealed syscalls 661-670 are massive handlers
-- (10-20KB each) in the dynlib code region. These are the most complex Sony
-- custom syscalls and most likely to contain exploitable bugs. We also test
-- syscall 522 (7873B handler near mmap) and 601 (10285B).

print("=== PROBE 51b: DYNLIB CLUSTER FUZZ (661-670, 522, 601, 622) ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

-- Get PID and module base for context
local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- Get eboot base via dynlib_get_info
local info = memory.alloc(0x200)
safe_wd(info, 0x160) -- size field
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end) -- handle 0 = eboot
local eboot_lo = safe_rd(info + 0x108) or 0
local eboot_hi = safe_rd(info + 0x10C) or 0
print(string.format("Eboot base: 0x%X%08X", eboot_hi, eboot_lo))

-- Allocate buffers
local buf1 = memory.alloc(0x4000)
local buf2 = memory.alloc(0x4000)
local buf3 = memory.alloc(0x4000)
local buf4 = memory.alloc(0x4000)
local buf5 = memory.alloc(0x4000)
local buf6 = memory.alloc(0x4000)

-- Zero all buffers
for i = 0, 0x3FF0, 4 do
    pcall(function() memory.write_dword(buf1 + i, 0) end)
    pcall(function() memory.write_dword(buf2 + i, 0) end)
    pcall(function() memory.write_dword(buf3 + i, 0) end)
    pcall(function() memory.write_dword(buf4 + i, 0) end)
    pcall(function() memory.write_dword(buf5 + i, 0) end)
    pcall(function() memory.write_dword(buf6 + i, 0) end)
end

-- Test each syscall with various argument patterns
local targets = {
    {num=661, narg=4, desc="dynlib region, 20384B"},
    {num=662, narg=3, desc="dynlib region, 20368B"},
    {num=663, narg=5, desc="dynlib region, 18080B"},
    {num=664, narg=3, desc="dynlib region, 14560B"},
    {num=665, narg=2, desc="dynlib region, 12832B"},
    {num=666, narg=3, desc="dynlib region, 12816B"},
    {num=668, narg=2, desc="dynlib region, 20400B"},
    {num=669, narg=5, desc="dynlib region, 10288B"},
    {num=670, narg=3, desc="dynlib region"},
    {num=522, narg=6, desc="near mmap, 7873B"},
    {num=601, narg=3, desc="complex op, 10285B"},
    {num=622, narg=6, desc="LARGEST handler, 20795B"},
}

print("")
print("--- PHASE 1: Zero-arg baseline ---")
print("")

for _, t in ipairs(targets) do
    local sc = make_syscall(t.num)
    local ok, ret = pcall(function() return sc() end)
    if ok then
        local h, l = get_hi_lo(ret)
        print(string.format("[%d] (%s) ret=%d (h=0x%X l=0x%X)", t.num, t.desc, to_num(ret), h, l))
    else
        print(string.format("[%d] (%s) CRASH: %s", t.num, t.desc, tostring(ret)))
    end
end

print("")
print("--- PHASE 2: Buffer pointer arguments ---")
print("")

-- Try with buffer pointers as arguments (simulating valid userland pointers)
for _, t in ipairs(targets) do
    local sc = make_syscall(t.num)

    -- Pattern A: first arg = buffer pointer
    local ok, ret = pcall(function()
        if t.narg == 2 then
            return sc(uint64(buf1), uint64(0x1000))
        elseif t.narg == 3 then
            return sc(uint64(buf1), uint64(buf2), uint64(0x1000))
        elseif t.narg == 4 then
            return sc(uint64(buf1), uint64(buf2), uint64(buf3), uint64(0x1000))
        elseif t.narg == 5 then
            return sc(uint64(buf1), uint64(buf2), uint64(buf3), uint64(buf4), uint64(0x1000))
        elseif t.narg == 6 then
            return sc(uint64(buf1), uint64(buf2), uint64(buf3), uint64(buf4), uint64(buf5), uint64(0x1000))
        else
            return sc(uint64(buf1))
        end
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        print(string.format("[%d] buf args: ret=%d (h=0x%X l=0x%X)", t.num, to_num(ret), h, l))
    else
        print(string.format("[%d] buf args: CRASH: %s", t.num, tostring(ret)))
    end
end

print("")
print("--- PHASE 3: Dynlib handle-based arguments ---")
print("")

-- The 661-670 cluster is in the dynlib region. Try with dynlib handles.
-- Handle 0 = eboot, handles 1-38 = loaded modules
for _, handle in ipairs({0, 1, 2, 3, 4, 5, 10, 20}) do
    for _, num in ipairs({661, 662, 663, 664, 665, 666, 668, 669, 670}) do
        local sc = make_syscall(num)
        local narg = 0
        for _, t in ipairs(targets) do
            if t.num == num then narg = t.narg; break end
        end

        local ok, ret = pcall(function()
            if narg == 2 then
                return sc(uint64(handle), uint64(buf1))
            elseif narg == 3 then
                return sc(uint64(handle), uint64(buf1), uint64(0x1000))
            elseif narg == 4 then
                return sc(uint64(handle), uint64(buf1), uint64(buf2), uint64(0x1000))
            elseif narg == 5 then
                return sc(uint64(handle), uint64(buf1), uint64(buf2), uint64(buf3), uint64(0x1000))
            else
                return sc(uint64(handle))
            end
        end)
        if ok then
            local r = to_num(ret)
            if r ~= -1 and r ~= 78 then
                print(string.format("[%d] handle=%d: ret=%d", num, handle, r))
            end
        else
            print(string.format("[%d] handle=%d: CRASH: %s", num, handle, tostring(ret)))
        end
    end
end

-- Check if any buffers were modified by the dynlib syscalls
print("")
print("--- Checking buf1 for kernel data ---")
local found_data = false
for i = 0, 0x100, 4 do
    local v = safe_rd(buf1 + i)
    if v and v ~= 0 then
        found_data = true
        print(string.format("  buf1+%d: 0x%08X", i, v))
    end
end
if not found_data then print("  buf1 unchanged") end

print("")
print("--- PHASE 4: Syscall 522 (near mmap, narg=6) ---")
print("")

-- 522 is near mmap handlers. Try mmap-like arguments.
local sc522 = make_syscall(522)

-- Pattern: (addr, len, prot, flags, fd, offset) like mmap
local mmap_tests = {
    {0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0, "anon RW"},
    {0, 0x4000, 1, 0x1002, 0xFFFFFFFF, 0, "anon R"},
    {0, 0x4000, 0x33, 0x1002, 0xFFFFFFFF, 0, "anon RW like GPU"},
    {0, 0x10000, 3, 2, 0xFFFFFFFF, 0, "private anon"},
}

for _, test in ipairs(mmap_tests) do
    local ok, ret = pcall(function()
        return sc522(uint64(test[1]), uint64(test[2]), uint64(test[3]),
                      uint64(test[4]), uint64(test[5]), uint64(test[6]))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        print(string.format("  522(%s): ret=0x%X%08X", test[7], h, l))
        -- If it returned an address, try reading from it
        if h > 0 and h < 0xFFFF0000 then
            local rd = safe_rd(ret)
            if rd then
                print(string.format("    -> readable! first dword: 0x%08X", rd))
            end
        end
    else
        print(string.format("  522(%s): CRASH: %s", test[7], tostring(ret)))
    end
end

print("")
print("--- PHASE 5: Syscall 622 deep probe (largest, 20KB, narg=6) ---")
print("")

local sc622 = make_syscall(622)

-- Try various argument patterns for the largest handler
local test_patterns = {
    {"zeros", 0, 0, 0, 0, 0, 0},
    {"buf+size", buf1, 0x1000, 0, 0, 0, 0},
    {"buf+buf+size", buf1, buf2, 0x1000, 0, 0, 0},
    {"cmd=1", 1, buf1, 0x1000, 0, 0, 0},
    {"cmd=2", 2, buf1, 0x1000, 0, 0, 0},
    {"cmd=3", 3, buf1, 0x1000, 0, 0, 0},
    {"cmd=0x10", 0x10, buf1, 0x1000, 0, 0, 0},
    {"cmd=0x100", 0x100, buf1, 0x1000, buf2, buf3, 0x1000},
    {"pid+buf", pid, buf1, 0x1000, 0, 0, 0},
    {"fd=3+buf", 3, buf1, 0x1000, buf2, 0, 0},
}

for _, test in ipairs(test_patterns) do
    -- Zero buffers before each test
    for i = 0, 0xFF, 4 do
        pcall(function() memory.write_dword(buf1 + i, 0xDEADBEEF) end)
        pcall(function() memory.write_dword(buf2 + i, 0xDEADBEEF) end)
    end

    local ok, ret = pcall(function()
        return sc622(uint64(test[2]), uint64(test[3]), uint64(test[4]),
                      uint64(test[5]), uint64(test[6]), uint64(test[7]))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local r = to_num(ret)
        local line = string.format("  622(%s): ret=%d (0x%X%08X)", test[1], r, h, l)

        -- Check if buf1 was modified
        local first_mod = nil
        for i = 0, 0xFF, 4 do
            local v = safe_rd(buf1 + i)
            if v and v ~= 0xDEADBEEF then
                first_mod = string.format("buf1+%d=0x%08X", i, v)
                break
            end
        end
        if first_mod then
            line = line .. "  [" .. first_mod .. "]"
        end
        print(line)
    else
        print(string.format("  622(%s): CRASH: %s", test[1], tostring(ret)))
    end
end

print("")
print("--- PHASE 6: Syscall 601 deep probe (10285B, narg=3) ---")
print("")

local sc601 = make_syscall(601)
local patterns601 = {
    {"zeros", 0, 0, 0},
    {"buf+size", buf1, 0x1000, 0},
    {"cmd=1+buf", 1, buf1, 0x1000},
    {"cmd=2+buf", 2, buf1, 0x1000},
    {"pid+buf+size", pid, buf1, 0x1000},
    {"fd=3+buf+size", 3, buf1, 0x1000},
    {"0xFF+buf", 0xFF, buf1, 0x1000},
}

for _, test in ipairs(patterns601) do
    for i = 0, 0xFF, 4 do
        pcall(function() memory.write_dword(buf1 + i, 0xCAFEBABE) end)
    end

    local ok, ret = pcall(function()
        return sc601(uint64(test[2]), uint64(test[3]), uint64(test[4]))
    end)
    if ok then
        local r = to_num(ret)
        local line = string.format("  601(%s): ret=%d", test[1], r)
        local first_mod = nil
        for i = 0, 0xFF, 4 do
            local v = safe_rd(buf1 + i)
            if v and v ~= 0xCAFEBABE then
                first_mod = string.format("buf+%d=0x%08X", i, v)
                break
            end
        end
        if first_mod then line = line .. "  [" .. first_mod .. "]" end
        print(line)
    else
        print(string.format("  601(%s): CRASH: %s", test[1], tostring(ret)))
    end
end

print("")
print("=== PROBE 51b COMPLETE ===")
