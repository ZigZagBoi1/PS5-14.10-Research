-- CRASH_CLASS: LOW
-- PROBE 43k: sceKernelGetCpuUsage deep investigation
--
-- Context: Probe 42f found syscall 617 (sceKernelGetCpuUsage) returns ret=0
-- with an empty 8-byte buffer. This is one of only TWO Sony syscalls that
-- succeeded (the other being 585/mtypeprotect). A larger output buffer and
-- systematic argument testing may reveal CPU usage data structures that
-- contain kernel pointers (scheduler data, per-CPU structs, thread lists).

print("=== PROBE 43k: sceKernelGetCpuUsage DEEP ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

local pid = to_num(syscall.getpid())
print("pid: " .. pid)

local sc617 = make_syscall(617)

-- === STEP 1: Basic call with various buffer sizes ===
print("--- STEP 1: Buffer size sweep ---")
local sizes = {8, 16, 32, 64, 128, 256, 512, 1024, 4096}
for _, sz in ipairs(sizes) do
    local buf = memory.alloc(sz + 16)
    for i = 0, math.min(sz - 1, 255) do
        pcall(function() memory.write_byte(buf + i, 0xAA) end)
    end
    local ok, ret = pcall(function()
        return sc617(uint64(buf), uint64(sz), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  size=%d: CRASH", sz))
    else
        local r = to_num(ret)
        local changed = 0
        for i = 0, math.min(sz - 1, 255) do
            local b = safe_rb(buf + i)
            if b and b ~= 0xAA then changed = changed + 1 end
        end
        print(string.format("  size=%d: ret=%d changed_bytes=%d", sz, r, changed))
        if changed > 0 then
            local limit = math.min(changed + 16, sz, 256)
            for row = 0, limit - 1, 16 do
                local hex = ""
                for col = 0, 15 do
                    if row + col < sz then
                        local b = safe_rb(buf + row + col)
                        if b then
                            hex = hex .. string.format("%02X ", b)
                        else
                            hex = hex .. "?? "
                        end
                    end
                end
                print(string.format("    +%03X: %s", row, hex))
            end
        end
    end
end

-- === STEP 2: Try with arg1=cpu_index (0-15, PS5 has 16 logical cores) ===
print("")
print("--- STEP 2: Per-CPU query ---")
local buf2 = memory.alloc(256)
for cpu = 0, 15 do
    for i = 0, 63 do
        pcall(function() memory.write_byte(buf2 + i, 0) end)
    end
    local ok, ret = pcall(function()
        return sc617(uint64(cpu), uint64(buf2), uint64(64), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  cpu=%d: CRASH", cpu))
    else
        local r = to_num(ret)
        local nonzero = 0
        for i = 0, 63 do
            local b = safe_rb(buf2 + i)
            if b and b ~= 0 then nonzero = nonzero + 1 end
        end
        if r == 0 or nonzero > 0 then
            print(string.format("  cpu=%d: ret=%d nonzero=%d", cpu, r, nonzero))
            if nonzero > 0 then
                for off = 0, 56, 8 do
                    local val = safe_rq(buf2 + off)
                    if val then
                        local h, l = get_hi_lo(val)
                        if h ~= 0 or l ~= 0 then
                            local tag = ""
                            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                                tag = " KPTR!"
                            end
                            print(string.format("    +%02X: %08X_%08X%s", off, h, l, tag))
                        end
                    end
                end
            end
        end
    end
end

-- === STEP 3: Try arg patterns from Sony SDK style ===
print("")
print("--- STEP 3: SDK-style argument patterns ---")
local patterns = {
    {0, 0, 0, 0, 0, 0, "null args"},
    {1, 0, 0, 0, 0, 0, "arg0=1"},
    {0xFFFFFFFF, 0, 0, 0, 0, 0, "arg0=-1 (all CPUs?)"},
}
local buf3 = memory.alloc(4096)
for _, p in ipairs(patterns) do
    for i = 0, 255 do
        pcall(function() memory.write_byte(buf3 + i, 0) end)
    end
    local ok, ret = pcall(function()
        return sc617(uint64(p[1]), uint64(p[2]), uint64(buf3),
            uint64(256), uint64(p[5]), uint64(p[6]))
    end)
    if not ok then
        print(string.format("  %s: CRASH", p[7]))
    else
        local r = to_num(ret)
        local nonzero = 0
        for i = 0, 255 do
            local b = safe_rb(buf3 + i)
            if b and b ~= 0 then nonzero = nonzero + 1 end
        end
        print(string.format("  %s: ret=%d nonzero=%d", p[7], r, nonzero))
    end
end

-- === STEP 4: Neighboring Sony syscalls that might be related ===
print("")
print("--- STEP 4: Nearby Sony syscalls (615-620) ---")
local buf4 = memory.alloc(256)
for num = 615, 620 do
    if num ~= 617 then
        for i = 0, 63 do
            pcall(function() memory.write_byte(buf4 + i, 0) end)
        end
        local sc = make_syscall(num)
        local ok, ret = pcall(function()
            return sc(uint64(buf4), uint64(64), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        if not ok then
            print(string.format("  syscall %d: CRASH/KILL", num))
        else
            local r = to_num(ret)
            local nonzero = 0
            for i = 0, 63 do
                local b = safe_rb(buf4 + i)
                if b and b ~= 0 then nonzero = nonzero + 1 end
            end
            print(string.format("  syscall %d: ret=%d nonzero=%d", num, r, nonzero))
            if nonzero > 0 then
                for off = 0, 56, 8 do
                    local val = safe_rq(buf4 + off)
                    if val then
                        local h, l = get_hi_lo(val)
                        if h ~= 0 or l ~= 0 then
                            print(string.format("    +%02X: %08X_%08X", off, h, l))
                        end
                    end
                end
            end
        end
    end
end

-- === STEP 5: Also test 585 (mtypeprotect) with actual arguments ===
print("")
print("--- STEP 5: sceKernelMtypeprotect(585) deep test ---")
local sc585 = make_syscall(585)

-- Get a RW page to try changing protections on
local sc_mmap = make_syscall(477)
local ok_mmap, test_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_mmap then
    local ph, pl = get_hi_lo(test_page)
    print(string.format("  test page: %08X_%08X", ph, pl))

    -- Try mtypeprotect with different protection values
    local prots = {
        {7, "RWX"},
        {5, "RX"},
        {3, "RW"},
        {4, "X only"},
        {1, "R only"},
    }
    for _, pr in ipairs(prots) do
        local ok, ret = pcall(function()
            return sc585(test_page, uint64(0x4000), uint64(pr[1]),
                uint64(0), uint64(0), uint64(0))
        end)
        if not ok then
            print(string.format("  prot=%d (%s): CRASH", pr[1], pr[2]))
        else
            print(string.format("  prot=%d (%s): ret=%d", pr[1], pr[2], to_num(ret)))
        end
    end

    -- If RWX succeeded, try writing + executing
    local ok_rwx, ret_rwx = pcall(function()
        return sc585(test_page, uint64(0x4000), uint64(7),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok_rwx and to_num(ret_rwx) >= 0 then
        print("  RWX may have succeeded! Testing write then read...")
        safe_wd(pl, 0xDEADBEEF)
        local readback = safe_rd(pl)
        print(string.format("  write/read test: %08X", readback or 0))
    end
end

print("")
print("=== PROBE 43k COMPLETE ===")
