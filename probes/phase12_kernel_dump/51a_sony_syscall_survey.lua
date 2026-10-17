-- CRASH_CLASS: MODERATE
-- PROBE 51a: Survey all Sony custom syscalls (532-676) via make_syscall
--
-- Context: Kernel dump analysis of FW 13.60 revealed 115 Sony-specific syscalls
-- in the 532-676 range. We've only tested 557, 593, 620 on 14.10.
-- This probe calls each with safe arguments (zeros/small values) to determine:
--   1. Which ones are implemented (vs nosys/ENOSYS=78)
--   2. Which ones are sandbox-killed (instant process termination)
--   3. Which ones return interesting values
--   4. Which ones crash with specific arguments (potential attack surface)

print("=== PROBE 51a: SONY SYSCALL SURVEY (532-676) ===")
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

-- Get PID for reference
local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- Allocate a buffer for syscalls that need pointer args
local buf = memory.alloc(0x1000)
for i = 0, 0xFF0, 4 do
    pcall(function() memory.write_dword(buf, 0) end)
end

local implemented = {}
local nosys = {}
local killed = {}
local errors = {}

print("")
print("--- PHASE 1: Zero-argument scan (all 145 syscalls) ---")
print("")

for num = 532, 676 do
    local sc = make_syscall(num)
    local ok, ret = pcall(function() return sc() end)

    if not ok then
        print(string.format("[%d] CRASH/KILL: %s", num, tostring(ret)))
        killed[num] = tostring(ret)
    else
        local h, l = get_hi_lo(ret)
        local rval = to_num(ret)

        if rval == 78 or l == 78 then
            nosys[num] = true
        elseif rval == -1 or l == 0xFFFFFFFF then
            -- Error return but implemented
            implemented[num] = {ret = -1, note = "error"}
            print(string.format("[%d] ret=-1 (implemented, needs args)", num))
        elseif rval == 0 then
            implemented[num] = {ret = 0, note = "success_noarg"}
            print(string.format("[%d] ret=0 (SUCCESS with no args!)", num))
        else
            implemented[num] = {ret = rval, h = h, l = l, note = "value"}
            print(string.format("[%d] ret=%d (h=%d l=%d)", num, rval, h, l))
        end
    end
end

print("")
print("--- PHASE 1 SUMMARY ---")
local impl_count = 0
local nosys_count = 0
local kill_count = 0
for _ in pairs(implemented) do impl_count = impl_count + 1 end
for _ in pairs(nosys) do nosys_count = nosys_count + 1 end
for _ in pairs(killed) do kill_count = kill_count + 1 end
print("Implemented: " .. impl_count)
print("Nosys/ENOSYS: " .. nosys_count)
print("Killed/Crashed: " .. kill_count)

-- Phase 2: For implemented syscalls that returned -1, try with buffer argument
print("")
print("--- PHASE 2: Retry error syscalls with buffer arg ---")
print("")

for num = 532, 676 do
    if implemented[num] and implemented[num].ret == -1 then
        local sc = make_syscall(num)

        -- Try with buffer pointer as first arg
        local ok2, ret2 = pcall(function()
            return sc(uint64(buf))
        end)
        if ok2 then
            local h2, l2 = get_hi_lo(ret2)
            local r2 = to_num(ret2)
            if r2 ~= -1 and r2 ~= 78 then
                print(string.format("[%d] with buf arg: ret=%d (h=%d l=%d)", num, r2, h2, l2))
                implemented[num].with_buf = r2
            end
        end

        -- Try with small integer as first arg
        local ok3, ret3 = pcall(function()
            return sc(uint64(1))
        end)
        if ok3 then
            local h3, l3 = get_hi_lo(ret3)
            local r3 = to_num(ret3)
            if r3 ~= -1 and r3 ~= 78 then
                print(string.format("[%d] with arg=1: ret=%d (h=%d l=%d)", num, r3, h3, l3))
                implemented[num].with_one = r3
            end
        end
    end
end

-- Phase 3: For success syscalls, check if return value leaks kernel info
print("")
print("--- PHASE 3: Analyze successful returns for kernel pointers ---")
print("")

for num = 532, 676 do
    if implemented[num] and implemented[num].ret == 0 then
        -- Call again and check all possible return locations
        local sc = make_syscall(num)

        -- Check if buffer was modified
        local pre = {}
        for i = 0, 63, 4 do
            pcall(function() memory.write_dword(buf + i, 0xDEADBEEF) end)
        end

        pcall(function() sc(uint64(buf), uint64(0x40)) end)

        local modified = false
        for i = 0, 63, 4 do
            local ok, val = pcall(function() return memory.read_dword(buf + i) end)
            if ok then
                local v = to_num(val)
                if v ~= 0xDEADBEEF then
                    modified = true
                    print(string.format("[%d] buf+%d modified: 0x%08X", num, i, v))
                end
            end
        end
        if not modified then
            print(string.format("[%d] ret=0, buffer not modified", num))
        end
    end
end

-- Phase 4: Try the known interesting ones from kernel dump with proper args
print("")
print("--- PHASE 4: Targeted tests for interesting syscalls ---")
print("")

-- Syscall 560: tiny wrapper (38B), narg=1 — reads global, compares to arg
print("Testing 560 (tiny wrapper, narg=1):")
for _, testval in ipairs({0, 1, 2, 3, 4, 0xFF, 0xFFFF}) do
    local sc = make_syscall(560)
    local ok, ret = pcall(function() return sc(uint64(testval)) end)
    if ok then
        print(string.format("  560(%d) = %d", testval, to_num(ret)))
    else
        print(string.format("  560(%d) = CRASH: %s", testval, tostring(ret)))
    end
end

-- Syscall 585: tiny no-arg (87B)
print("\nTesting 585 (tiny, narg=0):")
local sc585 = make_syscall(585)
local ok585, ret585 = pcall(function() return sc585() end)
if ok585 then
    local h, l = get_hi_lo(ret585)
    print(string.format("  585() = %d (h=0x%X l=0x%X)", to_num(ret585), h, l))
else
    print("  585() = CRASH: " .. tostring(ret585))
end

-- Syscall 606: tiny no-arg (34B)
print("\nTesting 606 (tiny, narg=0):")
local sc606 = make_syscall(606)
local ok606, ret606 = pcall(function() return sc606() end)
if ok606 then
    local h, l = get_hi_lo(ret606)
    print(string.format("  606() = %d (h=0x%X l=0x%X)", to_num(ret606), h, l))
else
    print("  606() = CRASH: " .. tostring(ret606))
end

-- Syscall 640: 8-byte stub (narg=8) — just a jump
print("\nTesting 640 (jump stub, narg=8):")
local sc640 = make_syscall(640)
local ok640, ret640 = pcall(function()
    return sc640(uint64(0), uint64(0), uint64(0), uint64(0),
                 uint64(0), uint64(0))
end)
if ok640 then
    print(string.format("  640() = %d", to_num(ret640)))
else
    print("  640() = CRASH: " .. tostring(ret640))
end

-- Syscall 622: largest handler (20KB, narg=6)
print("\nTesting 622 (largest, narg=6):")
local sc622 = make_syscall(622)
local ok622, ret622 = pcall(function()
    return sc622(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok622 then
    print(string.format("  622(0,0,0,0,0,0) = %d", to_num(ret622)))
else
    print("  622() = CRASH: " .. tostring(ret622))
end

-- Syscall 532: first Sony range (narg=5)
print("\nTesting 532 (narg=5):")
local sc532 = make_syscall(532)
local ok532, ret532 = pcall(function()
    return sc532(uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0))
end)
if ok532 then
    print(string.format("  532() = %d", to_num(ret532)))
else
    print("  532() = CRASH: " .. tostring(ret532))
end

print("")
print("=== PROBE 51a COMPLETE ===")
