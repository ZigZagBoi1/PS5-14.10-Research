-- CRASH_CLASS: LOW
-- PROBE 54j: Sys 624 counter/oracle investigation
--
-- Context: sys 624 returned 0xD31 in 51a and 0xD30 in 51b — delta of 1
-- across two separate processes. If this is a live counter, it might be
-- useful as a KASLR side channel or heap state oracle.

print("=== PROBE 54j: SYS 624 COUNTER ORACLE ===")
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
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function hexval(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X_%08X", val.h, val.l)
    end
    return string.format("0x%X", to_num(val))
end

local sc624 = make_syscall(624)
local sc477 = make_syscall(477) -- mmap
local sc97  = make_syscall(97)  -- socket
local sc6   = make_syscall(6)   -- close

-- Phase 1: Rapid repeated calls — does the counter change within one process?
print("[*] Phase 1: Rapid repeated calls (20x)")
print("")
local vals = {}
for i = 1, 20 do
    local ok, ret = pcall(function()
        return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        vals[i] = rv
        print(string.format("  call %2d: ret=%d (0x%X)", i, rv, rv >= 0 and rv or rv + 0x100000000))
    else
        print(string.format("  call %2d: CRASHED: %s", i, tostring(ret)))
        vals[i] = nil
    end
end
print("")

-- Check if monotonic
local increasing = true
local decreasing = true
local constant = true
for i = 2, #vals do
    if vals[i] and vals[i-1] then
        if vals[i] ~= vals[i-1] then constant = false end
        if vals[i] <= vals[i-1] then increasing = false end
        if vals[i] >= vals[i-1] then decreasing = false end
    end
end
print(string.format("  Pattern: constant=%s increasing=%s decreasing=%s",
    tostring(constant), tostring(increasing), tostring(decreasing)))
print("")

-- Phase 2: Call 624 before/after operations to see what changes it
print("[*] Phase 2: Call before/after mmap allocations")
print("")
local before = nil
do
    local ok, ret = pcall(function()
        return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then before = signed32(ret) end
end

-- Do 10 mmap allocations
for i = 1, 10 do
    pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
end

local after = nil
do
    local ok, ret = pcall(function()
        return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then after = signed32(ret) end
end
print(string.format("  Before 10 mmaps: %s", before and tostring(before) or "failed"))
print(string.format("  After 10 mmaps:  %s", after and tostring(after) or "failed"))
if before and after then
    print(string.format("  Delta: %d", after - before))
end
print("")

-- Phase 3: Before/after socket creation
print("[*] Phase 3: Call before/after socket creation")
print("")
before = nil
do
    local ok, ret = pcall(function()
        return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then before = signed32(ret) end
end

local fds = {}
for i = 1, 5 do
    local ok, ret = pcall(function()
        return sc97(uint64(2), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local fd = signed32(ret)
        if fd >= 0 then fds[#fds+1] = fd end
    end
end

after = nil
do
    local ok, ret = pcall(function()
        return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then after = signed32(ret) end
end
print(string.format("  Before 5 sockets: %s", before and tostring(before) or "failed"))
print(string.format("  After 5 sockets:  %s", after and tostring(after) or "failed"))
if before and after then
    print(string.format("  Delta: %d", after - before))
end
-- Clean up
for _, fd in ipairs(fds) do
    pcall(function() sc6(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("")

-- Phase 4: Try different arg patterns
print("[*] Phase 4: Different arg0 values")
print("")
for _, arg0 in ipairs({0, 1, 2, 3, 4, 0xFF, 0x100, 0xFFFF}) do
    local ok, ret = pcall(function()
        return sc624(uint64(arg0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print(string.format("  624(0x%X) = %d", arg0, signed32(ret)))
    else
        print(string.format("  624(0x%X) CRASHED: %s", arg0, tostring(ret)))
    end
end
print("")

-- Phase 5: Try with output buffer
print("[*] Phase 5: With output buffer as arg2")
print("")
local outbuf = memory.alloc(256)
for _, arg0 in ipairs({0, 1}) do
    for i = 0, 63, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return sc624(uint64(arg0), uint64(outbuf), uint64(64), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  624(%d, outbuf, 64) = %d", arg0, rv))
    else
        print(string.format("  624(%d, outbuf, 64) CRASHED: %s", arg0, tostring(ret)))
    end
end

print("")
print("=== PROBE 54j COMPLETE ===")
