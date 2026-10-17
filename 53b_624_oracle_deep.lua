-- CRASH_CLASS: LOW
-- PROBE 53b: syscall 624 counter/oracle characterization
--
-- Context: syscall 624 returns a changing scalar across fresh connections.
-- This probe measures repeatability, allocation sensitivity, and timing. It
-- does not pass pointers or write kernel state.

print("=== PROBE 53b: SYSCALL 624 ORACLE DEEP ===")
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
local function safe_call(sc, ...)
    local t0 = os.clock()
    local ok, v = pcall(function() return sc(...) end)
    return ok, to_num(v), os.clock() - t0
end
local function sample(tag, sc)
    local ok, v, dt = safe_call(sc)
    print(string.format("  %-18s ok=%s value=%d (0x%X) cpu_time=%.6f", tag, tostring(ok), v, v, dt))
    return v, dt
end

local sc624 = make_syscall(624)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)
local base = sample("baseline-1", sc624)
local i = 2
while i <= 16 do sample("baseline-" .. tostring(i), sc624); i = i + 1 end

print("--- allocation sensitivity ---")
local maps = {}
local n = 0
while n <= 8 do
    if n > 0 then
        local a = sc_mmap(uint64(0), uint64(n * 0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        maps[#maps + 1] = a
        print("  allocated_pages=" .. tostring(n * 4) .. " addr=" .. tostring(a))
        local z = 0
        while z < n * 0x4000 do
            pcall(function() memory.write_dword(a + z, 0) end)
            z = z + 4
        end
    end
    sample("after_alloc_" .. tostring(n), sc624)
    n = n + 1
end

print("--- allocation release sensitivity ---")
local k = #maps
while k >= 1 do
    pcall(function() sc_munmap(uint64(maps[k]), uint64(k * 0x4000)) end)
    sample("after_free_" .. tostring(k), sc624)
    k = k - 1
end

print("--- short-delay timing baseline ---")
local j = 1
while j <= 8 do
    local ok, v, dt = safe_call(sc624)
    print(string.format("  timed-%d value=%d delta=%.6f", j, v, dt))
    local sc_sleep = make_syscall(240)
    pcall(function() sc_sleep(uint64(0), uint64(1000000)) end)
    j = j + 1
end
print("=== 53b COMPLETE ===")
