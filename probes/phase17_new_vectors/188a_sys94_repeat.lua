-- CRASH_CLASS: MODERATE
-- PROBE 188a: is syscall 94 harmless on the first call and fatal on a repeat?
--
-- 187a called 94 once with six zeros in a loader that had just answered a PING
-- and got ret=-1, but the probe died at its next section (93 select kills) so
-- the call was never repeated. The 10-537 sweep, which had just lost the
-- process to 93, got no output from 94 at all. This probe separates the two
-- readings: interleave 94 with a syscall that is known to answer (20 getpid),
-- so a death between two markers names the call that caused it.
--
-- Every comparison uses the printed hex, not a Lua number: 0xFFFFFFFFFFFFFFFF
-- is a float in Lua 5.1 and never equals the loader's own -1 rendering.

print("=== PROBE 188a: SYSCALL 94 REPEATED ===")
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
local function describe(label, ok, v)
    print(string.format("%s ok=%s ret=%s", label, tostring(ok), tostring(v)))
end

local sc_alive = make_syscall(20)
local sc_94 = make_syscall(94)

local function alive(tag)
    local ok, ret = pcall(function() return sc_alive() end)
    describe("[alive " .. tag .. "]", ok, ret)
    return ok
end

alive("start")

for round = 1, 3 do
    print("")
    print("[A] round " .. round .. ": 94 with six zeros")
    local ok, ret = pcall(function()
        return sc_94(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    describe("[A] 94 zeros", ok, ret)
    alive("after-zero-" .. round)
end

print("")
print("[B] 94 with a single fd argument")
for _, fd in ipairs({1, 2, 0, 3}) do
    local ok, ret = pcall(function() return sc_94(uint64(fd)) end)
    describe("[B] 94 fd=" .. fd, ok, ret)
    alive("after-fd-" .. fd)
end

print("")
print("[C] 94 with 0x1000 in every slot")
local ok, ret = pcall(function()
    return sc_94(uint64(0x1000), uint64(0x1000), uint64(0x1000),
                 uint64(0x1000), uint64(0x1000), uint64(0x1000))
end)
describe("[C] 94 0x1000", ok, ret)
alive("after-1000")

print("")
print("[D] done, the thread survived every call above")
