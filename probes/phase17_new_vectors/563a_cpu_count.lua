-- CRASH_CLASS: LOW
-- PROBE 563a: how many CPUs can this process actually run on?
--
-- 562a woke three children in one _umtx_op wake and still got exactly one
-- successful delete per round: the winner finished the whole call before a
-- loser reached its first lookup. That is what a single runnable CPU looks
-- like. sysctl(CTL_HW, HW_NCPU) answers it directly.

print("=== PROBE 563a: CPU COUNT ===")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc_sysctl = mk(202)
local function get(mib_a, mib_b)
    local mib = memory.alloc(16)
    local out = memory.alloc(0x80)
    local len = memory.alloc(8)
    for i = 0, 0x7C, 4 do wd(N(out) + i, 0) end
    wd(N(mib), mib_a); wd(N(mib) + 4, mib_b)
    wd(N(len), 4)
    local ok, rv = pcall(function()
        return sc_sysctl(uint64(N(mib)), uint64(2), uint64(N(out)), uint64(N(len)), uint64(0), uint64(0))
    end)
    return N(rv), rd(N(out)), rd(N(len))
end

local names = {
    {"hw.ncpu", 6, 3},
    {"hw.ncpuonline", 6, 0x3c},
    {"kern.smp.cpus", 1, 0x3f},
    {"kern.smp.maxcpus", 1, 0x40},
}
for _, t in ipairs(names) do
    local rv, val, len = get(t[2], t[3])
    print(string.format("  %-16s ret=%d value=%s len=%s", t[1], rv,
        val and string.format("%d (0x%X)", val, val) or "nil", tostring(len)))
end
print("=== DONE ===")
