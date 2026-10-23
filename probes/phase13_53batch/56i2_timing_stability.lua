-- CRASH_CLASS: LOW
-- PROBE 56i2: Stability check for mprotect timing anomaly
--
-- 56i found 12% spread in mprotect timing across kernel addresses,
-- with peaks around 0xFFFFF800_0C000000 and 0xFFFFF800_30000000.
-- This probe repeats the measurement 5 times to check stability.
-- If the same addresses are consistently slow, it's signal.
-- If the peaks move, it's scheduling noise.

print("=== PROBE 56i2: TIMING STABILITY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc_clock = mk(232)
local ts = memory.alloc(16)

local function get_nsec()
    wq(ts, uint64(0))
    wq(uint64(N(ts) + 8), uint64(0))
    sc_clock(uint64(4), uint64(N(ts)))
    local sec = rd(N(ts))
    local nsec = rd(N(ts) + 8)
    if not sec or not nsec then return 0 end
    return sec * 1000000000 + nsec
end

local sc_mprot = mk(74)
local BATCH = 2000

-- Test the interesting addresses from 56i, plus controls
local addrs = {
    {name = "user_ref",       hi = 0x00000001, lo = 0x00000000},
    {name = "kern_8000",      hi = 0xFFFF8000, lo = 0x00000000},
    {name = "kern_F800",      hi = 0xFFFFF800, lo = 0x00000000},
    {name = "kern_F800_04M",  hi = 0xFFFFF800, lo = 0x00400000},
    {name = "kern_F800_08M",  hi = 0xFFFFF800, lo = 0x00800000},
    {name = "kern_F800_0CM",  hi = 0xFFFFF800, lo = 0x00C00000},
    {name = "kern_F800_10M",  hi = 0xFFFFF800, lo = 0x01000000},
    {name = "kern_F800_14M",  hi = 0xFFFFF800, lo = 0x01400000},
    {name = "kern_F800_18M",  hi = 0xFFFFF800, lo = 0x01800000},
    {name = "kern_F800_20M",  hi = 0xFFFFF800, lo = 0x02000000},
    {name = "kern_F800_30M",  hi = 0xFFFFF800, lo = 0x03000000},
    {name = "kern_F800_40M",  hi = 0xFFFFF800, lo = 0x04000000},
    {name = "kern_F000",      hi = 0xFFFFF000, lo = 0x00000000},
    {name = "kern_A000",      hi = 0xFFFFA000, lo = 0x00000000},
    {name = "kern_FFFF",      hi = 0xFFFFFFFF, lo = 0x00000000},
}

-- 5 rounds
local ROUNDS = 5

-- Header
local hdr = "  %-18s"
for r = 1, ROUNDS do hdr = hdr .. "  R" .. r end
hdr = hdr .. "  avg"
print(string.format(hdr, "address"))

for _, t in ipairs(addrs) do
    local addr = uint64(string.format("0x%08X%08X", t.hi, t.lo))
    local round_times = {}
    local total = 0

    for r = 1, ROUNDS do
        local before = get_nsec()
        for i = 1, BATCH do
            pcall(function() sc_mprot(addr, uint64(0x4000), uint64(1)) end)
        end
        local after = get_nsec()
        local per_call = math.floor((after - before) / BATCH)
        round_times[r] = per_call
        total = total + per_call
    end

    local line = string.format("  %-18s", t.name)
    for r = 1, ROUNDS do
        line = line .. string.format(" %5d", round_times[r])
    end
    line = line .. string.format(" %5d", math.floor(total / ROUNDS))
    print(line)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56i2 COMPLETE ===")
