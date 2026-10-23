-- CRASH_CLASS: MODERATE
-- PROBE 399a: sys 636 (set_timezone_info) deep probe
--
-- narg=2, 13.60 name "n_info". Only tested with six zeros (ret=-1).
-- Candidates: (ptr, len), (id, ptr), (cmd, ptr), (flags, value)
-- If it's truly a timezone setter, it might take a struct pointer.
-- Check: which arg patterns return 0? Any that write output?

print("=== PROBE 399a: sys 636 deep ===")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Ignore SIGSYS
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local sc636 = mk(636)
local buf = memory.alloc(0x400)
local buf2 = memory.alloc(0x400)

-- ============================================
-- PART A: Scalar pairs (cmd/id, value)
-- ============================================
print("")
print("-- A: scalar pairs --")

local scalars = {
    {0, 0}, {1, 0}, {0, 1}, {1, 1},
    {2, 0}, {3, 0}, {4, 0}, {5, 0},
    {0, 2}, {0, 0x10}, {0, 0x100},
    {0xFFFFFFFF, 0}, {0, 0xFFFFFFFF},
    {1, 0x100}, {2, 0x100},
}

for _, pair in ipairs(scalars) do
    local ok, rv = pcall(function()
        return sc636(uint64(pair[1]), uint64(pair[2]))
    end)
    local ret = ok and N(rv) or -999
    if ret ~= -1 and ret ~= 4294967295 then
        print(string.format("  (%X, %X) = %d ★", pair[1], pair[2], ret))
    end
end
-- Summary line
local ok0, rv0 = pcall(function() return sc636(uint64(0), uint64(0)) end)
local ok1, rv1 = pcall(function() return sc636(uint64(1), uint64(0)) end)
print(string.format("  (0,0)=%d (1,0)=%d", ok0 and N(rv0) or -999, ok1 and N(rv1) or -999))
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: (ptr, len) — output buffer pattern
-- ============================================
print("")
print("-- B: (ptr, len) output --")

local sizes = {0x10, 0x40, 0x100, 0x200, 0x400}

for _, sz in ipairs(sizes) do
    -- Fill with sentinel
    for i = 0, sz - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end

    local ok_b, rv_b = pcall(function()
        return sc636(uint64(N(buf)), uint64(sz))
    end)
    local ret_b = ok_b and N(rv_b) or -999

    -- Check if sentinel changed
    local changed = 0
    local first_change = -1
    local kptr = 0
    for i = 0, sz - 4, 4 do
        local v = rd(N(buf) + i) or 0xDEADDEAD
        if v ~= 0xDEADDEAD then
            changed = changed + 1
            if first_change < 0 then first_change = i end
            local h = math.floor(v / 0x10000)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr = kptr + 1
            end
        end
    end

    if changed > 0 or ret_b == 0 then
        print(string.format("  sz=%X ret=%d changed=%d first=+%X kptr=%d ★",
            sz, ret_b, changed, first_change, kptr))
        -- Dump first 32 bytes of changes
        if changed > 0 then
            local dump = "  "
            local cnt = 0
            for i = 0, sz - 4, 4 do
                local v = rd(N(buf) + i) or 0xDEADDEAD
                if v ~= 0xDEADDEAD then
                    dump = dump .. string.format("+%X=%08X ", i, v)
                    cnt = cnt + 1
                    if cnt >= 8 then break end
                end
            end
            print(dump)
        end
    end
end
if not alive() then print("CANARY FAIL B"); return end

-- ============================================
-- PART C: (len, ptr) — reversed args
-- ============================================
print("")
print("-- C: (len, ptr) reversed --")

for _, sz in ipairs(sizes) do
    for i = 0, sz - 4, 4 do wd(N(buf) + i, 0xCCCCCCCC) end

    local ok_c, rv_c = pcall(function()
        return sc636(uint64(sz), uint64(N(buf)))
    end)
    local ret_c = ok_c and N(rv_c) or -999

    local changed = 0
    for i = 0, sz - 4, 4 do
        local v = rd(N(buf) + i) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then changed = changed + 1 end
    end

    if changed > 0 or ret_c == 0 then
        print(string.format("  sz=%X ret=%d changed=%d ★", sz, ret_c, changed))
    end
end
if not alive() then print("CANARY FAIL C"); return end

-- ============================================
-- PART D: (ptr_to_struct, 0) — timezone struct shapes
-- FreeBSD tz struct: { int tz_minuteswest; int tz_dsttime; }
-- Also try: larger structs with name pointer, offset, etc.
-- ============================================
print("")
print("-- D: timezone struct --")

-- Classic FreeBSD timezone struct (8 bytes)
for i = 0, 0xFC, 4 do wd(N(buf) + i, 0) end
wd(N(buf), 300)      -- tz_minuteswest = 300 (UTC-5)
wd(N(buf) + 4, 1)    -- tz_dsttime = 1 (DST)

local shapes = {
    {N(buf), 0, "ptr,0"},
    {N(buf), 8, "ptr,8"},
    {N(buf), 0x10, "ptr,16"},
    {N(buf), 0x40, "ptr,64"},
    {0, N(buf), "0,ptr"},
    {8, N(buf), "8,ptr"},
    {1, N(buf), "1,ptr"},
}

for _, s in ipairs(shapes) do
    local ok_d, rv_d = pcall(function()
        return sc636(uint64(s[1]), uint64(s[2]))
    end)
    local ret_d = ok_d and N(rv_d) or -999
    if ret_d ~= -1 and ret_d ~= 4294967295 then
        print(string.format("  (%s) ret=%d ★", s[3], ret_d))
    end
end

-- Try settimeofday-like: (tv, tz) where tv is timeval struct
local tv = memory.alloc(16)
wq(tv, uint64(0))    -- tv_sec = 0
wq(tv + 8, uint64(0)) -- tv_usec = 0
local tz = memory.alloc(8)
wd(N(tz), 300); wd(N(tz) + 4, 1)

local ok_stod, rv_stod = pcall(function()
    return sc636(uint64(N(tv)), uint64(N(tz)))
end)
print(string.format("  (tv,tz)=%d", ok_stod and N(rv_stod) or -999))

if not alive() then print("CANARY FAIL D"); return end

-- ============================================
-- PART E: Read-back — does 636 have a getter mode?
-- If arg1 is a command (0=get, 1=set), try reading
-- ============================================
print("")
print("-- E: getter mode --")

-- Prepare clean output buffer
for i = 0, 0xFF, 4 do wd(N(buf2) + i, 0xEEEEEEEE) end

local getter_shapes = {
    {0, N(buf2), "0,ptr"},
    {1, N(buf2), "1,ptr"},
    {N(buf2), 0, "ptr,0"},
    {N(buf2), 0x100, "ptr,256"},
    {N(buf2), 8, "ptr,8"},
    {N(buf2), 0x40, "ptr,64"},
}

for _, s in ipairs(getter_shapes) do
    -- Reset
    for i = 0, 0xFF, 4 do wd(N(buf2) + i, 0xEEEEEEEE) end

    local ok_e, rv_e = pcall(function()
        return sc636(uint64(s[1]), uint64(s[2]))
    end)
    local ret_e = ok_e and N(rv_e) or -999

    local changed = 0
    local kptr = 0
    for i = 0, 0xFC, 4 do
        local v = rd(N(buf2) + i) or 0xEEEEEEEE
        if v ~= 0xEEEEEEEE then
            changed = changed + 1
            local h = math.floor(v / 0x10000)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then kptr = kptr + 1 end
        end
    end

    if changed > 0 or (ret_e ~= -1 and ret_e ~= 4294967295) then
        print(string.format("  (%s) ret=%d chg=%d kptr=%d ★", s[3], ret_e, changed, kptr))
        if changed > 0 then
            local dump = "  "
            local cnt = 0
            for i = 0, 0xFC, 4 do
                local v = rd(N(buf2) + i) or 0xEEEEEEEE
                if v ~= 0xEEEEEEEE then
                    dump = dump .. string.format("+%X=%08X ", i, v)
                    cnt = cnt + 1
                    if cnt >= 8 then break end
                end
            end
            print(dump)
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 399a COMPLETE ===")
