-- CRASH_CLASS: LOW
-- PROBE 69n: 663 wait mode parameter sweep
--
-- Context: syscall 663 (aio_multi_wait) takes 6 args. The 5th parameter
-- (param_5 in the 13.60 decompile) controls the wait mode. ALL existing
-- probes pass the default (0 or omitted). Non-default modes might unlock
-- wider readback or return raw object data instead of lookup-table status
-- dwords. This probe sweeps modes 0-7 and flag values 0x10-0x100, then
-- tests oversized output buffers for overcopy past the per-ID status dword.
--
-- 663 ABI (from 13.60 decompile): 663(ids, count, states, arg4, mode, arg6)

print("=== PROBE 69n: 663 MODE PARAMETER SWEEP ===")
print("")

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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Open /dev/zero for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("FAIL: no /dev/zero"); return end

-- ============================================================
-- AIO helpers
-- ============================================================
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))          -- offset
    wq(N(reqs) + 8, uint64(16))    -- nbytes
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- ============================================================
-- [A] Submit and poll AIO requests for use in sweep
-- ============================================================
print("")
print("[A] Submitting 16 AIO requests")
local ids = {}
for i = 1, 16 do
    local id = submit_one()
    if id ~= 0 then
        poll_one(id)
        table.insert(ids, id)
    end
end
print("  submitted+polled: " .. #ids)
if #ids < 8 then print("FAIL: too few IDs"); return end
for i = 1, math.min(4, #ids) do
    print(string.format("  id[%d] = 0x%X", i, ids[i]))
end

if not alive() then print("DEAD after submit"); return end

-- ============================================================
-- [B] Baseline: 663 with default args (mode=0, arg4=0, arg6=0)
-- ============================================================
print("")
print("[B] Baseline: 663 default call")
do
    local out = memory.alloc(0x40)
    for j = 0, 0x3C, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    wd(N(one_id), ids[1])

    local ret = nil
    pcall(function()
        ret = mk(663)(uint64(N(one_id)), uint64(1), uint64(N(out)),
            uint64(0), uint64(0), uint64(0))
    end)
    local r = ret and sgn(ret) or -999
    print(string.format("  663(id=0x%X, count=1, mode=0): ret=%d", ids[1], r))

    -- Dump first 16 dwords of output
    local modified = 0
    for j = 0, 0x3C, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then modified = modified + 1 end
        if j < 0x20 then
            print(string.format("    +0x%02X: 0x%08X%s", j, v,
                v ~= 0xCCCCCCCC and " *" or ""))
        end
    end
    print(string.format("  modified dwords: %d/16", modified))
end

if not alive() then print("DEAD after baseline"); return end

-- ============================================================
-- [C] Mode sweep: arg5 = 0..7, then flag values
-- ============================================================
print("")
print("[C] Mode sweep: arg5 (param_5) values")

local modes = {0, 1, 2, 3, 4, 5, 6, 7,
    0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800,
    0x1000, 0x10000, 0xFFFFFFFF}

for mi, mode in ipairs(modes) do
    if not alive() then print("  DEAD at mode " .. mode); break end

    -- Use a different ID for each mode to avoid state contamination
    local test_id = ids[((mi - 1) % #ids) + 1]

    local out = memory.alloc(0x40)
    for j = 0, 0x3C, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    wd(N(one_id), test_id)

    local ret = nil
    pcall(function()
        ret = mk(663)(uint64(N(one_id)), uint64(1), uint64(N(out)),
            uint64(0), uint64(mode), uint64(0))
    end)
    local r = ret and sgn(ret) or -999

    -- Count modified bytes and collect them
    local modified = 0
    local first_mod = -1
    local last_mod = -1
    local vals = {}
    for j = 0, 0x3C, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        vals[j] = v
        if v ~= 0xCCCCCCCC then
            modified = modified + 1
            if first_mod < 0 then first_mod = j end
            last_mod = j
        end
    end

    local tag = ""
    if modified > 1 then tag = " *** EXTRA DATA ***" end
    if r ~= 0 and r ~= -1 and r ~= -999 then tag = tag .. " *** UNUSUAL RET ***" end

    print(string.format("  mode=0x%04X: ret=%d modified=%d/16 range=[+0x%02X..+0x%02X]%s",
        mode, r, modified,
        first_mod >= 0 and first_mod or 0,
        last_mod >= 0 and last_mod or 0,
        tag))

    -- If more than 1 dword modified or unusual values, dump everything
    if modified > 1 or (modified == 1 and vals[0] ~= 0 and vals[0] ~= 3 and vals[0] ~= 4) then
        for j = 0, 0x3C, 4 do
            local v = vals[j]
            if v ~= 0xCCCCCCCC then
                local vh = rd(N(out) + j + 4) or 0xCCCCCCCC
                print(string.format("    +0x%02X: 0x%08X (hi: 0x%08X)%s", j, v, vh,
                    (v >= 0xFFFF8000 and v ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
            end
        end
    end
end

if not alive() then print("DEAD after mode sweep"); return end

-- ============================================================
-- [D] arg4 sweep: try non-zero arg4 values with mode=0
-- ============================================================
print("")
print("[D] arg4 sweep (param_4) with mode=0")

local arg4_vals = {0, 1, 2, 3, 4, 5, 6, 7, 8,
    0x10, 0x100, 0x1000, 0xFFFFFFFF}

for _, a4 in ipairs(arg4_vals) do
    if not alive() then break end

    local test_id = ids[1]
    local out = memory.alloc(0x40)
    for j = 0, 0x3C, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    wd(N(one_id), test_id)

    local ret = nil
    pcall(function()
        ret = mk(663)(uint64(N(one_id)), uint64(1), uint64(N(out)),
            uint64(a4), uint64(0), uint64(0))
    end)
    local r = ret and sgn(ret) or -999

    local v0 = rd(N(out)) or 0xCCCCCCCC
    local v4 = rd(N(out) + 4) or 0xCCCCCCCC
    local modified = 0
    for j = 0, 0x3C, 4 do
        if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
    end

    print(string.format("  arg4=0x%X: ret=%d d0=0x%08X d4=0x%08X mod=%d",
        a4, r, v0, v4, modified))
end

if not alive() then print("DEAD after arg4 sweep"); return end

-- ============================================================
-- [E] arg6 sweep: try non-zero arg6 values with mode=0
-- ============================================================
print("")
print("[E] arg6 sweep (param_6) with mode=0")

local arg6_vals = {0, 1, 2, 4, 8, 0x10, 0x100, 0x1000, 0xFFFFFFFF}

for _, a6 in ipairs(arg6_vals) do
    if not alive() then break end

    local test_id = ids[2]
    local out = memory.alloc(0x40)
    for j = 0, 0x3C, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    wd(N(one_id), test_id)

    local ret = nil
    pcall(function()
        ret = mk(663)(uint64(N(one_id)), uint64(1), uint64(N(out)),
            uint64(0), uint64(0), uint64(a6))
    end)
    local r = ret and sgn(ret) or -999

    local v0 = rd(N(out)) or 0xCCCCCCCC
    local v4 = rd(N(out) + 4) or 0xCCCCCCCC
    local modified = 0
    for j = 0, 0x3C, 4 do
        if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
    end

    print(string.format("  arg6=0x%X: ret=%d d0=0x%08X d4=0x%08X mod=%d",
        a6, r, v0, v4, modified))
end

if not alive() then print("DEAD after arg6 sweep"); return end

-- ============================================================
-- [F] Overcopy test: oversized output buffers
-- ============================================================
print("")
print("[F] Overcopy test: oversized output buffers")

local sizes = {4, 8, 16, 32, 64, 128, 256, 512, 1024}
for _, sz in ipairs(sizes) do
    if not alive() then break end

    local test_id = ids[3]
    local out = memory.alloc(sz + 64)
    -- Fill entire buffer with 0xCC sentinel
    for j = 0, sz + 60, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    wd(N(one_id), test_id)

    -- Call 663 with states_ptr pointing to the large buffer
    local ret = nil
    pcall(function()
        ret = mk(663)(uint64(N(one_id)), uint64(1), uint64(N(out)),
            uint64(0), uint64(0), uint64(0))
    end)
    local r = ret and sgn(ret) or -999

    -- Count how many dwords were modified
    local modified = 0
    local last_mod = -1
    for j = 0, sz - 4, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            modified = modified + 1
            last_mod = j
        end
    end

    -- Check past the expected single-ID status dword (first 4 bytes)
    local overcopy = 0
    for j = 4, sz - 4, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then overcopy = overcopy + 1 end
    end

    local tag = ""
    if overcopy > 0 then tag = " *** OVERCOPY ***" end

    print(string.format("  buf=%dB: ret=%d modified=%d last=+0x%02X overcopy=%d%s",
        sz, r, modified, last_mod >= 0 and last_mod or 0, overcopy, tag))

    -- If overcopy detected, dump the extra data
    if overcopy > 0 then
        for j = 0, math.min(sz - 4, 64), 4 do
            local v = rd(N(out) + j) or 0xCCCCCCCC
            if v ~= 0xCCCCCCCC then
                print(string.format("    +0x%02X: 0x%08X%s", j, v,
                    (v >= 0xFFFF8000 and v ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
            end
        end
    end
end

if not alive() then print("DEAD after overcopy test"); return end

-- ============================================================
-- [G] Multi-ID mode test: count > 1 with various modes
-- ============================================================
print("")
print("[G] Multi-ID mode test: 663 with count=4")

local multi_ids = memory.alloc(4 * 4)
local multi_out = memory.alloc(0x100)

for i = 0, 3 do
    wd(N(multi_ids) + i * 4, ids[i + 1])
end

local test_modes = {0, 1, 2, 3}
for _, mode in ipairs(test_modes) do
    if not alive() then break end

    for j = 0, 0xFC, 4 do wd(N(multi_out) + j, 0xCCCCCCCC) end

    local ret = nil
    pcall(function()
        ret = mk(663)(uint64(N(multi_ids)), uint64(4), uint64(N(multi_out)),
            uint64(0), uint64(mode), uint64(0))
    end)
    local r = ret and sgn(ret) or -999

    -- Read per-ID output plus extra
    local line = string.format("  mode=%d count=4: ret=%d", mode, r)
    local parts = {}
    for i = 0, 3 do
        local v = rd(N(multi_out) + i * 4) or 0xCCCCCCCC
        table.insert(parts, string.format("0x%08X", v))
    end
    line = line .. " ids=[" .. table.concat(parts, ",") .. "]"

    -- Check if data past 4*4=16 bytes was written
    local extra = 0
    for j = 16, 0x3C, 4 do
        if (rd(N(multi_out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then extra = extra + 1 end
    end
    if extra > 0 then line = line .. " EXTRA=" .. extra end

    print(line)

    -- If extra data, dump it
    if extra > 0 then
        for j = 16, 0x3C, 4 do
            local v = rd(N(multi_out) + j) or 0xCCCCCCCC
            if v ~= 0xCCCCCCCC then
                print(string.format("    +0x%02X: 0x%08X%s", j, v,
                    (v >= 0xFFFF8000 and v ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
            end
        end
    end
end

if not alive() then print("DEAD after multi-ID test"); return end

-- ============================================================
-- [H] Per-ID stride test: does 663 write more than 4 bytes per ID?
-- ============================================================
print("")
print("[H] Per-ID stride test: 663 with count=4, checking stride")

-- With 4 IDs, if stride > 4 bytes, we'll see writes past offset 16
-- Fill 256 bytes with sentinel, submit 4 IDs
local stride_out = memory.alloc(0x100)
for j = 0, 0xFC, 4 do wd(N(stride_out) + j, 0xCCCCCCCC) end

pcall(function()
    mk(663)(uint64(N(multi_ids)), uint64(4), uint64(N(stride_out)),
        uint64(0), uint64(0), uint64(0))
end)

-- Find all modified positions
local mod_positions = {}
for j = 0, 0xFC, 4 do
    local v = rd(N(stride_out) + j) or 0xCCCCCCCC
    if v ~= 0xCCCCCCCC then
        table.insert(mod_positions, {off = j, val = v})
    end
end

print(string.format("  4 IDs, 256B buffer: %d dwords modified", #mod_positions))
for _, mp in ipairs(mod_positions) do
    print(string.format("    +0x%02X: 0x%08X%s", mp.off, mp.val,
        (mp.val >= 0xFFFF8000 and mp.val ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
end

if #mod_positions == 4 then
    local stride = mod_positions[2].off - mod_positions[1].off
    print(string.format("  inferred stride: %d bytes (0x%X)", stride, stride))
    if stride > 4 then
        print("  *** STRIDE > 4 — per-ID record is larger than a dword! ***")
    end
elseif #mod_positions > 4 then
    print("  *** MORE WRITES THAN IDs — extra data present! ***")
end

-- ============================================================
-- [I] Cleanup
-- ============================================================
print("")
print("[I] Cleanup")
local cleaned = 0
for _, id in ipairs(ids) do
    local st = delete_one(id)
    if st == 0 then cleaned = cleaned + 1 end
end
print(string.format("  deleted %d/%d IDs", cleaned, #ids))
print("  alive=" .. (alive() and "YES" or "NO"))

print("")
print("=== PROBE 69n COMPLETE ===")
