-- CRASH_CLASS: LOW
-- PROBE 69l: Measure evf and namedobj kernel object sizes via sys 624
--
-- Sys 624 is a monotonic VM operation counter (+5 per mmap, zero jitter).
-- When enough slab objects are allocated to force a new slab page, 624
-- should increment. By counting objects between page boundaries we get
-- objects_per_page, and with 16KB pages: object_size = 16384 / count.
--
-- Compares measured sizes against AIO sub-object zones:
--   R = 48B -> 64B bucket (zone 0x1ab59e0)
--   I = 88B -> 128B bucket (zone 0x1ab5900)
-- A match means cross-subsystem spray is theoretically possible.

print("=== PROBE 69l: EVF/NAMEDOBJ OBJECT SIZE MEASUREMENT ===")
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

local function read_624()
    local ret = nil
    pcall(function() ret = mk(624)(uint64(0)) end)
    if ret == nil then return nil end
    return N(ret)
end

-- Verify 624 is working
local baseline = read_624()
if baseline == nil then
    print("sys 624 not available")
    print("=== PROBE 69l DONE ===")
    return
end
print("624 baseline: " .. baseline)

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- ============================================================
-- [A] EVF OBJECT SIZE MEASUREMENT
-- ============================================================
print("")
print("[A] EVF object size measurement (up to 2000 objects)")

local evf_handles = {}
local evf_jumps = {}     -- {index, prev_624, new_624, delta}
local prev_624 = read_624()
local MAX_EVF = 2000

for i = 1, MAX_EVF do
    if not alive() then print("DEAD at evf " .. i); break end

    local name = string.format("e%07d", i)
    local np = put_str(name)
    local ret = nil
    pcall(function()
        ret = mk(538)(uint64(N(np)), uint64(0xAA))
    end)

    if ret == nil then
        print("  evf_create returned nil at i=" .. i)
        break
    end

    local h, l = get_hi_lo(ret)
    -- ret=-1 means creation failed
    if l == 0xFFFFFFFF and (h == 0 or h == 0xFFFFFFFF) then
        print("  evf_create returned -1 at i=" .. i .. " (limit reached)")
        break
    end

    table.insert(evf_handles, ret)

    -- Read 624 after each creation
    local cur_624 = read_624()
    if cur_624 and prev_624 then
        local delta = cur_624 - prev_624
        if delta > 0 then
            table.insert(evf_jumps, {
                index = i,
                prev = prev_624,
                cur = cur_624,
                delta = delta
            })
            print(string.format("  624 JUMP at evf #%d: %d -> %d (delta=%d, total_handles=%d)",
                i, prev_624, cur_624, delta, #evf_handles))
        end
    end
    prev_624 = cur_624

    -- Progress every 500
    if i % 500 == 0 then
        print(string.format("  ... evf #%d created, 624=%s, jumps=%d",
            i, tostring(cur_624), #evf_jumps))
    end
end

print(string.format("  total evf created: %d", #evf_handles))
print(string.format("  total 624 jumps: %d", #evf_jumps))

-- Analyze gaps between jumps to estimate objects per page
if #evf_jumps >= 2 then
    print("")
    print("  EVF page boundary analysis:")
    local gaps = {}
    for j = 2, #evf_jumps do
        local gap = evf_jumps[j].index - evf_jumps[j - 1].index
        table.insert(gaps, gap)
        print(string.format("    jump %d->%d: gap=%d objects (624: %d->%d, delta=%d)",
            j - 1, j, gap,
            evf_jumps[j].prev, evf_jumps[j].cur, evf_jumps[j].delta))
    end

    -- Find most common gap (mode)
    local gap_counts = {}
    for _, g in ipairs(gaps) do
        gap_counts[g] = (gap_counts[g] or 0) + 1
    end
    local best_gap, best_count = 0, 0
    for g, c in pairs(gap_counts) do
        if c > best_count then best_gap = g; best_count = c end
    end

    if best_gap > 0 then
        local est_size = math.floor(16384 / best_gap)
        print(string.format("  ESTIMATED evf objects/page: %d (mode, seen %d times)",
            best_gap, best_count))
        print(string.format("  ESTIMATED evf object size: %d bytes (16384 / %d)",
            est_size, best_gap))

        -- Compare with AIO zones
        if est_size >= 33 and est_size <= 64 then
            print("  *** MATCHES R zone (48B -> 64B bucket) — CROSS-SPRAY POSSIBLE ***")
        elseif est_size >= 65 and est_size <= 128 then
            print("  *** MATCHES I/Q zone (88B -> 128B bucket) — CROSS-SPRAY POSSIBLE ***")
        else
            print(string.format("  Does NOT match R (64B) or I (128B) zones"))
        end
    end

    -- Also compute from first jump (includes initial slab warmup)
    if evf_jumps[1].index > 1 then
        local first_gap = evf_jumps[1].index
        local est_first = math.floor(16384 / first_gap)
        print(string.format("  First page filled at object #%d -> ~%dB/object (includes warmup)",
            first_gap, est_first))
    end
elseif #evf_jumps == 1 then
    print("  Only 1 jump detected — need more objects or pages are pre-allocated")
    print(string.format("  First jump at object #%d", evf_jumps[1].index))
elseif #evf_jumps == 0 then
    print("  NO 624 jumps detected in %d evf creations", #evf_handles)
    print("  624 may not track slab page allocations, only VM mapping operations")
end

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] NAMEDOBJ OBJECT SIZE MEASUREMENT
-- ============================================================
print("")
print("[B] NAMEDOBJ object size measurement (up to 2000 objects)")

local nobj_handles = {}
local nobj_jumps = {}
prev_624 = read_624()
local MAX_NOBJ = 2000

for i = 1, MAX_NOBJ do
    if not alive() then print("DEAD at nobj " .. i); break end

    local name = string.format("n%07d", i)
    local np = put_str(name)
    local ret = nil
    pcall(function()
        ret = mk(557)(uint64(N(np)))
    end)

    if ret == nil then
        print("  namedobj_create returned nil at i=" .. i)
        break
    end

    local h, l = get_hi_lo(ret)
    if l == 0xFFFFFFFF and (h == 0 or h == 0xFFFFFFFF) then
        print("  namedobj_create returned -1 at i=" .. i .. " (limit reached)")
        break
    end

    table.insert(nobj_handles, ret)

    local cur_624 = read_624()
    if cur_624 and prev_624 then
        local delta = cur_624 - prev_624
        if delta > 0 then
            table.insert(nobj_jumps, {
                index = i,
                prev = prev_624,
                cur = cur_624,
                delta = delta
            })
            print(string.format("  624 JUMP at nobj #%d: %d -> %d (delta=%d, total_handles=%d)",
                i, prev_624, cur_624, delta, #nobj_handles))
        end
    end
    prev_624 = cur_624

    if i % 500 == 0 then
        print(string.format("  ... nobj #%d created, 624=%s, jumps=%d",
            i, tostring(cur_624), #nobj_jumps))
    end
end

print(string.format("  total nobj created: %d", #nobj_handles))
print(string.format("  total 624 jumps: %d", #nobj_jumps))

if #nobj_jumps >= 2 then
    print("")
    print("  NAMEDOBJ page boundary analysis:")
    local gaps = {}
    for j = 2, #nobj_jumps do
        local gap = nobj_jumps[j].index - nobj_jumps[j - 1].index
        table.insert(gaps, gap)
        print(string.format("    jump %d->%d: gap=%d objects (624: %d->%d, delta=%d)",
            j - 1, j, gap,
            nobj_jumps[j].prev, nobj_jumps[j].cur, nobj_jumps[j].delta))
    end

    local gap_counts = {}
    for _, g in ipairs(gaps) do
        gap_counts[g] = (gap_counts[g] or 0) + 1
    end
    local best_gap, best_count = 0, 0
    for g, c in pairs(gap_counts) do
        if c > best_count then best_gap = g; best_count = c end
    end

    if best_gap > 0 then
        local est_size = math.floor(16384 / best_gap)
        print(string.format("  ESTIMATED nobj objects/page: %d (mode, seen %d times)",
            best_gap, best_count))
        print(string.format("  ESTIMATED nobj object size: %d bytes (16384 / %d)",
            est_size, best_gap))

        if est_size >= 33 and est_size <= 64 then
            print("  *** MATCHES R zone (48B -> 64B bucket) — CROSS-SPRAY POSSIBLE ***")
        elseif est_size >= 65 and est_size <= 128 then
            print("  *** MATCHES I/Q zone (88B -> 128B bucket) — CROSS-SPRAY POSSIBLE ***")
        else
            print(string.format("  Does NOT match R (64B) or I (128B) zones"))
        end
    end

    if nobj_jumps[1].index > 1 then
        local first_gap = nobj_jumps[1].index
        local est_first = math.floor(16384 / first_gap)
        print(string.format("  First page filled at object #%d -> ~%dB/object (includes warmup)",
            first_gap, est_first))
    end
elseif #nobj_jumps == 1 then
    print("  Only 1 jump detected")
    print(string.format("  First jump at object #%d", nobj_jumps[1].index))
elseif #nobj_jumps == 0 then
    print("  NO 624 jumps detected in %d nobj creations", #nobj_handles)
    print("  624 may not track slab page allocations")
end

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] AIO OBJECT SIZE MEASUREMENT (for comparison)
-- ============================================================
print("")
print("[C] AIO object size measurement (up to 500 submits)")

local fd_zero = -1
pcall(function()
    fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
end)
if fd_zero < 0 then
    print("  /dev/zero open failed, skipping AIO section")
else
    print("  /dev/zero fd=" .. fd_zero)

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

    local aio_ids = {}
    local aio_jumps = {}
    prev_624 = read_624()
    local MAX_AIO = 500

    for i = 1, MAX_AIO do
        if not alive() then print("DEAD at aio " .. i); break end

        local id = submit_one()
        if id == 0 then
            print("  aio submit failed at i=" .. i)
            break
        end
        table.insert(aio_ids, id)

        local cur_624 = read_624()
        if cur_624 and prev_624 then
            local delta = cur_624 - prev_624
            if delta > 0 then
                table.insert(aio_jumps, {
                    index = i,
                    prev = prev_624,
                    cur = cur_624,
                    delta = delta
                })
                print(string.format("  624 JUMP at aio #%d: %d -> %d (delta=%d)",
                    i, prev_624, cur_624, delta))
            end
        end
        prev_624 = cur_624

        if i % 100 == 0 then
            print(string.format("  ... aio #%d submitted, 624=%s, jumps=%d",
                i, tostring(cur_624), #aio_jumps))
        end
    end

    print(string.format("  total aio submitted: %d", #aio_ids))
    print(string.format("  total 624 jumps: %d", #aio_jumps))

    if #aio_jumps >= 2 then
        print("")
        print("  AIO page boundary analysis:")
        local gaps = {}
        for j = 2, #aio_jumps do
            local gap = aio_jumps[j].index - aio_jumps[j - 1].index
            table.insert(gaps, gap)
            print(string.format("    jump %d->%d: gap=%d objects",
                j - 1, j, gap))
        end
        local gap_counts = {}
        for _, g in ipairs(gaps) do
            gap_counts[g] = (gap_counts[g] or 0) + 1
        end
        local best_gap, best_count = 0, 0
        for g, c in pairs(gap_counts) do
            if c > best_count then best_gap = g; best_count = c end
        end
        if best_gap > 0 then
            local est_size = math.floor(16384 / best_gap)
            print(string.format("  ESTIMATED aio objects/page: %d -> ~%dB/object",
                best_gap, est_size))
        end
    elseif #aio_jumps == 0 then
        print("  NO 624 jumps — confirms 624 does NOT track slab allocations")
    end

    -- Clean up AIO: poll then delete all
    for _, id in ipairs(aio_ids) do
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function()
            mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
    end
    for _, id in ipairs(aio_ids) do
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
    end
end

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] CLEANUP
-- ============================================================
print("")
print("[D] Cleanup")

local evf_del = 0
for _, h in ipairs(evf_handles) do
    pcall(function() mk(539)(h) end)
    evf_del = evf_del + 1
end
print(string.format("  evf deleted: %d", evf_del))

local nobj_del = 0
for _, h in ipairs(nobj_handles) do
    pcall(function() mk(558)(h) end)
    nobj_del = nobj_del + 1
end
print(string.format("  nobj deleted: %d", nobj_del))

-- ============================================================
-- [E] SUMMARY
-- ============================================================
print("")
print("[E] SUMMARY")
print(string.format("  evf: %d created, %d 624-jumps", #evf_handles, #evf_jumps))
print(string.format("  nobj: %d created, %d 624-jumps", #nobj_handles, #nobj_jumps))

if #evf_jumps == 0 and #nobj_jumps == 0 then
    print("")
    print("  CONCLUSION: 624 does NOT track slab page allocations.")
    print("  Object sizes cannot be measured via this counter.")
    print("  Need alternative: allocate N objects, measure total memory")
    print("  via kinfo_proc or similar, divide by N.")
end

print("")
print("=== PROBE 69l COMPLETE ===")
