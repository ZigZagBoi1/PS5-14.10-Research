-- CRASH_CLASS: MODERATE
-- PROBE 530r: Submit with explicit pipe ID + doorbell hunt
--
-- 530q found:
-- - 2 GPU pipes: pipe 0 (active, state=1), pipe 1 (inactive, state=0)
-- - Doorbell offset candidate: 0x5C (92)
-- - 12 queues total (nr=27 returns 0xC)
--
-- The submit struct (16 bytes) may need a pipe ID somewhere.
-- ps5-hen uses: {pipe=0, count=N, descriptors_ptr}
-- Our previous submits had pipe=0, count=1, desc_ptr — maybe the format is different.
--
-- Also: try to find the doorbell BAR in dmem0 or via mmap of /dev/gc.
-- On AMD, the doorbell is accessed via mmap of the GPU device.

print("=== PROBE 530r: SUBMIT PIPE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Open /dev/gc and /dev/dmem0
local function open_dev(devname)
    local dp = memory.alloc(0x30)
    for i = 1, #devname do wd(N(dp) + i - 1, string.byte(devname, i)) end
    wd(N(dp) + #devname, 0)
    return N(native.fcall_with_rax(stub, 5, uint64(N(dp)), uint64(2), uint64(0)))
end

local gc_fd = open_dev("/dev/gc")
local dm_fd = open_dev("/dev/dmem0")
print(string.format("gc=%d dm=%d", gc_fd, dm_fd))

local sc_ioctl = mk(54)
local sc_477 = mk(477)
local PAGE = 0x4000

-- Get libkernel for AllocateDirectMemory
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

-- Allocate physical memory for fence
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(lk_base + uint64(0x17EF0), 0,
        uint64(0), uint64("0x150000000"), uint64(PAGE),
        uint64(PAGE), uint64(0), uint64(N(phys_out)))
end)
local fence_phys = rq(N(phys_out))
local fph, fpl = get_hi_lo(fence_phys)
if fph < 0 then fph = fph + 0x100000000 end
if fpl < 0 then fpl = fpl + 0x100000000 end

-- Map the fence page
local ok_m, rv_m = pcall(function()
    return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(1),
                   uint64(dm_fd), uint64(string.format("0x%X%08X", fph, fpl)))
end)
local fence_va = 0
if ok_m and rv_m then
    local rh = get_hi_lo(rv_m)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh ~= 0xFFFFFFFF then fence_va = N(rv_m) end
end
wq(fence_va, uint64(0))
print(string.format("fence_phys=0x%X%08X fence_va=0x%X", fph, fpl, fence_va))

-- Build a simple EVENT_WRITE_EOP command buffer
local cmd = memory.alloc(0x100)
wd(N(cmd) + 0x00, 0xC0044700)  -- EVENT_WRITE_EOP
wd(N(cmd) + 0x04, 0x00000504)  -- event 4, index 5
wd(N(cmd) + 0x08, fpl)
wd(N(cmd) + 0x0C, fph + 0x01000000)  -- data_sel=1
wd(N(cmd) + 0x10, 0xDEAD0001)

-- Build INDIRECT_BUF descriptor
local desc = memory.alloc(0x10)
local cmd_n = N(cmd)
wd(N(desc) + 0, 0xC0023F00)  -- INDIRECT_BUF
wd(N(desc) + 4, cmd_n % 0x100000000)
wd(N(desc) + 8, math.floor(cmd_n / 0x100000000))
wd(N(desc) + 12, 5)  -- 5 dwords

-- ============================================================
-- [A] Try submit with different struct layouts
-- ============================================================
print("")
print("[A] Submit struct variations")

local desc_n = N(desc)
local desc_lo2 = desc_n % 0x100000000
local desc_hi2 = math.floor(desc_n / 0x100000000)

-- Layout 1: {pipe(4), count(4), desc_ptr(8)} — what we've been using
local function try_submit(label, d0, d1, d2, d3)
    wq(fence_va, uint64(0))  -- reset fence
    wd(N(cmd) + 0x10, 0xDEAD0001)  -- unique marker
    local sub = memory.alloc(0x10)
    wd(N(sub), d0)
    wd(N(sub) + 4, d1)
    wd(N(sub) + 8, d2)
    wd(N(sub) + 12, d3)
    local ok_s, rv_s = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
    end)
    local ret = rv_s and N(rv_s) or -999
    -- Wait
    local dummy = 0
    for i = 1, 500000 do dummy = dummy + 1 end
    local fval = rd(fence_va) or 0
    if fval < 0 then fval = fval + 0x100000000 end
    print(string.format("  %s: rv=%d fence=0x%X%s", label,
        ret, fval, fval == 0xDEAD0001 and " MATCH!" or ""))
    return ret, fval
end

-- {0, 1, desc_lo, desc_hi} — pipe 0, count 1
try_submit("pipe0_cnt1", 0, 1, desc_lo2, desc_hi2)

-- {1, 1, desc_lo, desc_hi} — pipe 1, count 1
try_submit("pipe1_cnt1", 1, 1, desc_lo2, desc_hi2)

-- {count, desc_lo, desc_hi, 0} — maybe count is first?
try_submit("cnt_first", 1, desc_lo2, desc_hi2, 0)

-- {desc_lo, desc_hi, count, pipe} — reversed
try_submit("desc_cnt_pipe", desc_lo2, desc_hi2, 1, 0)

-- {desc_lo, desc_hi, 0, 0} — just ptr, implied count
try_submit("just_ptr", desc_lo2, desc_hi2, 0, 0)

-- ============================================================
-- [B] Try mmap on /dev/gc for doorbell access
-- ============================================================
print("")
print("[B] mmap /dev/gc for doorbell")

-- Try mapping offset 0 (ring), 0x10000 (doorbell), 0x5C*PAGE
for _, off_val in ipairs({0, 0x10000, 0x5C * 4, 0x5C * PAGE, 0x1000, 0x100000}) do
    local ok_g, rv_g = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(1),
                       uint64(gc_fd), uint64(off_val))
    end)
    local ret = -1
    if ok_g and rv_g then
        local rh = get_hi_lo(rv_g)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then ret = N(rv_g) end
    end
    local tag = "FAIL"
    if ret > 0 then
        local d = rd(ret) or -1
        if d < 0 then d = d + 0x100000000 end
        tag = string.format("VA=0x%X [0]=0x%X", ret, d)
    end
    print(string.format("  gc mmap off=0x%X: %s", off_val, tag))
end

-- ============================================================
-- [C] Try mmap on /dev/dce for GPU register access
-- ============================================================
print("")
print("[C] mmap /dev/dce")

local dce_fd = open_dev("/dev/dce")
print(string.format("  dce_fd=%d", dce_fd))
if dce_fd >= 0 then
    for _, off_val in ipairs({0, 0x10000, 0x100000, 0x1000000}) do
        local ok_d, rv_d = pcall(function()
            return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(1),
                           uint64(dce_fd), uint64(off_val))
        end)
        local ret = -1
        if ok_d and rv_d then
            local rh = get_hi_lo(rv_d)
            if rh < 0 then rh = rh + 0x100000000 end
            if rh ~= 0xFFFFFFFF then ret = N(rv_d) end
        end
        local tag = "FAIL"
        if ret > 0 then
            local d = rd(ret)
            if d then
                if d < 0 then d = d + 0x100000000 end
                tag = string.format("VA=0x%X [0]=0x%X", ret, d)
            else
                tag = string.format("VA=0x%X [0]=FAULT", ret)
            end
        end
        print(string.format("  dce mmap off=0x%X: %s", off_val, tag))
    end
end

-- Cleanup
pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)
if dce_fd >= 0 then pcall(function() native.fcall_with_rax(stub, 6, uint64(dce_fd)) end) end

print("")
print("=== 530r DONE ===")
