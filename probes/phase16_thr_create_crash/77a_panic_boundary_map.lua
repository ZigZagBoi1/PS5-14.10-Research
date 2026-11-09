-- CRASH_CLASS: RISKY
-- PROBE 77a: Map the kernel panic boundary across RIP values
--
-- Context: probes 58e/76c/76d/76e all triggered reproducible PS5 console
-- shutdowns after thr_create(430) succeeded. The panic occurred with RIP=0,
-- RIP=longjmp, and RIP=Thrd_exit. This probe tests ONE RIP value per run
-- (since the PS5 crashes after each thr_create) to map which fault types
-- trigger the kernel panic.
--
-- Strategy: each section creates a thread with a different RIP, prints markers,
-- and checks if the main thread survives. But since every prior thr_create
-- crashed the PS5, we test ONLY ONE per connection. The section to run is
-- selected by a variable at the top.
--
-- IMPORTANT: Change TEST_SECTION before each run to test the next RIP class.
-- The PS5 will crash after each run. Reboot, relaunch the loader, then send
-- again with the next section number.
--
-- Sections:
--   1 = RIP=0 (null, baseline — already confirmed panic)
--   2 = RIP=1 (misaligned, unmapped low address)
--   3 = RIP=0xDEAD (unmapped, non-null, non-zero)
--   4 = RIP=eboot .text (valid RX code — does a WORKING thread also panic?)
--   5 = RIP=GPU mmap region (RW, not executable — NX fault)
--   6 = RIP=0xFFFF800000000000 (kernel VA — what does the kernel do?)
--   7 = NO thr_create at all (control — does the setup alone crash?)

local TEST_SECTION = 1

print("=== PROBE 77a: PANIC BOUNDARY MAP ===")
print("TEST_SECTION=" .. TEST_SECTION)
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end
local function wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end
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

local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- Get eboot base for section 4 (valid RX code)
local eboot_base = nil
repeat
    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    local sc_info = make_syscall(593)
    local iok = pcall(function() sc_info(uint64(0), info) end)
    if iok then
        local lo = rd(info + 0x108)
        local hi = rd(info + 0x10C)
        if lo and hi then
            eboot_base = uint64(string.format("0x%X%08X", hi, lo))
            print("[0] eboot_base=" .. q(eboot_base))
        end
    end
until true

-- GPU mmap for section 5 (RW non-exec region)
local gpu_region = nil
repeat
    local sc_mmap = make_syscall(477)
    local mok, maddr = pcall(function()
        return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if mok and maddr then
        gpu_region = maddr
        print("[0] gpu_region=" .. q(gpu_region))
    end
until true

-- Allocate shared resources
local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local stack = memory.alloc(0x4000)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(stack, 0x4000)

-- Context validation gates (required for kernel to accept the context)
wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)

-- Common register setup: valid stack, zeroed flags
wq(ctx + 0xE0, stack + 0x3FF0)  -- RSP
wq(ctx + 0x100, 0)               -- RFLAGS

-- RDI/RSI default to 0 (will be overridden per section if needed)
wq(ctx + 0x48, 0)  -- RDI
wq(ctx + 0x50, 0)  -- RSI

print("[0] ctx=" .. tostring(ctx) .. " stack_top=" .. q(stack + 0x3FF0))
print("")

-- === SECTION 7: CONTROL — no thr_create at all ===
if TEST_SECTION == 7 then
    print("[7] CONTROL: no thr_create call")
    print("[7] sleeping 2 seconds to see if setup alone crashes...")
    local ts = memory.alloc(16)
    wq(ts, 2)
    wq(ts + 8, 0)
    local sok, srv = pcall(function() return sc_nanosleep(uint64(ts), uint64(0)) end)
    print("[7] sleep_ok=" .. tostring(sok) .. " rv=" .. tostring(srv))
    local c_ok, c_pid = canary()
    print("[7] post_canary ok=" .. tostring(c_ok) .. " pid=" .. tostring(c_pid))
    print("=== SECTION 7 COMPLETE (no crash expected) ===")
    print("=== PROBE 77a COMPLETE ===")
    return
end

-- Determine RIP for this section
local test_rip = nil
local rip_label = ""

if TEST_SECTION == 1 then
    test_rip = uint64(0)
    rip_label = "NULL (0x0)"
elseif TEST_SECTION == 2 then
    test_rip = uint64(1)
    rip_label = "MISALIGNED (0x1)"
elseif TEST_SECTION == 3 then
    test_rip = uint64(0xDEAD)
    rip_label = "UNMAPPED (0xDEAD)"
elseif TEST_SECTION == 4 then
    if eboot_base == nil then
        print("[!] eboot_base not available, cannot test section 4")
        print("=== PROBE 77a ABORTED ===")
        return
    end
    -- Point RIP at a "ret" instruction in eboot .text
    -- We'll scan eboot for a 0xC3 byte (ret) in the first 4KB
    local ret_addr = nil
    for off = 0, 0x1000 - 1 do
        local b = rd(eboot_base + off)
        if b then
            local low_byte = b % 256
            if low_byte == 0xC3 then
                ret_addr = eboot_base + off
                print("[4] found ret(0xC3) at eboot+" .. string.format("0x%X", off))
                break
            end
        end
    end
    if ret_addr == nil then
        print("[!] no ret found in eboot first 4KB")
        print("=== PROBE 77a ABORTED ===")
        return
    end
    test_rip = uint64(ret_addr)
    rip_label = "EBOOT_RET (" .. q(ret_addr) .. ")"
    -- For a ret, RSP must point to a valid return address.
    -- Put Thrd_exit on the stack so after ret, the thread calls Thrd_exit(0).
    wq(stack + 0x3FF0, libc_addrofs.Thrd_exit)
    wq(stack + 0x3FF8, 0)
elseif TEST_SECTION == 5 then
    if gpu_region == nil then
        print("[!] gpu_region not available, cannot test section 5")
        print("=== PROBE 77a ABORTED ===")
        return
    end
    -- Write a "ret" opcode (0xC3) into the GPU mmap region
    -- This is RW but not executable, so the CPU should raise an NX fault
    wd(gpu_region, 0xC3)
    test_rip = uint64(gpu_region)
    rip_label = "GPU_MMAP_NX (" .. q(gpu_region) .. ")"
elseif TEST_SECTION == 6 then
    test_rip = uint64(string.format("0x%X%08X", 0xFFFF8000, 0x00000000))
    rip_label = "KERNEL_VA (0xFFFF800000000000)"
else
    print("[!] invalid TEST_SECTION=" .. TEST_SECTION)
    print("=== PROBE 77a ABORTED ===")
    return
end

-- Set the RIP
wq(ctx + 0xF8, test_rip)

print("[" .. TEST_SECTION .. "] RIP=" .. rip_label)
print("[" .. TEST_SECTION .. "] RSP=" .. q(stack + 0x3FF0))

-- Prefill id_slot with sentinel
wd(id_slot, 0xDEADBEEF)
wd(id_slot + 4, 0xDEADBEEF)
print("[" .. TEST_SECTION .. "] id_before=" .. q(rq(id_slot)))

-- Make the call
print("[" .. TEST_SECTION .. "] [BEFORE] thr_create(430)")
local sc_430 = make_syscall(430)
local ok_call, rv = pcall(function()
    return sc_430(uint64(ctx), uint64(id_slot), uint64(0))
end)
print("[" .. TEST_SECTION .. "] [RETURNED] ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))

-- Read back the thread id
local id_val = rq(id_slot)
if id_val then
    print("[" .. TEST_SECTION .. "] id_after=" .. q(id_val))
end

-- Immediate canary
local c1_ok, c1_pid = canary()
print("[" .. TEST_SECTION .. "] canary_immediate ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

-- Wait 500ms then canary again (the crash is delayed)
local ts = memory.alloc(16)
wq(ts, 0)
wq(ts + 8, 500000000)  -- 500ms
print("[" .. TEST_SECTION .. "] sleeping 500ms...")
local sok, srv = pcall(function() return sc_nanosleep(uint64(ts), uint64(0)) end)
print("[" .. TEST_SECTION .. "] sleep_ok=" .. tostring(sok) .. " rv=" .. tostring(srv))

local c2_ok, c2_pid = canary()
print("[" .. TEST_SECTION .. "] canary_500ms ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

-- Wait another 2 seconds
wq(ts, 2)
wq(ts + 8, 0)
print("[" .. TEST_SECTION .. "] sleeping 2s...")
local sok2, srv2 = pcall(function() return sc_nanosleep(uint64(ts), uint64(0)) end)
print("[" .. TEST_SECTION .. "] sleep2_ok=" .. tostring(sok2) .. " rv=" .. tostring(srv2))

local c3_ok, c3_pid = canary()
print("[" .. TEST_SECTION .. "] canary_2500ms ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

-- Wait 5 more seconds
wq(ts, 5)
print("[" .. TEST_SECTION .. "] sleeping 5s...")
local sok3, srv3 = pcall(function() return sc_nanosleep(uint64(ts), uint64(0)) end)
print("[" .. TEST_SECTION .. "] sleep3_ok=" .. tostring(sok3) .. " rv=" .. tostring(srv3))

local c4_ok, c4_pid = canary()
print("[" .. TEST_SECTION .. "] canary_7500ms ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

print("")
print("=== PROBE 77a SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("If the PS5 crashed before this line, the panic timing is in the gaps above.")
print("If this line printed, the PS5 survived 7.5 seconds after thr_create.")
print("=== PROBE 77a COMPLETE ===")
