-- CRASH_CLASS: MODERATE
-- PROBE: 13.60 Kernel Memory Dumper
--
-- Dumps the full kernel .text section on a jailbroken 13.60 PS5.
-- After etaHEN gives kernel R/W, this reads kernel memory and sends
-- it back as hex over the TCP connection.
--
-- The orchestrator calls this repeatedly with different START/SIZE
-- values to reassemble the full image on the server side.
--
-- Protocol: each line starting with "HEXDATA:" carries 64 hex chars
-- (32 bytes). The orchestrator strips the prefix and concatenates.

print("=== KERNEL DUMP v1 ===")
print("FIRMWARE: 13.60")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Step 1: Identify the system
local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- Get OS release
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 2)   -- KERN_OSRELEASE
local outbuf = memory.alloc(256)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 256)
local ret = sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
if to_num(ret) == 0 then
    local osrel = ""
    for i = 0, 63 do
        local c = safe_rd(outbuf + i)
        if not c or c == 0 then break end
        osrel = osrel .. string.char(c % 256)
    end
    print("OSRELEASE: " .. osrel)
end

-- Step 2: Use the fault oracle to find kernel base
-- On 13.60 jailbroken, we may also have direct kernel R/W via
-- the etaHEN patches. Try both approaches.

-- Approach A: Try reading from known 13.60 kernel base range
-- The 13.60 captures show kernel at ~0xFFFFFFFF82200000
-- but KASLR means we need to find it per-boot

-- Use the fault oracle (same as 14.10 probes 1199a-c)
-- thr_create child with RIP=candidate, signal handler reads error code

print("")
print("=== KERNEL BASE SCAN ===")

-- Get eboot base for gadgets
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info_buf) end)
local eboot_lo = safe_rd(info_buf + 0x108)
local eboot_hi = safe_rd(info_buf + 0x10C)
if eboot_lo and eboot_hi then
    print("EBOOT_BASE: " .. string.format("0x%X%08X", eboot_hi, eboot_lo))
else
    print("EBOOT_BASE: FAILED")
end

-- Try to read kernel memory directly (works if etaHEN patched the kernel)
-- Test with a known kernel stub address first
print("")
print("=== DIRECT KERNEL READ TEST ===")

-- Try reading 0xFFFFFFFF80000000 (typical low end of kernel VA)
local test_addrs = {
    {0xFFFFFFFF, 0x80000000, "stub_low"},
    {0xFFFFFFFF, 0x82200000, "13.60_typical"},
    {0xFFFFFFFF, 0xC0000000, "14.10_stub"},
}

for _, entry in ipairs(test_addrs) do
    local hi, lo, label = entry[1], entry[2], entry[3]
    local addr = uint64(string.format("0x%X%08X", hi, lo))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        print(string.format("READ[%s] 0x%X%08X = 0x%08X%08X", label, hi, lo, vh, vl))
    else
        print(string.format("READ[%s] 0x%X%08X = FAULT", label, hi, lo))
    end
end

-- Step 3: If direct read works, dump a chunk
-- The orchestrator will call this with specific addresses
-- For now, report what we found

-- Try to use the VM map (sys 674) to enumerate all regions
-- This gives us the full process memory layout
print("")
print("=== VM MAP (sys 674) ===")
local sc_vm = make_syscall(674)
local vm_buf = memory.alloc(0x8000)  -- 32KB buffer
local vm_count = 0

-- 674 signature: (addr, outbuf, count_ptr)
local count_ptr = memory.alloc(8)
safe_wd(count_ptr, 512)  -- max 512 entries

local vm_ret = sc_vm(uint64(0), uint64(vm_buf), uint64(count_ptr))
local vm_ret_val = to_num(vm_ret)
print("VM_RET: " .. vm_ret_val)

if vm_ret_val == 0 then
    -- Each entry is 72 bytes: +0x00 start, +0x08 end, +0x18 prot, +0x20 name
    local entry_size = 72
    local num_entries = safe_rd(count_ptr) or 0
    print("VM_ENTRIES: " .. num_entries)

    for i = 0, math.min(num_entries - 1, 511) do
        local base = vm_buf + i * entry_size
        local start_q = safe_rq(base)
        local end_q = safe_rq(base + 8)
        local prot = safe_rd(base + 0x18)

        if start_q and end_q then
            local sh, sl = get_hi_lo(start_q)
            local eh, el = get_hi_lo(end_q)
            -- Read name string at +0x20
            local name = ""
            for j = 0, 31 do
                local c = safe_rd(base + 0x20 + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then
                    name = name .. string.char(c)
                end
            end
            print(string.format("VM[%03d] %08X%08X-%08X%08X p=0x%X %s",
                i, sh, sl, eh, el, prot or 0, name))
        end
    end
end

print("")
print("=== KERNEL DUMP v1 COMPLETE ===")
print("NOTE: If direct kernel reads failed, the fault oracle is needed.")
print("The orchestrator will proceed with the appropriate method.")
