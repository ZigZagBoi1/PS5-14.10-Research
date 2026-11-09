-- CRASH_CLASS: LOW
-- PROBE: 13.60 Syscall Table (sysent) Dumper
--
-- On 13.60 jailbroken with kernel R/W, dump the entire sysent table.
-- This gives us the complete syscall handler addresses, which we can
-- then cross-reference with the 14.10 fault oracle to identify
-- handler locations on 14.10 without needing a 14.10 kernel dump.
--
-- The sysent is an array of struct sysent entries:
--   struct sysent {
--       int sy_narg;           // +0x00: number of args
--       sy_call_t *sy_call;    // +0x08: handler function pointer
--       au_event_t sy_auevent; // +0x10: audit event
--       systrace_args_func_t sy_systrace_args_func; // +0x18
--       int sy_entry;          // +0x20
--       int sy_return;         // +0x24
--       int sy_flags;          // +0x28
--       int sy_thrcnt;         // +0x2C
--   };
-- Size: 0x30 (48 bytes) per entry

print("=== SYSENT DUMP v1 ===")
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

-- Step 1: Find kernel base using fault oracle or known offset
local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- On 13.60 jailbroken, the kernel base should be readable
-- The etaHEN patches typically expose kread/kwrite via a specific syscall
-- or by mapping kernel pages into userland

-- Try to find the sysent by reading kernel memory
-- Known 13.60 offsets from the capture:
--   sysent is typically at kernel_base + some_offset

-- First, test if kernel read works at all
print("")
print("=== KERNEL READ TEST ===")

local test_addrs = {
    {0xFFFFFFFF, 0x82200000},
    {0xFFFFFFFF, 0x83000000},
    {0xFFFFFFFF, 0x84000000},
}

local kernel_readable = false
for _, entry in ipairs(test_addrs) do
    local hi, lo = entry[1], entry[2]
    local addr = uint64(string.format("0x%X%08X", hi, lo))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        print(string.format("KREAD %08X%08X = %08X%08X", hi, lo, vh, vl))
        if vh ~= 0 or vl ~= 0 then
            kernel_readable = true
        end
    else
        print(string.format("KREAD %08X%08X = FAULT", hi, lo))
    end
end

if kernel_readable then
    print("")
    print("KERNEL READ: WORKING")
    print("Proceeding with sysent dump...")

    -- The sysent address can be found by:
    -- 1. Reading the IDT/syscall handler at MSR LSTAR
    -- 2. Following the call chain to find sysent reference
    -- 3. Or using known offsets from the 13.60 capture

    -- For now, scan for the sysent signature:
    -- Entry 0 (nosys): sy_narg=0, sy_call points to nosys handler
    -- Entry 1 (sys_exit): sy_narg=1
    -- Entry 2 (fork): sy_narg=0
    -- Entry 3 (read): sy_narg=3
    -- Entry 4 (write): sy_narg=3
    -- Entry 5 (open): sy_narg=3

    print("")
    print("SYSENT_SEARCH: scanning for narg pattern [0,1,0,3,3,3]...")
    print("(This requires knowing the kernel base first)")
    print("See 01_kernel_dump.lua for kernel base discovery")
else
    print("")
    print("KERNEL READ: NOT AVAILABLE")
    print("etaHEN kernel patches may not be active, or the kernel")
    print("read primitive works through a different mechanism.")
    print("")
    print("Alternative approaches:")
    print("1. etaHEN may expose kread via a specific syscall number")
    print("2. The exploit may map kernel pages at a known userland VA")
    print("3. Check if /dev/kmem is accessible after jailbreak")
end

-- Step 2: Try /dev/kmem (may be available after jailbreak)
print("")
print("=== /dev/kmem ACCESS TEST ===")

local sc_open = make_syscall(5)
local kmem_path = memory.alloc(32)
-- Write "/dev/kmem\0" to buffer
local path_str = "/dev/kmem"
for i = 1, #path_str do
    safe_wd(kmem_path + (i-1), string.byte(path_str, i))
end
safe_wd(kmem_path + #path_str, 0)

local kmem_fd = sc_open(uint64(kmem_path), uint64(0), uint64(0))  -- O_RDONLY
local fd_val = to_num(kmem_fd)
print("KMEM_FD: " .. fd_val)

if fd_val >= 0 then
    print("*** /dev/kmem IS ACCESSIBLE ***")
    print("Can read arbitrary kernel memory through file I/O")

    -- Read first 8 bytes at offset 0
    local sc_read = make_syscall(3)
    local sc_lseek = make_syscall(478)  -- lseek

    -- Seek to a kernel address
    local seek_ret = sc_lseek(uint64(fd_val), uint64(0), uint64(0))
    print("SEEK_RET: " .. to_num(seek_ret))

    local read_buf = memory.alloc(8)
    local read_ret = sc_read(uint64(fd_val), uint64(read_buf), uint64(8))
    print("READ_RET: " .. to_num(read_ret))

    if to_num(read_ret) > 0 then
        local rh, rl = get_hi_lo(safe_rq(read_buf))
        print(string.format("KMEM[0] = %08X%08X", rh, rl))
    end

    local sc_close = make_syscall(6)
    sc_close(uint64(fd_val))
else
    print("/dev/kmem not accessible (fd=" .. fd_val .. ")")
    print("This is expected before jailbreak patches are applied")
end

print("")
print("=== SYSENT DUMP v1 COMPLETE ===")
