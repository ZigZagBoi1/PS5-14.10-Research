-- CRASH_CLASS: SAFE (read-only mmap)
-- PROBE 42g2: high physical addresses + phys 0 decode
--
-- 42g found 3577 nonzero qwords at phys 0, zero kernel pointers.
-- Bug in step 2 (missing MB var). This probe:
-- 1. Scans 4GB-16GB for any accessible data
-- 2. Decodes what's at phys 0 (hardware regs? page tables?)
-- 3. Tries kenv syscall (573) for kernel environment strings

print("=== PROBE 42g2: HIGH PHYS + DECODE ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
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
local sc_sysctl = make_syscall(202)

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

--------------------------------------------------------------------
-- STEP 1: kenv syscall — reads kernel environment variables
-- These often contain boot parameters that reveal memory layout
--------------------------------------------------------------------
print("--- STEP 1: KENV (syscall 390) ---")

local sc_kenv = make_syscall(390)
local kenv_buf = memory.alloc(0x2000)
local kenv_len = memory.alloc(8)

-- KENV_DUMP = 0, KENV_GET = 1
-- kenv(KENV_DUMP, NULL, buf, buflen) dumps all env vars
safe_wq(kenv_len, uint64(0x2000))
local ret = nil
local ok = pcall(function()
    ret = sc_kenv(uint64(0), uint64(0), kenv_buf, kenv_len)
end)
local ret_n = ret and to_num(ret) or -1
print("kenv dump: ret=" .. ret_n)

if ret_n >= 0 then
    -- Read strings from buffer
    local pos = 0
    local count = 0
    local max_read = math.min(ret_n, 0x1000)
    while pos < max_read and count < 30 do
        local s = ""
        while pos < max_read do
            local b = safe_rb(kenv_buf + pos)
            pos = pos + 1
            if not b or b == 0 then break end
            if b >= 32 and b < 127 then
                s = s .. string.char(b)
            end
        end
        if #s > 0 then
            count = count + 1
            print("  " .. s)
        end
    end
    print("entries: " .. count)
else
    print("kenv blocked")
end
print("")

--------------------------------------------------------------------
-- STEP 2: High physical addresses (4GB-16GB)
--------------------------------------------------------------------
print("--- STEP 2: HIGH PHYSICAL ADDRESSES ---")

local dmem_fd = dev_open("/dev/dmem0")
print("dmem0 fd: " .. dmem_fd)

if dmem_fd >= 0 then
    -- 4GB to 16GB in 512MB steps
    local high_addrs = {}
    for i = 0, 23 do
        local gb = 4 + i * 0.5
        local total_bytes_hi = math.floor(gb * 4)  -- in units of 0x40000000
        local phys_hi = math.floor(total_bytes_hi / 4)
        local phys_lo = (total_bytes_hi % 4) * 0x40000000
        high_addrs[#high_addrs + 1] = {
            hi = phys_hi, lo = phys_lo,
            label = string.format("%.1fGB", gb)
        }
    end

    for _, ha in ipairs(high_addrs) do
        local off_u64 = uint64(string.format("0x%X%08X", ha.hi, ha.lo))
        local addr = nil
        local map_ok = pcall(function()
            addr = sc_mmap(uint64(0), uint64(0x4000), uint64(1),
                uint64(1), uint64(dmem_fd), off_u64)
        end)
        if map_ok and addr then
            local _, ah, al = qw_hex(addr)
            if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
                local d0 = safe_rd(addr)
                local d4 = safe_rd(addr + 4)
                if d0 ~= nil and (d0 ~= 0 or (d4 and d4 ~= 0)) then
                    local tag = ""
                    if d0 == 0x464C457F then tag = " *** ELF ***" end
                    local q = safe_rq(addr)
                    if q then
                        local _, qh, _ = qw_hex(q)
                        if qh >= 0xFFFF8000 and qh < 0xFFFFFFF0 then
                            tag = tag .. " KPTR!"
                        end
                    end
                    print(string.format("  %s: %08X_%08X%s",
                        ha.label, d4 or 0, d0, tag))
                end
                pcall(function() sc_munmap(addr, uint64(0x4000)) end)
            end
        end
    end

    print("")

    --------------------------------------------------------------------
    -- STEP 3: Decode phys 0 structure
    -- Dump every 0x100-byte block that has non-zero data
    --------------------------------------------------------------------
    print("--- STEP 3: PHYS 0 STRUCTURE ---")

    local addr = nil
    pcall(function()
        addr = sc_mmap(uint64(0), uint64(0x40000), uint64(1),
            uint64(1), uint64(dmem_fd), uint64(0))
    end)

    if addr then
        local _, ah, al = qw_hex(addr)
        if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
            -- First 64 bytes decoded
            print("phys 0x0 first 64 bytes:")
            for off = 0, 0x38, 8 do
                local q = safe_rq(addr + off)
                if q then
                    local hex, qh, ql = qw_hex(q)
                    local tag = ""
                    -- Bit patterns
                    if qh == 0x80000000 then tag = " (bit63 + low32)" end
                    if ql == 0 and qh == 0 then tag = " zero" end
                    print(string.format("  +0x%02X: %s%s", off, hex, tag))
                end
            end

            -- Find regions with dense non-zero data
            print("")
            print("non-zero density (per 256-byte block, first 256KB):")
            for blk = 0, 255 do
                local base = blk * 0x100
                local nz = 0
                for off = 0, 0xF8, 8 do
                    local q = safe_rq(addr + base + off)
                    if q then
                        local _, qh, ql = qw_hex(q)
                        if qh > 0 or ql > 0 then nz = nz + 1 end
                    end
                end
                if nz > 0 then
                    -- Show first qword of this block
                    local first_q = safe_rq(addr + base)
                    print(string.format("  +0x%05X: %d/32 nz, first=%s",
                        base, nz, first_q and qw_hex(first_q) or "?"))
                end
            end

            pcall(function() sc_munmap(addr, uint64(0x40000)) end)
        end
    end

    pcall(function() sc_close(uint64(dmem_fd)) end)
end

print("")
print("=== PROBE 42g2 COMPLETE ===")
