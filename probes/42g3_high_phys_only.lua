-- CRASH_CLASS: SAFE (read-only mmap)
-- PROBE 42g3: high physical addresses + phys 0 decode
-- kenv (42g2) killed the process. Skip it. Just scan high phys.

print("=== PROBE 42g3: HIGH PHYS + PHYS0 DECODE ===")
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
-- STEP 1: High physical addresses (4GB to 16GB, 512MB steps)
--------------------------------------------------------------------
print("")
print("--- STEP 1: HIGH PHYSICAL ADDRESSES ---")

-- Build offsets manually to avoid float issues
-- 4GB = 0x1_00000000, 4.5GB = 0x1_20000000, etc.
local high_offsets = {
    {1, 0x00000000, "4.0GB"},
    {1, 0x20000000, "4.5GB"},
    {1, 0x40000000, "5.0GB"},
    {1, 0x60000000, "5.5GB"},
    {1, 0x80000000, "6.0GB"},
    {1, 0xA0000000, "6.5GB"},
    {1, 0xC0000000, "7.0GB"},
    {1, 0xE0000000, "7.5GB"},
    {2, 0x00000000, "8.0GB"},
    {2, 0x40000000, "9.0GB"},
    {2, 0x80000000, "10GB"},
    {2, 0xC0000000, "11GB"},
    {3, 0x00000000, "12GB"},
    {3, 0x40000000, "13GB"},
    {3, 0x80000000, "14GB"},
    {3, 0xC0000000, "15GB"},
}

for _, ha in ipairs(high_offsets) do
    local off_u64 = uint64(string.format("0x%X%08X", ha[1], ha[2]))
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
            local tag = ""
            if d0 == 0x464C457F then tag = " *** ELF ***" end
            if d0 ~= nil and (d0 ~= 0 or (d4 and d4 ~= 0)) then
                local q = safe_rq(addr)
                if q then
                    local _, qh, _ = qw_hex(q)
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFF0 then
                        tag = tag .. " KPTR!"
                    end
                end
                print(string.format("  %s: %08X_%08X%s", ha[3], d4 or 0, d0, tag))
            else
                print(string.format("  %s: zeros", ha[3]))
            end
            pcall(function() sc_munmap(addr, uint64(0x4000)) end)
        else
            print(string.format("  %s: MAP_FAILED", ha[3]))
        end
    else
        print(string.format("  %s: mmap error", ha[3]))
    end
end
print("")

--------------------------------------------------------------------
-- STEP 2: Phys 0 decode — first 64 bytes + density map
--------------------------------------------------------------------
print("--- STEP 2: PHYS 0 DECODE ---")

local addr = nil
pcall(function()
    addr = sc_mmap(uint64(0), uint64(0x40000), uint64(1),
        uint64(1), uint64(dmem_fd), uint64(0))
end)

if addr then
    local _, ah, al = qw_hex(addr)
    if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
        print("first 128 bytes:")
        for off = 0, 0x78, 8 do
            local q = safe_rq(addr + off)
            if q then
                print(string.format("  +0x%02X: %s", off, qw_hex(q)))
            end
        end
        print("")

        -- Find non-zero 256-byte blocks in first 256KB
        print("non-zero blocks (256B each):")
        local total_nz_blocks = 0
        for blk = 0, 1023 do
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
                total_nz_blocks = total_nz_blocks + 1
                if total_nz_blocks <= 20 then
                    local fq = safe_rq(addr + base)
                    print(string.format("  +0x%05X: %d/32 nz first=%s",
                        base, nz, fq and qw_hex(fq) or "?"))
                end
            end
        end
        print("total non-zero blocks: " .. total_nz_blocks .. " / 1024")

        pcall(function() sc_munmap(addr, uint64(0x40000)) end)
    end
end

pcall(function() sc_close(uint64(dmem_fd)) end)
print("")
print("=== PROBE 42g3 COMPLETE ===")
