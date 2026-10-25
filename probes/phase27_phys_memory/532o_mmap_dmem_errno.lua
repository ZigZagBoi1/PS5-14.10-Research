-- CRASH_CLASS: LOW
-- PROBE 532o: mmap_dmem(628) with errno capture and proper args
--
-- 532n revealed errno=16 (EBUSY) for sys 628, not EPERM!
-- This means 628 is NOT sandbox-blocked.
-- Previous tests (330a/331a) didn't capture errno.
--
-- From 13.60 analysis: mmap_dmem has 6 slots:
--   arg1 = address (+0x00)
--   arg2 = length (+0x08)
--   arg3 = descriptor (+0x10) — -1 bypasses device lookup
--   arg4 = protection (+0x18)
--   arg5 = flags (+0x20) — 0x40 flag noted
--   arg6 = offset (+0x28)
--
-- Test with: valid dmem0 fd, AllocateDirectMemory phys address,
-- descriptor -1, and various flag combos.

print("=== PROBE 532o: MMAP_DMEM ERRNO ===")
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

local sc_open = make_syscall(5)
local sc_628 = make_syscall(628)

-- Get libkernel base for __error
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

-- Open /dev/dmem0
local dmem_path = memory.alloc(32)
local path_str = "/dev/dmem0\0"
for ci = 1, #path_str do wd(dmem_path + ci - 1, string.byte(path_str, ci)) end
-- Fix: write as bytes not dwords
for ci = 1, #path_str do
    local b = string.byte(path_str, ci)
    pcall(function() memory.write_byte(dmem_path + ci - 1, b) end)
end
-- Use native open - the write_byte may not exist
-- Let's use the dword approach properly
local function write_string(buf, str)
    for pos = 0, #str - 1, 4 do
        local val = 0
        for bi = 0, 3 do
            local ci = pos + bi + 1
            if ci <= #str then
                val = val + string.byte(str, ci) * (256 ^ bi)
            end
        end
        wd(buf + pos, val)
    end
end

local path_buf = memory.alloc(64)
write_string(path_buf, "/dev/dmem0\0")

local ok_o, dmem_fd = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))  -- O_RDWR
end)
local dmem_fdn = to_num(dmem_fd)
print("dmem0_fd=" .. dmem_fdn)

-- Allocate physical memory
local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("phys=" .. q(phys))

-- Test mmap_dmem(628) with various arg combinations
-- Signature from 13.60: (addr, len, descriptor, prot, flags, offset)
print("")
print("[TESTS] mmap_dmem(628) with errno capture")

local tests = {
    -- Basic: descriptor=-1 (bypass device), offset=phys
    { "desc=-1 off=phys", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(0), phys },
    -- With flag 0x40
    { "desc=-1 flags=0x40", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(0x40), phys },
    -- With dmem0 fd
    { "desc=dmem0 off=phys", uint64(0), uint64(0x4000), uint64(dmem_fdn), uint64(3), uint64(0), phys },
    -- dmem0 fd + flag 0x40
    { "desc=dmem0 flags=0x40", uint64(0), uint64(0x4000), uint64(dmem_fdn), uint64(3), uint64(0x40), phys },
    -- desc=-1 offset=0 (in-pool)
    { "desc=-1 off=0", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(0), uint64(0) },
    -- desc=-1 flag=MAP_SHARED(1)
    { "desc=-1 MAP_SHARED", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(1), phys },
    -- desc=-1 flag=0x41
    { "desc=-1 flags=0x41", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(0x41), phys },
    -- dmem0 + offset in pool
    { "dmem0 off=0x10000", uint64(0), uint64(0x4000), uint64(dmem_fdn), uint64(3), uint64(0), uint64(0x10000) },
    -- desc=0
    { "desc=0", uint64(0), uint64(0x4000), uint64(0), uint64(3), uint64(0), phys },
    -- prot=1 (RO)
    { "desc=-1 RO", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(1), uint64(0), phys },
    -- len=0x10000 (64KB)
    { "desc=-1 len=64K", uint64(0), uint64(0x10000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(0), phys },
    -- flag=0x440 (MAP_FIXED + 0x40?)
    { "desc=-1 flags=0x440", uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"), uint64(3), uint64(0x440), phys },
}

for _, t in ipairs(tests) do
    local label = t[1]
    local ok_c, rv = pcall(function()
        return sc_628(t[2], t[3], t[4], t[5], t[6], t[7])
    end)
    local rvn = -999
    if ok_c then rvn = to_num(rv); if rvn < 0 then rvn = rvn + 0x100000000 end end
    local errno = get_errno()

    local va_str = ""
    if ok_c and rv and rvn ~= 0xFFFFFFFF then
        va_str = " VA=" .. q(rv)
        -- Try to read the mapped page
        local ok_r, val = pcall(function() return memory.read_dword(rv) end)
        if ok_r then
            local vn = to_num(val); if vn < 0 then vn = vn + 0x100000000 end
            va_str = va_str .. string.format(" rd=0x%X", vn)
        end
    end
    print(string.format("  %-25s rv=0x%X errno=%d%s", label, rvn, errno, va_str))
end

print("")
print("=== 532o DONE ===")
