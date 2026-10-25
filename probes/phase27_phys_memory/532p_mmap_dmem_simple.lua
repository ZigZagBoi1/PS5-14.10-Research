-- CRASH_CLASS: LOW
-- PROBE 532p: mmap_dmem(628) with errno — simplified
--
-- 532n: errno=16 (EBUSY) for sys 628. NOT sandbox-blocked.
-- 13.60: mmap_dmem(addr, len, descriptor, prot, flags, offset)
-- desc=-1 bypasses device lookup.

print("=== PROBE 532p: MMAP_DMEM SIMPLE ===")
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

local sc_628 = make_syscall(628)

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

-- Allocate physical memory
local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("phys=" .. q(phys))

-- Open /dev/dmem0
local path_buf = memory.alloc(64)
write_string(path_buf, "/dev/dmem0\0")
local ok_o, dmem_fd = pcall(function()
    return make_syscall(5)(uint64(path_buf), uint64(2), uint64(0))
end)
local dmem_fdn = to_num(dmem_fd)
if dmem_fdn < 0 then dmem_fdn = dmem_fdn + 0x100000000 end
print("dmem0_fd=" .. dmem_fdn)

-- Test mmap_dmem(628)
-- Signature: (addr, len, descriptor, prot, flags, offset)
print("")
print("[TESTS]")

local function test(label, a1, a2, a3, a4, a5, a6)
    local ok_c, rv = pcall(function()
        return sc_628(a1, a2, a3, a4, a5, a6)
    end)
    local rvn = -999
    if ok_c then rvn = to_num(rv) end
    local errno = get_errno()

    local extra = ""
    if ok_c and rv and rvn ~= -1 and rvn > 0 then
        extra = " VA=" .. q(rv)
        local ok_r, val = pcall(function() return memory.read_dword(rv) end)
        if ok_r then
            local vn = to_num(val); if vn < 0 then vn = vn + 0x100000000 end
            extra = extra .. string.format(" [rd=0x%X]", vn)
        else
            extra = extra .. " [rd=FAULT]"
        end
    end
    print(string.format("  %-28s rv=%d e=%d%s", label, rvn, errno, extra))
end

-- desc=-1 (bypass device), phys offset
test("desc=-1 off=phys",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), phys)

-- desc=-1 flags=0x40
test("desc=-1 f=0x40",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x40), phys)

-- dmem0 fd
test("desc=dmem0",
    uint64(0), uint64(0x4000), uint64(dmem_fdn),
    uint64(3), uint64(0), phys)

-- dmem0 + flags=0x40
test("dmem0 f=0x40",
    uint64(0), uint64(0x4000), uint64(dmem_fdn),
    uint64(3), uint64(0x40), phys)

-- desc=-1 offset=0
test("desc=-1 off=0",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), uint64(0))

-- desc=-1 flags=1 (MAP_SHARED)
test("desc=-1 f=1",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(1), phys)

-- desc=-1 flags=0x41
test("desc=-1 f=0x41",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x41), phys)

-- dmem0 offset=0x10000
test("dmem0 off=0x10000",
    uint64(0), uint64(0x4000), uint64(dmem_fdn),
    uint64(3), uint64(0), uint64(0x10000))

-- desc=0
test("desc=0",
    uint64(0), uint64(0x4000), uint64(0),
    uint64(3), uint64(0), phys)

-- prot=1
test("desc=-1 prot=1",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(1), uint64(0), phys)

-- prot=0x33 (RWX-ish)
test("desc=-1 prot=0x33",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(0x33), uint64(0), phys)

-- flags=2 (MAP_PRIVATE)
test("desc=-1 f=2",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(2), phys)

-- flags=0x1002 (MAP_ANON|MAP_PRIVATE)
test("desc=-1 f=0x1002",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0x1002), phys)

-- All zeros
test("all zeros",
    uint64(0), uint64(0x4000), uint64(0),
    uint64(0), uint64(0), uint64(0))

-- Phys address below GPU pool (system RAM?)
test("desc=-1 off=0x1000",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), uint64(0x1000))

-- Phys 0x80000000 (2GB)
test("desc=-1 off=0x80000000",
    uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
    uint64(3), uint64(0), uint64("0x80000000"))

print("")
print("=== 532p DONE ===")
