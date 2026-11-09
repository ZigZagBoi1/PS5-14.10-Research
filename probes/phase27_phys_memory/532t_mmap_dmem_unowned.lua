-- CRASH_CLASS: LOW
-- PROBE 532t: mmap_dmem(628) with un-allocated physical addresses
--
-- 532r/532s: mmap_dmem works with desc=-1 + AllocateDirectMemory phys.
-- Question: does it check ownership? Can we map phys pages we didn't allocate?
-- If yes: map kernel physical pages, other process memory, etc.
--
-- Test: try physical addresses in the GPU pool that we did NOT allocate.
-- Our allocations start at ~0x110010000. Try addresses before that.
-- Also: try batch_map(548) with different arg shapes.

print("=== PROBE 532t: MMAP_DMEM UNOWNED ===")
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

-- First: allocate one page to establish our range
local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local our_phys = rq(phys_out)
print("our_phys=" .. q(our_phys))

-- Map our page as baseline
local ok_b, va_b = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), our_phys)
end)
print("baseline: VA=" .. q(va_b) .. " e=" .. get_errno())

-- [A] Try un-allocated addresses in the GPU pool
print("")
print("[A] Un-allocated GPU pool addresses")

-- The GPU pool is 0x100000000-0x150000000 (1.25 GB)
-- Our allocs start at ~0x110010000
-- Pages BEFORE our allocs should be "someone else's" or free
local test_offsets = {
    0x100000000,  -- start of pool
    0x100004000,
    0x100008000,
    0x100100000,  -- 1MB into pool
    0x101000000,  -- 16MB into pool
    0x108000000,  -- 128MB into pool
    0x110000000,  -- near our allocs
    0x110004000,  -- just before our first alloc (~0x110010000)
    0x110008000,
    0x11000C000,
    0x120000000,  -- 256MB past pool start
    0x130000000,  -- 768MB past
    0x140000000,  -- 1GB past
    0x14FFF0000,  -- near end of pool
}

for _, off in ipairs(test_offsets) do
    local ok_m, va_m = pcall(function()
        return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(3), uint64(0), uint64(string.format("0x%X", off)))
    end)
    local rvn = -999; if ok_m then rvn = to_num(va_m) end
    local errno = get_errno()
    
    local extra = ""
    if ok_m and rvn > 0 then
        extra = " VA=" .. q(va_m)
        local ok_r, val = pcall(function() return memory.read_dword(va_m) end)
        if ok_r then
            local vn = to_num(val); if vn < 0 then vn = vn + 0x100000000 end
            extra = extra .. string.format(" [0x%08X]", vn)
        else
            extra = extra .. " [FAULT]"
        end
        -- Unmap
        pcall(function() make_syscall(73)(va_m, uint64(0x4000)) end)
    end
    print(string.format("  0x%09X: rv=%d e=%d%s", off, rvn, errno, extra))
end

-- [B] Try system RAM via batch_map(548)
print("")
print("[B] batch_map(548) tests")
-- batch_map has 5 args. Maybe: (ops*, count, ?, ?, ?)
-- Or: (start_addr, len, prot, flags, phys_offset)
-- Try the same pattern as mmap_dmem
local sc_548 = make_syscall(548)

local ok_bm, rv_bm = pcall(function()
    return sc_548(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0))
end)
print("  548(0, 0x4000, -1, 3, 0): rv=" .. (ok_bm and tostring(to_num(rv_bm)) or "pcall_fail") .. " e=" .. get_errno())

-- With our allocated phys as 5th arg
local ok_bm2, rv_bm2 = pcall(function()
    return sc_548(uint64(0), uint64(0x4000), uint64(3),
        uint64(0), our_phys)
end)
print("  548(0, 0x4000, 3, 0, phys): rv=" .. (ok_bm2 and tostring(to_num(rv_bm2)) or "pcall_fail") .. " e=" .. get_errno())

-- Try batch_map as array-of-ops
-- Allocate an "operation struct" with MapDirectMemory-like fields
local op = memory.alloc(0x40)
zero(op, 0x40)
wq(op + 0x00, uint64(0))         -- addr (out?)
wq(op + 0x08, uint64(0x4000))    -- len
wq(op + 0x10, our_phys)          -- phys offset
wd(op + 0x18, 3)                 -- prot
wd(op + 0x1C, 0)                 -- flags

local ok_bm3, rv_bm3 = pcall(function()
    return sc_548(uint64(op), uint64(1), uint64(0), uint64(0), uint64(0))
end)
print("  548(op_buf, 1, 0, 0, 0): rv=" .. (ok_bm3 and tostring(to_num(rv_bm3)) or "pcall_fail") .. " e=" .. get_errno())

-- Check if op buffer was modified
local addr_out = rq(op)
print("  op[0]=" .. q(addr_out))

print("")
print("=== 532t DONE ===")
