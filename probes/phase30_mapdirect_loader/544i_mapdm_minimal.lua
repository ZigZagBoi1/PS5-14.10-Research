-- CRASH_CLASS: LOW
-- PROBE 544i: MapDirectMemory — minimal, read result immediately
--
-- 544g: rv=0 printed correctly, then Lua corrupted at section [D]
-- 544h: corruption starts earlier, inside section [C]
--
-- This probe: absolute minimum code path after MapDM returns.
-- Read virt_out with memory.read_dword immediately after pcall.
-- Print the address bytes, then test R/W on the mapped page.

print("=== PROBE 544i: MapDM MINIMAL ===")
io.stdout:setvbuf("no")

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
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end

if not libkernel_base then print("FATAL"); return end
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- AllocDM
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a or to_num(arv) ~= 0 then print("ALLOC FAIL"); return end
local phys = memory.read_qword(phys_out)
print("phys=" .. q(phys))

-- Prepare virt_out
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- MapDM
print("MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- IMMEDIATELY read virt_out with dword reads (most reliable)
local lo = rd(to_num(virt_out))
local hi = rd(to_num(virt_out) + 4)
if lo and hi then
    if lo < 0 then lo = lo + 0x100000000 end
    if hi < 0 then hi = hi + 0x100000000 end
    print(string.format("VIRT=%08X%08X", hi, lo))
else
    print("VIRT=FAULT")
end

-- Print rv
if ok_m then
    print("RV=" .. to_num(mrv))
else
    print("RV=CRASH:" .. tostring(mrv))
end

-- If we have a virtual address, test R/W
if lo and hi and (lo ~= 0 or hi ~= 0) then
    local virt = uint64(string.format("0x%X%08X", hi, lo))
    print("TESTING " .. q(virt))

    -- Write pattern
    local ok_w = wd(virt, 0xDEADBEEF)
    print("W=" .. tostring(ok_w))

    if ok_w then
        local rb = rd(to_num(virt))
        if rb then
            if rb < 0 then rb = rb + 0x100000000 end
            print(string.format("R=0x%08X", rb))
            if rb == 0xDEADBEEF then
                print("*** PHYSICAL MEMORY R/W ***")
            end
        end
    end

    -- Write second pattern
    wd(virt + uint64(4), 0xCAFEBABE)
    local rb2 = rd(to_num(virt) + 4)
    if rb2 then
        if rb2 < 0 then rb2 = rb2 + 0x100000000 end
        print(string.format("R2=0x%08X", rb2))
    end

    -- Dump first 32 bytes
    print("PAGE:")
    -- Reset to zero first
    wd(virt, 0)
    wd(virt + uint64(4), 0)
    for off = 0, 28, 4 do
        local dw = rd(to_num(virt) + off)
        if dw then
            if dw < 0 then dw = dw + 0x100000000 end
            io.write(string.format("%08X ", dw))
        end
    end
    print("")
end

print("C=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
