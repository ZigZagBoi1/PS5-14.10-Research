-- CRASH_CLASS: LOW
-- PROBE 544p: MapDirectMemory — test different flags and read result
--
-- Key findings:
-- 1. MapDM IS 6-arg (Apollo loader confirms: out, size, prot, flags, phys, align)
-- 2. rv=0 confirmed but process crashes after call (address collision)
-- 3. Lua prints work after MapDM (544n: A/B/C/D ok) when collision is mild
-- 4. memory.read_dword crashes after MapDM (544n: D ok, then crash)
--
-- Strategy: call MapDM multiple times with different flag values.
-- Before EACH call, alloc fresh phys and re-alloc fresh virt_out far from heap.
-- Use fcall() table (not native.fcall_with_rax) if possible.
-- After each call, only do pure Lua prints (no memory reads).
-- Count which calls survive.
--
-- Actually: the simplest test is to NOT read the result.
-- Just call MapDM and see if Lua survives. If it does, we know
-- the mapping was created. Then we can access it later.
--
-- Better: MapDM writes to *virt_out. We set virt_out to point to a
-- KNOWN safe location. If MapDM respects the hint at *virt_out,
-- it maps at that address. If not, it writes a new address there.
--
-- Since we can't READ virt_out safely, we test: can we WRITE to
-- the target address (0x880000000) after MapDM?

print("=== 544p: MapDM FLAGS ===")
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
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- Test: can we write/read to 0x880000000 BEFORE MapDM?
local target = uint64("0x880000000")
print("pre-map test on target")
local ok_pre_w = pcall(function() memory.write_dword(target, 0x12345678) end)
print("  write=" .. tostring(ok_pre_w))
if ok_pre_w then
    local v = rd(to_num(target))
    if v then
        if v < 0 then v = v + 0x100000000 end
        print("  read=" .. string.format("0x%X", v))
    else
        print("  read=FAULT")
    end
else
    print("  (not mapped yet, expected)")
end

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

-- Test different flag values for MapDM
-- Sony SDK flags for MapDirectMemory may differ from FreeBSD mmap flags
-- Possible flags:
-- 0x00 - default
-- 0x10 - MAP_FIXED equivalent
-- 0x01 - unknown
-- 0x40 - dmem0-related?

local flags_to_test = {0, 0x10, 1, 0x40}

for _, fl in ipairs(flags_to_test) do
    -- Need fresh virt_out for each attempt
    -- But we can't use memory.alloc (might be near heap corruption zone)
    -- Use a pre-allocated large buffer with offsets
    local virt_buf = memory.alloc(0x100)
    -- Set the hint address
    wq(virt_buf, uint64("0x880000000"))

    print(string.format("MAP flags=0x%X", fl))
    local ok_m = pcall(function()
        native.fcall_with_rax(map_fn, 0,
            uint64(virt_buf), uint64(0x4000), uint64(3),
            uint64(fl), phys, uint64(0x4000))
    end)
    print("  ok=" .. tostring(ok_m))

    if ok_m then
        -- Try to access 0x880000000 (might be mapped now)
        print("  testing target...")
        local ok_tw = pcall(function() memory.write_dword(target, 0xCAFEBABE) end)
        print("  wd=" .. tostring(ok_tw))
        if ok_tw then
            local rv = rd(to_num(target))
            if rv then
                if rv < 0 then rv = rv + 0x100000000 end
                print(string.format("  rd=0x%08X", rv))
                if rv == 0xCAFEBABE then
                    print("  *** MAPPED AT TARGET ***")

                    -- Dump first 32 bytes
                    for off = 0, 28, 4 do
                        local dw = rd(to_num(target) + off)
                        if dw then
                            if dw < 0 then dw = dw + 0x100000000 end
                            io.write(string.format("%08X ", dw))
                        end
                    end
                    print("")
                    break -- success!
                end
            else
                print("  rd=FAULT")
            end
        end

        -- AllocDM again for next attempt (need new phys for each map)
        wq(phys_out, uint64(0))
        local ok_a2, arv2 = pcall(function()
            return native.fcall_with_rax(alloc_fn, 0,
                uint64(0), uint64("0x150000000"), uint64(0x4000),
                uint64(0x4000), uint64(0), uint64(phys_out))
        end)
        if ok_a2 and to_num(arv2) == 0 then
            phys = memory.read_qword(phys_out)
        else
            print("  AllocDM2 fail, stopping")
            break
        end
    end
end

print("C=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
