-- CRASH_CLASS: LOW
-- PROBE 545h: Raw mmap_dmem (syscall 628) with real phys addr from AllocDM
--
-- Prior probes (330a/331a) tested sys 628 with various args and all returned -1.
-- BUT: those tests didn't have a valid phys addr from AllocateDirectMemory.
-- Now we have one: AllocDM returns phys like 0x110010000.
--
-- mmap_dmem signature (from 13.60 dossier):
-- int mmap_dmem(void *addr, size_t len, int prot, int flags,
--               off_t directMemoryStart, size_t len2)
--
-- This is a RAW SYSCALL — no wrapper corruption. make_syscall(628) goes
-- through the loader's syscall path, which works reliably.
-- If 628 works with a valid phys addr, we bypass sceKernelMapDirectMemory entirely.

print("=== 545h: RAW 628 ===")
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
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end

if not libkernel_base then print("FATAL"); return end
print("pid=" .. to_num(syscall.getpid()))

local alloc_fn = libkernel_base + uint64(0x17EF0)

-- Step 1: AllocDM to get a real phys addr
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a or to_num(arv) ~= 0 then print("ALLOC FAIL"); return end
local phys = rq(phys_out)
print("phys=" .. q(phys))

-- Step 2: Try raw mmap_dmem (628) with different arg combos
local sc628 = make_syscall(628)
local target = uint64("0x880000000")

-- Sony constants
local PROT_RW_GPU = 0x33  -- PROT_READ|PROT_WRITE|GPU_READ|GPU_WRITE
local MAP_SHARED = 0x1
local MAP_FIXED = 0x10
local MAP_NO_COALESCE = 0x400000

-- Test A: addr=0x880000000, len=0x4000, prot=0x33, flags=MAP_SHARED|MAP_FIXED,
--         offset=phys, len2=0x4000
print("[A] 628 SHARED+FIXED")
local okA, rvA = pcall(function()
    return sc628(target, uint64(0x4000), uint64(PROT_RW_GPU),
        uint64(MAP_SHARED + MAP_FIXED), phys, uint64(0x4000))
end)
print("[A] ok=" .. tostring(okA))
if okA then
    local n = to_num(rvA)
    if n < 0 then n = n + 0x100000000 end
    print(string.format("[A] rv=0x%X", n))
    -- If rv looks like an address (not -1), it worked
    if n ~= 0xFFFFFFFF and n > 0 then
        print("[A] MAPPED!")
        -- Test R/W
        wd(target, 0xDEADBEEF)
        local v = rd(to_num(target))
        if v then
            if v < 0 then v = v + 0x100000000 end
            print(string.format("[A] rd=0x%08X", v))
            if v == 0xDEADBEEF then
                print("*** RAW 628 R/W WORKS ***")
                print("DONE"); return
            end
        end
    end
end

-- Test B: flags=MAP_SHARED, addr=0 (kernel chooses)
-- Skip this — same collision problem

-- Test C: descriptor-based — open /dev/dmem0, use fd
print("[C] dmem0 fd")
local sc_open = make_syscall(5)
local path_buf = memory.alloc(16)
-- Write "/dev/dmem0\0" as dwords
-- "/dev" = 0x7665642F, "/dme" = 0x656D642F, "m0\0\0" = 0x0000306D
-- Actually: "/dev/dmem0\0" = 2F 64 65 76 2F 64 6D 65 6D 30 00
memory.write_dword(path_buf, 0x7665642F)                -- "/dev"
memory.write_dword(path_buf + uint64(4), 0x656D642F)    -- "/dme"
memory.write_dword(path_buf + uint64(8), 0x00306D)      -- "m0\0"

local okC1, fdC = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))  -- O_RDWR=2
end)
print("[C] open ok=" .. tostring(okC1))
if okC1 then
    local fd = to_num(fdC)
    print("[C] fd=" .. fd)

    if fd >= 0 then
        -- mmap_dmem with dmem0 fd?
        -- Actually 628 might take the fd differently.
        -- Let's try standard mmap (477) with the dmem0 fd and phys as offset
        local sc_mmap = make_syscall(477)
        print("[C] mmap477 dmem0")
        local okC2, rvC2 = pcall(function()
            return sc_mmap(target, uint64(0x4000), uint64(0x33),
                uint64(MAP_SHARED + MAP_FIXED), uint64(fd), phys)
        end)
        print("[C] ok=" .. tostring(okC2))
        if okC2 then
            local n = to_num(rvC2)
            if n < 0 then n = n + 0x100000000 end
            print(string.format("[C] rv=0x%X", n))
            if n ~= 0xFFFFFFFF then
                print("[C] MAPPED!")
                wd(target, 0xBEEFCAFE)
                local v = rd(to_num(target))
                if v then
                    if v < 0 then v = v + 0x100000000 end
                    print(string.format("[C] rd=0x%08X", v))
                    if v == 0xBEEFCAFE then
                        print("*** DMEM0 MMAP R/W WORKS ***")
                        print("DONE"); return
                    end
                end
            end
        end
    end
end

-- Test D: 628 with different prot/flags combos
local combos = {
    {0x3, 0x11, "RW+SHARED+FIXED"},
    {0x3, 0x1, "RW+SHARED"},
    {0x33, 0x1, "RW_GPU+SHARED"},
    {0x33, 0x400001, "RW_GPU+SHARED+NOCOAL"},
    {0x33, 0x400011, "RW_GPU+ALL"},
    {0x3, 0x400011, "RW+ALL"},
}

for _, c in ipairs(combos) do
    local prot, flags, name = c[1], c[2], c[3]
    print(string.format("[D] %s p=0x%X f=0x%X", name, prot, flags))
    local okD, rvD = pcall(function()
        return sc628(target, uint64(0x4000), uint64(prot),
            uint64(flags), phys, uint64(0x4000))
    end)
    if okD then
        local n = to_num(rvD)
        if n < 0 then n = n + 0x100000000 end
        print(string.format("  rv=0x%X", n))
        if n ~= 0xFFFFFFFF and n ~= 0 then
            print("  MAPPED?")
            local ok_t = pcall(function() memory.write_dword(target, 0x42) end)
            local v = rd(to_num(target))
            print("  wd=" .. tostring(ok_t) .. " rd=" .. tostring(v))
        end
    else
        print("  PCALL FAIL")
    end
end

print("pid=" .. to_num(syscall.getpid()))
print("DONE")
