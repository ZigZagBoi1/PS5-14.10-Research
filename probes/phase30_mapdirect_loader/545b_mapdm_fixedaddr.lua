-- CRASH_CLASS: LOW
-- PROBE 545b: MapDirectMemory — force virtual address 0x880000000
--
-- KEY HYPOTHESIS: The crash after MapDM is NOT inherent to native.fcall_with_rax.
-- It's because MapDM maps to a random virtual address that sometimes collides
-- with loader/heap/native handler memory.
--
-- TEST: Set *virt_out = 0x880000000 (well above typical userland heap).
-- If MapDM respects this hint and maps there, the collision is avoided.
-- Then memory.read_dword/write_dword should work fine.
--
-- If this works → KASLR defeat is next (map physical RAM at known address).

print("=== 545b: FIXED ADDR ===")
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
local map_fn = libkernel_base + uint64(0x15020)

-- Step 1: AllocDM (works fine from main thread)
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

-- Step 2: Set virt_out to FIXED address 0x880000000
-- This is ~34GB, well above typical game process heap
local target_addr = uint64("0x880000000")
local virt_out = memory.alloc(8)
wq(virt_out, target_addr)

-- Verify the write
local check = rq(virt_out)
print("hint=" .. q(check))

-- Skip pre-test: we KNOW 0x880000000 is not mapped (reading crashes the signal handler)

-- Step 4: MapDM with hint address and Apollo flags
print("MAP")
io.flush()
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

-- Step 5: Post-MapDM tests
print("A")
io.flush()

-- Don't access mrv yet. First test basic ops.
print("B")
io.flush()

-- Read a pre-existing heap address (not virt_out, not mapped page)
-- This tests if memory.read_dword works at all
print("T1")
io.flush()
local t1_buf = memory.alloc(8)  -- fresh alloc after MapDM
-- Wait, memory.alloc might crash too. Let's use phys_out (allocated before)
local ok_t1, v_t1 = pcall(function() return memory.read_dword(phys_out) end)
print("T1=" .. tostring(ok_t1))
io.flush()
if ok_t1 then
    local v = to_num(v_t1)
    if v < 0 then v = v + 0x100000000 end
    print(string.format("T1v=0x%X", v))
    io.flush()
end

-- Read virt_out (did MapDM change it from 0x880000000?)
print("T2")
io.flush()
local ok_t2, v_t2 = pcall(function() return memory.read_qword(virt_out) end)
print("T2=" .. tostring(ok_t2))
io.flush()
if ok_t2 then
    print("T2v=" .. q(v_t2))
    io.flush()
end

-- Write to the mapped page at 0x880000000
print("T3")
io.flush()
local ok_t3 = pcall(function() memory.write_dword(target_addr, 0xDEADBEEF) end)
print("T3=" .. tostring(ok_t3))
io.flush()

-- Read back from mapped page
print("T4")
io.flush()
local ok_t4, v_t4 = pcall(function() return memory.read_dword(target_addr) end)
print("T4=" .. tostring(ok_t4))
io.flush()
if ok_t4 then
    local v = to_num(v_t4)
    if v < 0 then v = v + 0x100000000 end
    print(string.format("T4v=0x%X", v))
    if v == 0xDEADBEEF then
        print("*** DIRECT MEMORY R/W CONFIRMED ***")
    end
    io.flush()
end

-- Canary: getpid
print("T5")
io.flush()
local ok_t5, v_t5 = pcall(function() return syscall.getpid() end)
if ok_t5 then
    print("T5pid=" .. to_num(v_t5))
else
    print("T5=FAIL")
end

print("DONE")
