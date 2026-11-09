-- CRASH_CLASS: LOW
-- PROBE 545c: MapDirectMemory — call with INVALID args first (should fail, not crash)
--
-- If MapDM with bad args returns error and memory.* works after → the crash
-- is caused by the MAPPING, not by calling MapDM itself.
--
-- Then: test if a FIXED address hint avoids the collision.
-- Use: *virt_out = mmap'd page (pre-allocate an anonymous page there, then
-- MapDM should MAP_FIXED over it)

print("=== 545c: FAIL FIRST ===")
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

-- ====== TEST 1: Call MapDM with INVALID phys addr (should return error) ======
local virt_out1 = memory.alloc(8)
wq(virt_out1, uint64(0))

print("[1] BAD CALL")
local ok1, rv1 = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out1), uint64(0x4000), uint64(0x33),
        uint64(0x400000), uint64(0xDEADDEAD), uint64(0x4000))
end)
print("[1] ok=" .. tostring(ok1))
if ok1 then
    local n = to_num(rv1)
    if n < 0 then n = n + 0x100000000 end
    print(string.format("[1] rv=0x%X", n))
end

-- Can we still use memory.read_dword?
local heap_test = memory.alloc(8)
wd(heap_test, 0x12345678)
local v1 = rd(to_num(heap_test))
if v1 then
    if v1 < 0 then v1 = v1 + 0x100000000 end
    print(string.format("[1] rd=0x%X", v1))
else
    print("[1] rd=FAIL")
end

-- ====== TEST 2: AllocDM (get real phys addr) ======
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

-- ====== TEST 3: Pre-mmap anonymous page at 0x880000000 ======
-- mmap(0x880000000, 0x4000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANON|MAP_PRIVATE, -1, 0)
-- MAP_FIXED=0x10, MAP_ANON=0x1000, MAP_PRIVATE=0x2
local sc_mmap = make_syscall(477)
local target = uint64("0x880000000")
print("[3] PRE-MMAP")
local ok3, mm3 = pcall(function()
    return sc_mmap(target, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
end)
print("[3] ok=" .. tostring(ok3))
if ok3 then print("[3] addr=" .. q(mm3)) end

-- Verify: write/read the pre-mapped page
local ok3w = wd(target, 0xCAFEBABE)
print("[3] wd=" .. tostring(ok3w))
local v3 = rd(to_num(target))
if v3 then
    if v3 < 0 then v3 = v3 + 0x100000000 end
    print(string.format("[3] rd=0x%X", v3))
else
    print("[3] rd=FAIL")
end

-- ====== TEST 4: MapDM with hint pointing to pre-mapped page ======
-- Set *virt_out = 0x880000000 (where we already have an anonymous mapping)
local virt_out2 = memory.alloc(8)
wq(virt_out2, target)

print("[4] MAP FIXED")
local ok4, rv4 = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out2), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

-- Post-MapDM
print("[4] A")
io.flush()
print("[4] ok=" .. tostring(ok4))
io.flush()

if ok4 then
    local n4 = to_num(rv4)
    if n4 < 0 then n4 = n4 + 0x100000000 end
    print(string.format("[4] rv=0x%X", n4))
    io.flush()
end

-- Read virt_out2 (did MapDM change it?)
print("[4] RD_VO")
io.flush()
local vo2 = rq(virt_out2)
if vo2 then
    print("[4] vo=" .. q(vo2))
    io.flush()
end

-- Write to 0x880000000 (should now be direct memory)
print("[4] WR_TGT")
io.flush()
local ok4w = wd(target, 0xDEADBEEF)
print("[4] wd=" .. tostring(ok4w))
io.flush()

-- Read from 0x880000000
print("[4] RD_TGT")
io.flush()
local v4 = rd(to_num(target))
if v4 then
    if v4 < 0 then v4 = v4 + 0x100000000 end
    print(string.format("[4] rd=0x%X", v4))
    if v4 == 0xDEADBEEF then
        print("*** DIRECT MEMORY R/W AT 0x880000000 ***")
    end
else
    print("[4] rd=FAULT")
end
io.flush()

-- Canary
print("pid=" .. to_num(syscall.getpid()))
print("DONE")
