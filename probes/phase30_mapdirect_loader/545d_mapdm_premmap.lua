-- CRASH_CLASS: LOW
-- PROBE 545d: MapDirectMemory with pre-mmap'd target address
--
-- Root cause confirmed: MapDM with *virt_out=0 lets kernel choose VA,
-- which sometimes falls on heap → corrupts Lua objects → crash.
--
-- FIX: pre-mmap an anon page at 0x880000000, set *virt_out=0x880000000,
-- then MapDM should map direct memory there.
--
-- If MapDM doesn't respect the hint, try with MAP_FIXED flag (0x10).

print("=== 545d: PREMMAP ===")
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

-- Step 1: Pre-mmap anon page at 0x880000000
local sc_mmap = make_syscall(477)
local target = uint64("0x880000000")
-- MAP_FIXED=0x10, MAP_ANON=0x1000, MAP_PRIVATE=0x2
-- prot = PROT_READ|PROT_WRITE = 3
local ok_pm, pm_rv = pcall(function()
    return sc_mmap(target, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
end)
if not ok_pm then print("PREMMAP PCALL FAIL"); return end
local pm_addr = to_num(pm_rv)
if pm_addr < 0 then pm_addr = pm_addr + 0x100000000 end
print(string.format("premmap=0x%X", pm_addr))

-- Verify: write/read the pre-mapped page
wd(target, 0xAAAABBBB)
local pre_v = rd(to_num(target))
if pre_v then
    if pre_v < 0 then pre_v = pre_v + 0x100000000 end
    print(string.format("pre_rd=0x%X", pre_v))
else
    print("pre_rd=FAIL (0x880000000 not mapped)")
    return
end

-- Step 2: AllocDM
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

-- Step 3: MapDM with *virt_out = 0x880000000 (hint to pre-mapped region)
local virt_out = memory.alloc(8)
wq(virt_out, target)  -- set hint = 0x880000000

print("MAP")
io.flush()
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out),            -- &virt_addr (in/out)
        uint64(0x4000),              -- size = 16KB
        uint64(0x33),                -- prot = R|W|GPU_R|GPU_W
        uint64(0x400000),            -- flags = MAP_NO_COALESCE
        phys,                        -- phys_addr
        uint64(0x4000))              -- alignment
end)

-- Post-MapDM
print("A")
io.flush()

-- Check pcall result
if ok_m then
    print("B:ok")
    io.flush()
    local rv_n = to_num(mrv)
    if rv_n < 0 then rv_n = rv_n + 0x100000000 end
    print(string.format("rv=0x%X", rv_n))
    io.flush()

    if rv_n ~= 0 then
        print("MAP ERR")
        -- Try without MAP_NO_COALESCE, or with different flags
        -- But first check if memory works
        print("C:rd_check")
        local heap_v = rd(to_num(phys_out))
        if heap_v then
            print("heap_ok")
        else
            print("heap_fail")
        end
        return
    end
else
    print("B:fail=" .. tostring(mrv))
    io.flush()
    -- MapDM pcall failed, but check if memory works
    print("C:rd_check")
    io.flush()
    local heap_v = rd(to_num(phys_out))
    if heap_v then
        print("heap_ok_after_fail")
    else
        print("heap_fail")
    end
    return
end

-- MapDM returned 0! Now read where it actually mapped
print("C:rd_virt_out")
io.flush()
local mapped_addr = rq(virt_out)
if mapped_addr then
    print("mapped=" .. q(mapped_addr))
    io.flush()
else
    print("mapped=READ_FAIL")
    io.flush()
    -- Can't read virt_out — try accessing 0x880000000 directly
    print("D:direct_test")
    wd(target, 0xDEADBEEF)
    local dv = rd(to_num(target))
    if dv then
        if dv < 0 then dv = dv + 0x100000000 end
        print(string.format("direct=0x%X", dv))
    else
        print("direct=FAIL")
    end
    return
end

-- Check if it mapped at our hint address
local mh, ml = 0, 0
if type(mapped_addr) == "table" and mapped_addr.h then
    mh = mapped_addr.h or 0
    ml = mapped_addr.l or 0
    if mh < 0 then mh = mh + 0x100000000 end
    if ml < 0 then ml = ml + 0x100000000 end
end

if mh == 8 and ml == 0x80000000 then
    print("*** MAPPED AT HINT 0x880000000 ***")
else
    print(string.format("mapped_at=%08X%08X", mh, ml))
end

-- Test R/W on mapped page (use the actual mapped address)
print("D:write")
io.flush()
local ok_w = wd(mapped_addr, 0xDEADBEEF)
print("wd=" .. tostring(ok_w))
io.flush()

print("E:read")
io.flush()
local rv_read = rd(to_num(mapped_addr))
if rv_read then
    if rv_read < 0 then rv_read = rv_read + 0x100000000 end
    print(string.format("rd=0x%08X", rv_read))
    if rv_read == 0xDEADBEEF then
        print("*** DIRECT MEMORY R/W CONFIRMED ***")
        -- Dump first 64 bytes
        print("DUMP:")
        for off = 0, 60, 4 do
            local dw = rd(to_num(mapped_addr) + off)
            if dw then
                if dw < 0 then dw = dw + 0x100000000 end
                io.write(string.format("%08X ", dw))
            end
        end
        print("")
    end
else
    print("rd=FAULT")
end

-- Canary
print("F:pid=" .. to_num(syscall.getpid()))
print("DONE")
