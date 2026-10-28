-- CRASH_CLASS: LOW
-- PROBE 544l: MapDirectMemory — pure Lua print after call (NO memory reads)
--
-- 544g/h/i/j/k all show corruption after MapDM's pcall.
-- Testing: after MapDM, do ONLY pure Lua operations (no memory reads).
-- If prints work, the issue is in memory.read_* / native.read_buffer.
-- If prints still corrupt, the issue is in the Lua state itself.

print("=== PROBE 544l: MapDM PUREPRINT ===")
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

if not libkernel_base then print("FATAL"); return end
print("pid=" .. to_num(syscall.getpid()))

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
print("CALLING MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- PURE LUA ONLY after this point (no memory.read, no native.*)
print("BACK FROM MAP")
print("pcall=" .. tostring(ok_m))
if ok_m then
    print("rv_type=" .. type(mrv))
    print("rv=" .. to_num(mrv))

    -- Can we still do Lua operations?
    local x = 42 + 58
    print("math=" .. x)

    -- Can we still format strings?
    print(string.format("fmt=%d", 12345))

    -- Can we call tostring on rv?
    print("rvstr=" .. tostring(mrv))

    -- Can we do table operations?
    local t = {1, 2, 3}
    print("table=" .. #t)

    -- NOW try to read the uint64 mrv using only its Lua methods
    -- (not memory.read_*, which might be native)
    if type(mrv) == "table" and mrv.h then
        print("mrv.h=" .. mrv.h)
        print("mrv.l=" .. mrv.l)
    end

    -- Try accessing virt_out (uint64 object properties, not memory read)
    print("virt_out addr=" .. q(virt_out))

    -- NOW try a careful memory read
    print("ATTEMPTING memory.read_dword...")
    local ok_rd, val = pcall(function()
        return memory.read_dword(virt_out)
    end)
    print("rd ok=" .. tostring(ok_rd))
    if ok_rd then
        print("rd val=" .. to_num(val))
    else
        print("rd err=" .. tostring(val))
    end

    -- Try memory.read_qword
    print("ATTEMPTING memory.read_qword...")
    local ok_rq, qval = pcall(function()
        return memory.read_qword(virt_out)
    end)
    print("rq ok=" .. tostring(ok_rq))
    if ok_rq then
        print("rq val=" .. q(qval))
    end
else
    print("MAP CRASHED")
    print("err=" .. tostring(mrv))
end

print("canary=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
