-- CRASH_CLASS: LOW
-- PROBE 545g: Is native handler dead after MapDM, or only memory.*?
--
-- Minimal test sequence:
-- 1. AllocDM #1 (confirm native handler works)
-- 2. MapDM with *virt_out=0x880000000, flags=0x400000
-- 3. DO NOT access return value
-- 4. DO NOT use memory.read/write
-- 5. Try native.fcall_with_rax for AllocDM #2
-- 6. Try make_syscall(20) = getpid
-- 7. If both work → native handler is alive, only memory.* is broken
-- 8. If both crash → native handler is dead after MapDM

print("=== 545g ===")
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

if not libkernel_base then print("FATAL"); return end
print("pid=" .. to_num(syscall.getpid()))

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)

-- Prepare ALL buffers BEFORE MapDM
local phys_out1 = memory.alloc(8)
local phys_out2 = memory.alloc(8)
local virt_out = memory.alloc(8)
wq(phys_out1, uint64(0))
wq(phys_out2, uint64(0))
wq(virt_out, uint64("0x880000000"))

-- Pre-create syscall object
local sc_getpid = make_syscall(20)

-- AllocDM #1
print("A1")
local ok1, rv1 = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out1))
end)
if not ok1 or to_num(rv1) ~= 0 then print("A1 FAIL"); return end
local phys = rq(phys_out1)
print("P=" .. q(phys))

-- MapDM (discard return value completely)
print("MAP")
io.flush()
pcall(function()
    native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

-- Pure Lua marker
print("X")
io.flush()

-- Test 1: native.fcall_with_rax — AllocDM #2
print("T1")
io.flush()
local ok2, rv2 = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out2))
end)
print("T1=" .. tostring(ok2))
io.flush()

-- Test 2: make_syscall getpid (pre-created)
print("T2")
io.flush()
local ok3, rv3 = pcall(sc_getpid)
print("T2=" .. tostring(ok3))
io.flush()

-- Test 3: memory.alloc (just C malloc, no native handler?)
print("T3")
io.flush()
local ok4, rv4 = pcall(memory.alloc, 8)
print("T3=" .. tostring(ok4))
io.flush()

-- Test 4: memory.write_dword (C function)
print("T4")
io.flush()
local ok5 = pcall(function() memory.write_dword(phys_out2, 0x42) end)
print("T4=" .. tostring(ok5))
io.flush()

-- Test 5: memory.read_dword (C function)
print("T5")
io.flush()
local ok6 = pcall(function() return memory.read_dword(phys_out2) end)
print("T5=" .. tostring(ok6))
io.flush()

print("DONE")
