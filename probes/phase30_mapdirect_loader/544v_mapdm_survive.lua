-- CRASH_CLASS: LOW
-- PROBE 544v: MapDirectMemory — minimal survival test after MapDM
--
-- Tests in order after MapDM:
-- 1. Pure Lua (known to work)
-- 2. make_syscall getpid
-- 3. native.fcall_with_rax (another AllocDM call)
-- 4. memory.read_dword (known to crash — last)

print("=== 544v: SURVIVE ===")
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

-- AllocDM
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a or to_num(arv) ~= 0 then print("ALLOC FAIL"); return end
local phys = rq(phys_out)
print("P=" .. q(phys))

-- Prep virt_out
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- Also grab a heap address for later testing
local heap_test = memory.alloc(8)
pcall(function() memory.write_dword(heap_test, 0x12345678) end)
-- Verify pre-MapDM read works
local pre_val = rq(heap_test)
print("pre=" .. (pre_val and q(pre_val) or "nil"))

-- ========= MapDM =========
print("M")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

-- T1: Pure Lua
print("1:" .. tostring(1+1))
print("1:ok=" .. tostring(ok_m))
if ok_m then print("1:rv=" .. to_num(mrv)) end

-- T2: make_syscall(20) = getpid
print("2")
io.flush()
local ok2, r2 = pcall(function()
    local sc = make_syscall(20)
    return sc()
end)
print("2:ok=" .. tostring(ok2))
if ok2 then print("2:pid=" .. to_num(r2)) end

-- T3: native.fcall_with_rax (second AllocDM)
print("3")
io.flush()
local phys_out2 = memory.alloc(8)  -- this is memory.alloc, not read/write
wq(phys_out2, uint64(0))           -- wq uses pcall
local ok3, r3 = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out2))
end)
print("3:ok=" .. tostring(ok3))
if ok3 then print("3:rv=" .. to_num(r3)) end

-- T4: memory.alloc (C func, no native handler?)
print("4")
io.flush()
local ok4, a4 = pcall(function() return memory.alloc(8) end)
print("4:ok=" .. tostring(ok4))

-- T5: memory.read_dword on PRE-EXISTING heap buffer (not virt_out)
print("5")
io.flush()
local ok5, v5 = pcall(function() return memory.read_dword(heap_test) end)
print("5:ok=" .. tostring(ok5))
if ok5 then print("5:v=" .. to_num(v5)) end

-- T6: memory.read_qword on virt_out (the MapDM output)
print("6")
io.flush()
local ok6, v6 = pcall(function() return memory.read_qword(virt_out) end)
print("6:ok=" .. tostring(ok6))
if ok6 then print("6:v=" .. q(v6)) end

print("=== DONE ===")
