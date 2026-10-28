-- CRASH_CLASS: LOW
-- PROBE 544o: MapDirectMemory — access mapped page directly
--
-- 544n proved: Lua prints A/B/C/D fine after MapDM.
-- Crash happens at memory.read_dword(virt_out).
--
-- Hypothesis 1: memory.read_dword uses native handler internally → crash
-- Hypothesis 2: virt_out page was remapped by MapDM → crash on access
--
-- Tests:
-- A) Set *virt_out = 0x880000000, call MapDM
-- B) Access 0x880000000 directly with memory.write_dword (known C addr)
-- C) Try to access 0x880000000 via string manipulation (pure Lua)
-- D) Also try memory.write_dword first (if write works but read doesn't,
--    it tells us memory.read_dword specifically is the issue)

print("=== 544o: MapDM DIRECTACCESS ===")
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

-- Test: memory.read_dword and memory.write_dword before MapDM
local test_buf = memory.alloc(8)
wd(test_buf, 0x12345678)
local tb = rd(to_num(test_buf))
if tb then
    if tb < 0 then tb = tb + 0x100000000 end
    print("pre-map rd=" .. string.format("0x%X", tb))
end

-- Prepare virt_out pointing to 0x880000000
local virt_out = memory.alloc(8)
wq(virt_out, uint64("0x880000000"))
print("virt_out=" .. q(virt_out))

-- MapDM with hint
print("MAP")
local ok_m = pcall(function()
    native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)
print("ok=" .. tostring(ok_m))

-- Lua is alive. Now carefully test different memory operations.

-- Test 1: memory.write_dword to a DIFFERENT buffer (test_buf, not virt_out)
print("T1:wd_testbuf")
local ok_t1 = pcall(function() memory.write_dword(test_buf, 0xAAAAAAAA) end)
print("  " .. tostring(ok_t1))

-- Test 2: memory.read_dword on test_buf
print("T2:rd_testbuf")
local ok_t2, val_t2 = pcall(function() return memory.read_dword(test_buf) end)
print("  ok=" .. tostring(ok_t2))
if ok_t2 then
    local v = to_num(val_t2)
    if v < 0 then v = v + 0x100000000 end
    print("  v=" .. string.format("0x%X", v))
end

-- Test 3: memory.write_dword to the mapped address directly
print("T3:wd_mapped")
local mapped = uint64("0x880000000")
local ok_t3 = pcall(function() memory.write_dword(mapped, 0xDEADBEEF) end)
print("  " .. tostring(ok_t3))

-- Test 4: memory.read_dword from mapped address
print("T4:rd_mapped")
local ok_t4, val_t4 = pcall(function() return memory.read_dword(mapped) end)
print("  ok=" .. tostring(ok_t4))
if ok_t4 then
    local v = to_num(val_t4)
    if v < 0 then v = v + 0x100000000 end
    print("  v=" .. string.format("0x%X", v))
    if v == 0xDEADBEEF then
        print("  *** MAPPED PAGE R/W WORKS ***")
    end
end

-- Test 5: read virt_out (the one that crashed in 544n)
print("T5:rd_virt_out")
local ok_t5, val_t5 = pcall(function() return memory.read_dword(virt_out) end)
print("  ok=" .. tostring(ok_t5))
if ok_t5 then
    local v = to_num(val_t5)
    if v < 0 then v = v + 0x100000000 end
    print("  v=" .. string.format("0x%X", v))
end

-- Test 6: getpid via syscall (uses native handler)
print("T6:getpid")
local ok_t6, pid_t6 = pcall(function() return syscall.getpid() end)
print("  ok=" .. tostring(ok_t6))
if ok_t6 then print("  pid=" .. to_num(pid_t6)) end

print("=== DONE ===")
