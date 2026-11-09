-- CRASH_CLASS: LOW
-- PROBE 544r: MapDirectMemory — write test (no reads) after call
--
-- ALL prior probes crash at memory.read_dword after MapDM.
-- Test: can we memory.write_dword after MapDM?
-- If yes → reads use native handler, writes don't.
-- Then: write a pattern to mapped page, make a SECOND connection to read it.
--
-- Also: since rv=0, MapDM maps phys→virt. We set *virt_out=0 so MapDM
-- chooses the virtual address. But we can't READ where it chose.
--
-- Alternative: pre-set *virt_out to a specific address and hope MapDM
-- maps there (address hint semantics).
-- Then: write to that known address directly, without reading virt_out.

print("=== 544r: MapDM WRITEONLY ===")
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

-- Pre-set virt_out to 0 (let MapDM choose)
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- MapDM
print("MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)
print("ok=" .. tostring(ok_m))
if ok_m then print("rv=" .. to_num(mrv)) end

-- Test 1: Can we write_dword to a known heap address?
print("T1:wd_heap")
local heap_test = memory.alloc(8)
local ok1 = pcall(function() memory.write_dword(heap_test, 0xAAAAAAAA) end)
print("  " .. tostring(ok1))

-- Test 2: Can we write_qword?
print("T2:wq_heap")
local ok2 = pcall(function() memory.write_qword(heap_test, uint64(0xBBBBBBBB)) end)
print("  " .. tostring(ok2))

-- Test 3: Can we call tostring on a Lua value?
print("T3:tostring")
print("  " .. tostring(42))
print("  " .. tostring("hello"))

-- Test 4: string.format
print("T4:format")
print(string.format("  x=%d", 12345))

-- Test 5: write_dword to virt_out address
-- This writes to the buffer that MapDM wrote to.
-- If MapDM wrote a new virtual address there, this overwrites it.
print("T5:wd_virt_out")
local ok5 = pcall(function() memory.write_dword(virt_out, 0xDEAD) end)
print("  " .. tostring(ok5))

-- Test 6: pcall of memory.read_dword (the one that always crashes)
print("T6:rd_heap")
local ok6, v6 = pcall(function() return memory.read_dword(heap_test) end)
print("  ok=" .. tostring(ok6))
if ok6 then print("  v=" .. to_num(v6)) end

-- Test 7: simple arithmetic on mrv (is the uint64 object valid?)
if ok_m and mrv then
    print("T7:mrv")
    local ok7 = pcall(function()
        local x = to_num(mrv)
        print("  n=" .. x)
    end)
    print("  ok=" .. tostring(ok7))
end

-- Test 8: syscall.getpid (uses native handler)
print("T8:getpid")
local ok8, pid8 = pcall(function() return syscall.getpid() end)
print("  ok=" .. tostring(ok8))
if ok8 then print("  pid=" .. to_num(pid8)) end

print("=== DONE ===")
