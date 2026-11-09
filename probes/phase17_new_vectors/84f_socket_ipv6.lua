-- CRASH_CLASS: LOW
-- PROBE 84f: Test IPv6 socket creation and setsockopt for kernel R/W setup
-- syscall.getpid() works, so the chain is functional.
-- Now test the pieces needed for ipv6_kernel_rw.

print("=== PROBE 84f: SOCKET IPV6 ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

-- Step 1: getpid
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Step 2: Create IPv6 UDP socket
print("--- SOCKET ---")
local ok1, ret1 = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(17))
end)
print("socket ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
if not ok1 then
    print("err=" .. tostring(ret1))
    print("=== PROBE 84f COMPLETE ===")
    return
end
local fd1 = to_num(ret1)
print("fd1=" .. fd1)

-- Step 3: setsockopt IPV6_PKTINFO
print("--- SETSOCKOPT ---")
local optval = memory.alloc(4)
memory.write_dword(optval, 1)
local ok2, ret2 = pcall(function()
    return syscall.setsockopt(uint64(fd1), uint64(41), uint64(46),
        uint64(optval), uint64(4))
end)
print("setsockopt ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

-- Step 4: Create a second socket
local ok3, ret3 = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(17))
end)
print("socket2 ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))
local fd2 = ok3 and to_num(ret3) or -1
print("fd2=" .. fd2)

-- Step 5: Create pipe pair
print("--- PIPE ---")
local pipebuf = memory.alloc(8)
memory.write_dword(pipebuf, 0)
memory.write_dword(pipebuf + 4, 0)
local ok4, ret4 = pcall(function()
    return syscall.pipe(uint64(pipebuf))
end)
print("pipe ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))
local pipe_rd = to_num(memory.read_dword(pipebuf))
local pipe_wr = to_num(memory.read_dword(pipebuf + 4))
print("pipe_fds=" .. pipe_rd .. "," .. pipe_wr)

-- Step 6: Get fd data addr (this is what ipv6_kernel_rw uses)
-- ipv6_kernel_rw.get_fd_data_addr needs kernel R/W to work
-- But we can try to get the socket's kernel address through other means

-- Step 7: Check if dynlib_get_info gives us the process's file descriptor table
print("--- PROC INFO ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = syscall.collect_info
if sc_info then
    print("collect_info=" .. tostring(sc_info))
end

-- Clean up
pcall(function() syscall.close(uint64(fd1)) end)
pcall(function() syscall.close(uint64(fd2)) end)
if pipe_rd > 0 then pcall(function() syscall.close(uint64(pipe_rd)) end) end
if pipe_wr > 0 then pcall(function() syscall.close(uint64(pipe_wr)) end) end

print("=== PROBE 84f COMPLETE ===")
