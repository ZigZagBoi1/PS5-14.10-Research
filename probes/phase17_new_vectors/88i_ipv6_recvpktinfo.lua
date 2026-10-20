-- CRASH_CLASS: LOW
-- PROBE 88i: Test IPV6_RECVPKTINFO(19) and related sockopts
-- The exploit framework uses IPV6_PKTINFO(46) which is blocked.
-- IPV6_RECVPKTINFO(19) might allocate the same pktopts kernel struct.
-- Also try IPV6_2292PKTINFO(1), IPV6_PATHMTU(44), etc.

print("=== PROBE 88i ===")

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

print("pid=" .. to_num(syscall.getpid()))

-- Create IPv6 socket
local sc_socket = make_syscall(97)  -- socket
local sc_setsockopt = make_syscall(105)  -- setsockopt
local sc_getsockopt = make_syscall(118)  -- getsockopt

local fd = nil
local ok_s, ret_s = pcall(function()
    return sc_socket(uint64(28), uint64(2), uint64(0))  -- AF_INET6, SOCK_DGRAM
end)
print("socket ok=" .. tostring(ok_s) .. " ret=" .. tostring(ret_s))
fd = to_num(ret_s)
print("fd=" .. fd)

if fd > 0 then
    -- IPPROTO_IPV6 = 41
    local val_buf = memory.alloc(256)
    local len_buf = memory.alloc(8)

    -- Test various IPv6 socket options
    local opts = {
        {1, "IPV6_2292PKTINFO"},
        {2, "IPV6_2292HOPOPTS"},
        {3, "IPV6_2292DSTOPTS"},
        {4, "IPV6_2292RTHDR"},
        {6, "IPV6_CHECKSUM"},
        {19, "IPV6_RECVPKTINFO"},
        {20, "IPV6_RECVHOPLIMIT"},
        {21, "IPV6_RECVRTHDR"},
        {22, "IPV6_RECVHOPOPTS"},
        {23, "IPV6_RECVDSTOPTS"},
        {25, "IPV6_RECVPATHMTU"},
        {36, "IPV6_RECVTCLASS"},
        {44, "IPV6_PATHMTU"},
        {46, "IPV6_PKTINFO"},
        {47, "IPV6_HOPLIMIT"},
        {48, "IPV6_NEXTHOP"},
        {49, "IPV6_HOPOPTS"},
        {50, "IPV6_DSTOPTS"},
        {51, "IPV6_RTHDR"},
    }

    for _, opt in ipairs(opts) do
        local optnum, optname = opt[1], opt[2]
        -- Try setsockopt with value=1
        memory.write_dword(val_buf, 1)
        local ok_set, ret_set = pcall(function()
            return sc_setsockopt(uint64(fd), uint64(41), uint64(optnum), uint64(val_buf), uint64(4))
        end)
        local tag_set = ""
        if ok_set then tag_set = "ret=" .. tostring(ret_set) else tag_set = "FAIL" end

        -- Try getsockopt
        memory.write_dword(len_buf, 256)
        for i = 0, 252, 4 do memory.write_dword(val_buf + i, 0) end
        local ok_get, ret_get = pcall(function()
            return sc_getsockopt(uint64(fd), uint64(41), uint64(optnum), uint64(val_buf), uint64(len_buf))
        end)
        local tag_get = ""
        local gotten_len = to_num(memory.read_dword(len_buf))
        if ok_get then tag_get = "ret=" .. tostring(ret_get) .. " len=" .. gotten_len else tag_get = "FAIL" end

        print(string.format("  %2d %-20s set:%s get:%s", optnum, optname, tag_set, tag_get))

        -- If getsockopt returned data, dump it
        if ok_get and gotten_len > 4 then
            local kcount = 0
            for off = 0, gotten_len - 4, 4 do
                local v = to_num(memory.read_dword(val_buf + off))
                if v ~= 0 then
                    print(string.format("    +%02X: 0x%08X", off, v))
                end
            end
        end
    end

    -- PART B: Create second socket and try overlapped allocation
    print("")
    print("--- SECOND SOCKET ---")
    local ok_s2, ret_s2 = pcall(function()
        return sc_socket(uint64(28), uint64(2), uint64(0))
    end)
    local fd2 = to_num(ret_s2)
    print("fd2=" .. fd2)

    -- Set IPV6_RECVPKTINFO on both to force pktopts allocation
    if fd2 > 0 then
        memory.write_dword(val_buf, 1)
        local ok_r1, ret_r1 = pcall(function()
            return sc_setsockopt(uint64(fd), uint64(41), uint64(19), uint64(val_buf), uint64(4))
        end)
        local ok_r2, ret_r2 = pcall(function()
            return sc_setsockopt(uint64(fd2), uint64(41), uint64(19), uint64(val_buf), uint64(4))
        end)
        print("recvpktinfo fd1=" .. tostring(ret_r1) .. " fd2=" .. tostring(ret_r2))
    end
end

print("=== PROBE 88i COMPLETE ===")
