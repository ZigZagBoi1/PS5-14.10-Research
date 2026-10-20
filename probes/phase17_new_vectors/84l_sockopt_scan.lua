-- CRASH_CLASS: LOW
-- PROBE 84l: Scan which setsockopt options work on IPv6 UDP socket

print("=== PROBE 84l ===")
print("pid=" .. tostring(syscall.getpid()))

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local fd = syscall.socket(uint64(28), uint64(2), uint64(17))
print("fd=" .. to_num(fd))

local optbuf = memory.alloc(4)
memory.write_dword(optbuf, 1)

-- Scan IPPROTO_IPV6=41 options
print("--- IPV6 OPTS ---")
local ipv6_names = {
    [1]="IPV6_UNICAST_HOPS", [2]="IPV6_MULTICAST_IF",
    [3]="IPV6_MULTICAST_HOPS", [4]="IPV6_MULTICAST_LOOP",
    [6]="IPV6_V6ONLY", [7]="IPV6_CHECKSUM",
    [8]="IPV6_IPSEC_POLICY", [18]="IPV6_RECVRTHDR",
    [19]="IPV6_RECVPKTINFO", [20]="IPV6_RECVHOPLIMIT",
    [21]="IPV6_RECVRTHDR2", [23]="IPV6_RECVPATHMTU",
    [24]="IPV6_PATHMTU", [25]="IPV6_PKTINFO",
    [26]="IPV6_HOPLIMIT", [27]="IPV6_NEXTHOP",
    [29]="IPV6_HOPOPTS", [32]="IPV6_DSTOPTS",
    [33]="IPV6_RTHDR", [36]="IPV6_RECVDSTOPTS",
    [42]="IPV6_TCLASS", [43]="IPV6_RECVTCLASS",
    [44]="IPV6_USE_MIN_MTU", [45]="IPV6_DONTFRAG",
    [46]="IPV6_PKTINFO_46", [47]="IPV6_47",
    [48]="IPV6_FLOWID", [49]="IPV6_FLOWTYPE",
    [50]="IPV6_RECVFLOWID", [61]="IPV6_ORIGDSTADDR",
    [62]="IPV6_RECVORIGDSTADDR",
}
for opt = 1, 70 do
    memory.write_dword(optbuf, 1)
    local ok, ret = pcall(function()
        return syscall.setsockopt(uint64(to_num(fd)), uint64(41), uint64(opt),
            uint64(optbuf), uint64(4))
    end)
    if ok then
        local rv = to_num(ret)
        local name = ipv6_names[opt] or ""
        if rv == 0 then
            print(string.format("opt %d %s = OK", opt, name))
        end
    end
end

-- Scan SOL_SOCKET=0xFFFF options
print("--- SOL_SOCKET OPTS ---")
local sol_names = {
    [2]="SO_DEBUG", [4]="SO_REUSEADDR", [8]="SO_KEEPALIVE",
    [32]="SO_DONTROUTE", [128]="SO_BROADCAST",
    [256]="SO_SNDBUF", [257]="SO_RCVBUF",
    [4097]="SO_SNDLOWAT", [4098]="SO_RCVLOWAT",
}
for _, opt in ipairs({2,4,8,16,32,64,128,256,257,512,1024,2048,4097,4098,4099,4100,4101}) do
    memory.write_dword(optbuf, 1)
    local ok, ret = pcall(function()
        return syscall.setsockopt(uint64(to_num(fd)), uint64(0xFFFF), uint64(opt),
            uint64(optbuf), uint64(4))
    end)
    if ok then
        local rv = to_num(ret)
        local name = sol_names[opt] or ""
        if rv == 0 then
            print(string.format("sol opt %d %s = OK", opt, name))
        end
    end
end

syscall.close(uint64(to_num(fd)))
print("=== PROBE 84l COMPLETE ===")
