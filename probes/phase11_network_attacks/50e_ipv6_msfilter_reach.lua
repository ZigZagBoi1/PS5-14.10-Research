-- CRASH_CLASS: MODERATE
-- PROBE 50e: IPV6_MSFILTER reachability (CVE-2026-49412)
--
-- Context: upstream FreeBSD fixed a use-after-free in in6p_set_source_filters(),
-- the IPV6_MSFILTER handler, in ce2b95932ec2 (SA-26:29). The option was never
-- issued on 14.10: the 31 sockopt sweep covers gets for options 1-73 and only
-- three IPv6 sets (1, 63, 50). This probe does NOT attempt the race. It answers
-- the prior question: is a handler present behind option 74, and is it shaped
-- like upstream? See docs/CVE-2026-49412-PS5-14.10.md.
--
-- Layout: sockaddr_storage (128), __msfilterreq (12 + 128 + 8 = 148).

print("=== PROBE 50e: IPV6_MSFILTER REACHABILITY ===")
print("")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function safe_close(sc_close, fd)
    if fd and fd >= 0 then pcall(function() sc_close(uint64(fd)) end) end
end

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_UDP = 17
local IPPROTO_IPV6 = 41
local IPPROTO_IP = 0
local IPV6_MSFILTER = 74
local IP_MSFILTER = 74
local IPV6_JOIN_GROUP = 12
local IPV6_LEAVE_GROUP = 13
local MCAST_INCLUDE = 1
local MSFR_SIZE = 148
local SS_SIZE = 128
local SIN6_SIZE = 28

local sc_socket = make_syscall(97)
local sc_close = make_syscall(6)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)

local function tag_call(name, fn)
    print("  [BEFORE] " .. name)
    local ok, rv = pcall(fn)
    if ok then
        print(string.format("  [RETURNED] %s rv=%s", name, tostring(rv)))
        return true, to_num(rv)
    end
    print(string.format("  [RAISED] %s err=%s", name, tostring(rv)))
    return false, -999
end

-- sockaddr_in6 at buf: len(1) family(1) port(2) flow(4) addr(16) scope(4).
local function write_sin6(buf, b0, b1)
    for i = 0, SS_SIZE - 1 do safe_wb(buf + i, 0) end
    safe_wb(buf, SIN6_SIZE)      -- ss_len / sin6_len = 28
    safe_wb(buf + 1, AF_INET6)   -- ss_family / sin6_family = 28
    safe_wb(buf + 8, b0)         -- addr[0], e.g. 0xff for multicast
    safe_wb(buf + 9, b1)         -- addr[1]
    safe_wb(buf + 23, 1)         -- addr[15] = 1  (ff02::1)
end

-- __msfilterreq at buf: ifindex(4) fmode(4) nsrcs(4) group(128) srcs_ptr(8).
-- Returns the address of the stored srcs pointer for verification.
local function write_msfr(buf, ifindex, fmode, nsrcs, srcs_ptr)
    for i = 0, MSFR_SIZE - 1 do safe_wb(buf + i, 0) end
    safe_wd(buf, ifindex)
    safe_wd(buf + 4, fmode)
    safe_wd(buf + 8, nsrcs)
    write_sin6(buf + 12, 0xff, 0x02)  -- group = ff02::1 (multicast)
    local lo = srcs_ptr % 4294967296
    local hi = math.floor(srcs_ptr / 4294967296)
    safe_wd(buf + 140, lo)
    safe_wd(buf + 144, hi)
    return buf + 140
end

-- struct ipv6_mreq at buf: addr(16) + ifindex(4).
local function write_mreq6(buf, ifindex)
    for i = 0, 19 do safe_wb(buf + i, 0) end
    safe_wb(buf, 0xff)
    safe_wb(buf + 1, 0x02)
    safe_wb(buf + 15, 1)
    safe_wd(buf + 16, ifindex)
end

print("--- A: UDPv6 socket + join ff02::1 ---")
local ok, fd = pcall(function()
    return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
end)
fd = ok and to_num(fd) or -999
print("  socket(28, DGRAM, UDP) fd=" .. fd)

local joined = false
if fd >= 0 then
    local mreq = memory.alloc(32)
    for _, ifx in ipairs({1, 0}) do
        write_mreq6(mreq, ifx)
        local sok, srv = tag_call(
            string.format("IPV6_JOIN_GROUP if=%d", ifx),
            function()
                return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
                    uint64(IPV6_JOIN_GROUP), uint64(mreq), uint64(20))
            end)
        if sok and srv == 0 then
            joined = true
            print("  joined on ifindex=" .. ifx)
            break
        end
    end
    if not joined then
        print("  NOTE: join failed on if 1 and 0; MSFILTER calls still run "
            .. "to map the handler's early checks")
    end
else
    print("  ABORT: no UDPv6 socket")
end

if fd >= 0 then
    print("")
    print("--- B: MSFILTER with 0 and 1 sources ---")
    local msfr = memory.alloc(256)
    local srcs = memory.alloc(256)
    write_sin6(srcs, 0x20, 0x01)  -- source = 2001::1 (unicast)

    write_msfr(msfr, 1, MCAST_INCLUDE, 0, 0)
    tag_call("MSFILTER nsrcs=0 null-srcs", function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), uint64(msfr), uint64(MSFR_SIZE))
    end)

    write_msfr(msfr, 1, MCAST_INCLUDE, 1, srcs)
    tag_call("MSFILTER nsrcs=1 valid-srcs", function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), uint64(msfr), uint64(MSFR_SIZE))
    end)

    print("")
    print("--- C: malformed registry (expect EINVAL-class) ---")
    write_msfr(msfr, 1, 99, 0, 0)
    tag_call("MSFILTER fmode=99", function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), uint64(msfr), uint64(MSFR_SIZE))
    end)

    -- non-multicast group: clears byte 0 so the group is 0002::1.
    write_msfr(msfr, 1, MCAST_INCLUDE, 0, 0)
    safe_wb(msfr + 12 + 8, 0x00)
    tag_call("MSFILTER group=unicast", function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), uint64(msfr), uint64(MSFR_SIZE))
    end)

    -- wrong sa_len: 16 instead of 28.
    write_msfr(msfr, 1, MCAST_INCLUDE, 0, 0)
    safe_wb(msfr + 12, 16)
    tag_call("MSFILTER ss_len=16", function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), uint64(msfr), uint64(MSFR_SIZE))
    end)

    print("")
    print("--- D: readback ---")
    local out = memory.alloc(256)
    local outlen = memory.alloc(16)
    safe_wd(outlen, 256)
    write_msfr(msfr, 1, MCAST_INCLUDE, 0, 0)
    for i = 0, 255 do safe_wb(out + i, 0) end
    local gok, grv = tag_call("MSFILTER getsockopt", function()
        return sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6),
            uint64(IPV6_MSFILTER), uint64(out), uint64(outlen))
    end)
    if gok and grv == 0 then
        local n0 = safe_rd(out)
        local n4 = safe_rd(out + 4)
        local n8 = safe_rd(out + 8)
        print(string.format("  out[0,4,8]=%s,%s,%s",
            tostring(n0), tostring(n4), tostring(n8)))
    end

    print("")
    print("--- E: v4 parity (IP_MSFILTER, level 0) ---")
    local ok4, fd4 = pcall(function()
        return sc_socket(uint64(2), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
    end)
    fd4 = ok4 and to_num(fd4) or -999
    print("  socket(2, DGRAM, UDP) fd=" .. fd4)
    if fd4 >= 0 then
        -- v4 group 224.0.0.1 in a sockaddr_in inside the storage field.
        for i = 0, MSFR_SIZE - 1 do safe_wb(msfr + i, 0) end
        safe_wd(msfr, 1)
        safe_wd(msfr + 4, MCAST_INCLUDE)
        safe_wd(msfr + 8, 0)
        safe_wb(msfr + 12, 16)       -- sin_len
        safe_wb(msfr + 13, 2)        -- AF_INET
        safe_wb(msfr + 12 + 4, 224)
        safe_wb(msfr + 12 + 7, 1)
        tag_call("IP_MSFILTER nsrcs=0", function()
            return sc_setsockopt(uint64(fd4), uint64(IPPROTO_IP),
                uint64(IP_MSFILTER), uint64(msfr), uint64(MSFR_SIZE))
        end)
        safe_close(sc_close, fd4)
    end

    safe_close(sc_close, fd)
end

print("")
print("=== PROBE 50e COMPLETE ===")
