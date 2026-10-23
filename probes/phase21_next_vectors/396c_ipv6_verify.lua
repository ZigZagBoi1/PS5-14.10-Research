-- CRASH_CLASS: LOW
-- PROBE 396c: verify IPv6 setsockopt basics
--
-- 396b showed 0 working options. But prior evidence (50e3) claims 4/10/11/27 work.
-- Verify with explicit debug on specific options + different socket types.

print("=== PROBE 396c: ipv6 verify ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Test 3 socket types
local types = {
    {name="DGRAM", domain=28, stype=2, proto=0},
    {name="STREAM", domain=28, stype=1, proto=0},
    {name="RAW", domain=28, stype=3, proto=58},  -- ICMPv6
}

local buf = memory.alloc(16)
local lenp = memory.alloc(8)

for _, st in ipairs(types) do
    local ok_s, rv_s = pcall(function()
        return mk(97)(uint64(st.domain), uint64(st.stype), uint64(st.proto))
    end)
    local fd = ok_s and N(rv_s) or -1
    print(string.format("%s fd=%d", st.name, fd))

    if fd >= 0 then
        -- Test specific options: IPV6_HOPLIMIT(4), MULTICAST_HOPS(10),
        -- MULTICAST_LOOP(11), V6ONLY(27), 2292PKTOPTIONS(25)
        local opts = {4, 10, 11, 25, 27, 36, 49, 50, 51}
        local names = {"HOPLIMIT", "MC_HOPS", "MC_LOOP", "2292PKTOPT", "V6ONLY",
                       "RECVPKTINFO", "HOPOPTS", "DSTOPTS", "RTHDR"}

        for i, opt in ipairs(opts) do
            -- setsockopt with 4 bytes, value=1
            wd(N(buf), 1)
            wd(N(buf)+4, 0)
            local ok1, rv1 = pcall(function()
                return mk(105)(uint64(fd), uint64(41), uint64(opt), buf, uint64(4))
            end)
            local r1 = -999
            if ok1 then r1 = N(rv1) end

            -- getsockopt
            wq(lenp, uint64(16))
            wd(N(buf), 0xCC)
            wd(N(buf)+4, 0xCC)
            local ok2, rv2 = pcall(function()
                return mk(118)(uint64(fd), uint64(41), uint64(opt), buf, lenp)
            end)
            local r2 = -999
            if ok2 then r2 = N(rv2) end
            local glen = rd(N(lenp)) or 0
            local gval = rd(N(buf)) or 0

            print(string.format("  %12s(%2d): set=%2d get=%2d glen=%d val=%X",
                names[i], opt, r1, r2, glen, gval))

            if not alive() then print("DEAD!"); return end
        end

        -- close
        pcall(function() mk(6)(uint64(fd)) end)
    end
    print("")
end

-- Also try: TCP socket with IPV6
local ok_tcp, rv_tcp = pcall(function()
    return mk(97)(uint64(28), uint64(1), uint64(6))  -- AF_INET6, SOCK_STREAM, IPPROTO_TCP
end)
local tcp_fd = ok_tcp and N(rv_tcp) or -1
print(string.format("TCP6 fd=%d", tcp_fd))
if tcp_fd >= 0 then
    for _, opt in ipairs({4, 10, 11, 27}) do
        wd(N(buf), 1)
        local ok1, rv1 = pcall(function()
            return mk(105)(uint64(tcp_fd), uint64(41), uint64(opt), buf, uint64(4))
        end)
        print(string.format("  opt %2d: set=%d", opt, ok1 and N(rv1) or -999))
    end
    pcall(function() mk(6)(uint64(tcp_fd)) end)
end

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 396c COMPLETE ===")
