-- 14.10 Probe 36: bind() port sweep
-- Goal: unblock fragment reassembly testing (Finding 8) by mapping which
-- ports actually bind on loopback for UDP and TCP listeners.
-- Safe: no crash primitives, pure bind/close cycles.

print("=== 36: BIND PORT SWEEP ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socket = 97,
    sc_bind = 104,
    sc_close = 6,
    sc_listen = 106,
    sc_setsockopt = 105,
})

local function make_sockaddr_in(ip_a, ip_b, ip_c, ip_d, port)
    local sa = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(sa + i, 0) end
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)        -- AF_INET
    memory.write_byte(sa + 2, math.floor(port / 256))
    memory.write_byte(sa + 3, port % 256)
    memory.write_byte(sa + 4, ip_a)
    memory.write_byte(sa + 5, ip_b)
    memory.write_byte(sa + 6, ip_c)
    memory.write_byte(sa + 7, ip_d)
    return sa
end

-- Candidate ports: known-good from probe 34 (31337/31338), loader-adjacent,
-- low/system ports, ephemeral range, and edge cases.
local ports = {
    0,      -- ephemeral: let kernel pick
    1, 53, 80, 443, 1023, 1024,
    5000, 8080, 9026, 9027,
    31337, 31338, 31339, 31340,
    40000, 49152, 50000, 60000, 65534, 65535,
}

print("")
print("--- UDP bind sweep (127.0.0.1) ---")
local udp_ok = {}
for _, p in ipairs(ports) do
    local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 2, 17) end)
    local fd = ok_s and rv_s:tonumber() or -1
    if fd >= 0 then
        local sa = make_sockaddr_in(127, 0, 0, 1, p)
        local ok_b, rv_b = pcall(function() return syscall.sc_bind(fd, sa, 16) end)
        local rv = ok_b and rv_b:tonumber() or -999
        print(string.format("UDP bind port %5d: rv=%d", p, rv))
        if rv == 0 then table.insert(udp_ok, p) end
        pcall(function() syscall.sc_close(fd) end)
    else
        print(string.format("UDP bind port %5d: SOCKET FAILED", p))
    end
end

print("")
print("--- TCP bind+listen sweep (127.0.0.1) ---")
local tcp_ok = {}
for _, p in ipairs(ports) do
    local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 1, 6) end)
    local fd = ok_s and rv_s:tonumber() or -1
    if fd >= 0 then
        local sa = make_sockaddr_in(127, 0, 0, 1, p)
        local ok_b, rv_b = pcall(function() return syscall.sc_bind(fd, sa, 16) end)
        local rv = ok_b and rv_b:tonumber() or -999
        local lrv = -1
        if rv == 0 then
            local ok_l, rv_l = pcall(function() return syscall.sc_listen(fd, 4) end)
            lrv = ok_l and rv_l:tonumber() or -999
            table.insert(tcp_ok, p)
        end
        print(string.format("TCP bind port %5d: rv=%d listen=%d", p, rv, lrv))
        pcall(function() syscall.sc_close(fd) end)
    else
        print(string.format("TCP bind port %5d: SOCKET FAILED", p))
    end
end

-- Also test bind on INADDR_ANY (0.0.0.0) for a known-good port, in case
-- the restriction is address-specific rather than port-specific.
print("")
print("--- INADDR_ANY comparison ---")
for _, p in ipairs({31338, 9027}) do
    local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 2, 17) end)
    local fd = ok_s and rv_s:tonumber() or -1
    if fd >= 0 then
        local sa = make_sockaddr_in(0, 0, 0, 0, p)
        local ok_b, rv_b = pcall(function() return syscall.sc_bind(fd, sa, 16) end)
        print(string.format("UDP bind 0.0.0.0:%d: rv=%d", p, ok_b and rv_b:tonumber() or -999))
        pcall(function() syscall.sc_close(fd) end)
    end
end

-- Double-bind test: does SO_REUSEADDR change anything? (rebind same port twice)
print("")
print("--- SO_REUSEADDR double-bind ---")
local f1 = -1
local ok1, rv1 = pcall(function() return syscall.sc_socket(2, 2, 17) end)
f1 = ok1 and rv1:tonumber() or -1
if f1 >= 0 then
    local sa = make_sockaddr_in(127, 0, 0, 1, 31338)
    local okb1, rvb1 = pcall(function() return syscall.sc_bind(f1, sa, 16) end)
    print("first bind: rv=" .. (okb1 and rvb1:tonumber() or -999))
    local ok2, rv2 = pcall(function() return syscall.sc_socket(2, 2, 17) end)
    local f2 = ok2 and rv2:tonumber() or -1
    if f2 >= 0 then
        local v = memory.alloc(4)
        memory.write_dword(v, 1)
        pcall(function() syscall.sc_setsockopt(f2, 0xFFFF, 0x0004, v, 4) end) -- SO_REUSEADDR
        local okb2, rvb2 = pcall(function() return syscall.sc_bind(f2, sa, 16) end)
        print("second bind (REUSEADDR): rv=" .. (okb2 and rvb2:tonumber() or -999))
        pcall(function() syscall.sc_close(f2) end)
    end
    pcall(function() syscall.sc_close(f1) end)
end

print("")
print("--- SUMMARY ---")
local s = "UDP bindable: "
for _, p in ipairs(udp_ok) do s = s .. p .. " " end
print(s)
s = "TCP bindable: "
for _, p in ipairs(tcp_ok) do s = s .. p .. " " end
print(s)
print("=== 36 DONE ===")
