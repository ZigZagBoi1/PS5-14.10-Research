-- CRASH_CLASS: LOW
-- PROBE 1424a: the socket families that need a non-zero protocol, and the
--             non-stream/dgram/raw socket types
--
-- prior art:
--   results/phase36_realargs/1423a_af_space_20261109_160029.txt
--     family sweep with proto 0 and types 1/2/3 only. Every family except
--     AF_UNIX(1), AF_INET(2), AF_ROUTE(17) and AF_INET6(28) answered -1.
--     FreeBSD 11 numbering (sys/socket.h): 28 AF_INET6, 29 AF_NATM, 30 AF_ATM,
--     32 AF_NETGRAPH, 35 AF_ARP, 36 AF_BLUETOOTH, 40 AF_INET_SDP, 42 AF_INET6_SDP.
--     So netgraph(32) is genuinely refused, but PF_KEY (pseudo_AF_KEY 27,
--     SOCK_RAW, PF_KEY_V2=2), AF_BLUETOOTH(36) with proto 1/2 and AF_INET_SDP(40)
--     were never asked with their real protocols.
--   results/48a_sctp_ipv6_icmp_20261016_201145.txt lines 29-36 attempted family 32
--     for netgraph/bluetooth, i.e. the wrong numbers for bluetooth.
--   No probe in the tree has ever used SOCK_SEQPACKET(5) or SOCK_RDM(4).
--
-- Why it matters: PF_KEY is a message parser with its own SADB command surface;
-- a game process that can open it gains a whole kernel subsystem. SOCK_SEQPACKET
-- on AF_UNIX is a distinct FreeBSD code path (unp_connect/disconnect on a
-- sequenced stream) that no probe has touched.
--
-- Shape: numbers only, no user pointer, so nothing can fault on an argument.

print("=== PROBE 1424a: SOCKET FAMILY/PROTO/TYPE MATRIX ===")

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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local sc_sock = make_syscall(97)

local function try(af, stype, proto)
    local rv
    local ok = pcall(function()
        rv = sc_sock(uint64(af), uint64(stype), uint64(proto), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return nil, "EXC" end
    local n = to_num(rv)
    if n == 0xFFFFFFFF or n < 0 then return -1, es() end
    return n, ""
end

local spec = {
    -- PF_KEY: the only protocol value the family accepts
    { 27, 3, 2,  "PF_KEY SOCK_RAW PF_KEY_V2" },
    { 27, 3, 1,  "PF_KEY proto 1" },
    { 27, 2, 2,  "PF_KEY dgram PF_KEY_V2" },
    -- bluetooth
    { 36, 3, 1,  "AF_BLUETOOTH raw HCI" },
    { 36, 3, 2,  "AF_BLUETOOTH raw L2CAP" },
    { 36, 1, 2,  "AF_BLUETOOTH stream L2CAP" },
    { 36, 3, 3,  "AF_BLUETOOTH raw SCO" },
    -- ATM / NATM
    { 30, 3, 0,  "AF_ATM raw" },
    { 29, 3, 0,  "AF_NATM raw" },
    -- netgraph, both types, both protocols
    { 32, 3, 1,  "AF_NETGRAPH raw NG_CONTROL" },
    { 32, 3, 2,  "AF_NETGRAPH raw NG_DATA" },
    -- SDP variants
    { 40, 1, 0,  "AF_INET_SDP stream" },
    { 42, 1, 0,  "AF_INET6_SDP stream" },
    -- IEEE80211
    { 37, 3, 0,  "AF_IEEE80211 raw" },
    -- AF_LINK with every type
    { 18, 1, 0,  "AF_LINK stream" },
    { 18, 2, 0,  "AF_LINK dgram" },
    { 18, 3, 0,  "AF_LINK raw" },
    -- XTP / RTIP / PIP pseudos
    { 19, 2, 0,  "pseudo_AF_XTP" },
    { 25, 3, 0,  "pseudo_AF_PIP raw" },
    -- AF_ARP
    { 35, 3, 0,  "AF_ARP raw" },
}

print("")
print("[A] family/protocol pairs")
for _, s in ipairs(spec) do
    io.write(string.format("  (%2d,%d,%d) %-30s ... ", s[1], s[2], s[3], s[4])); io.flush()
    local fd, err = try(s[1], s[2], s[3])
    if fd == nil then print("EXC")
    elseif fd == -1 then print("-1  " .. err)
    else print("fd=" .. fd) end
end

print("")
print("[B] SOCK_RDM(4) and SOCK_SEQPACKET(5) across the families that opened")
local tspec = { 4, 5 }
for _, af in ipairs({ 1, 2, 17, 28, 27 }) do
    for _, st in ipairs(tspec) do
        io.write(string.format("  (%2d,%d,0) ... ", af, st)); io.flush()
        local fd, err = try(af, st, 0)
        if fd == nil then print("EXC")
        elseif fd == -1 then print("-1  " .. err)
        else print("fd=" .. fd) end
    end
end
-- PF_KEY and unix with seqpacket/rdm and their real protos
for _, s in ipairs({ { 27, 5, 2 }, { 27, 4, 2 }, { 1, 5, 0 }, { 32, 5, 1 }, { 32, 4, 1 } }) do
    io.write(string.format("  (%2d,%d,%d) ... ", s[1], s[2], s[3])); io.flush()
    local fd, err = try(s[1], s[2], s[3])
    if fd == nil then print("EXC")
    elseif fd == -1 then print("-1  " .. err)
    else print("fd=" .. fd) end
end

print("")
print("[C] SOCK_CLOEXEC / SOCK_NONBLOCK flags (0x10000000 / 0x20000000) if honoured")
for _, st in ipairs({ 0x10000001, 0x20000002, 0x30000002 }) do
    io.write(string.format("  socket(2,%d,0) ... ", st)); io.flush()
    local fd, err = try(2, st, 0)
    if fd == nil then print("EXC")
    elseif fd == -1 then print("-1  " .. err)
    else print("fd=" .. fd) end
end

print("")
print("=== PROBE 1424a COMPLETE ===")
