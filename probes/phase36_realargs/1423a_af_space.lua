-- CRASH_CLASS: LOW
-- PROBE 1423a: address-family space - which sockets can a game process create?
--
-- prior art:
--   results/48a_sctp_ipv6_icmp_20261016_201145.txt lines 29-36:
--     "AF_NETGRAPH dgram   FAILED (-1)" and "AF_NETGRAPH stream   FAILED (-1)"
--     were made with family 32 and type 2/1. On FreeBSD 11 family 32 is AF_SYSTEM,
--     not netgraph - AF_NETGRAPH is 30 - so netgraph itself has never been tried.
--     "AF_BLUETOOTH raw/seqpacket FAILED" likewise used family 32.
--   probes/phase4_ipc_network/27_thread_and_fd.lua:328 labels {34,2,0} "AF_NETGRAPH",
--     again the wrong number.
--   results/kernel_handlers/asm/sys_97.asm / sys_97 socket: no family filter was
--     ever measured from userland; the repo's socket work covered INET, INET6,
--     ROUTE, SCTP and exotic IP protocols only.
--
-- Why it matters: AF_NETGRAPH (30) exposes ng_socket plus every loaded node type
-- through sendto/recvfrom with a sockaddr_ng, and PF_SYSTEM (32) exposes
-- SYSPROTO_CONTROL/SYSPROTO_EVENT. Both are large, largely un-audited kernel
-- surfaces; neither is reachable any other way from this process.
--
-- Shape: socket(af, type, proto) with all six syscall arguments as numbers, fd
-- printed. No address is passed, so nothing can fault on a bad user pointer.
-- A family that returns a descriptor opens a new subsystem; -1 closes it.

print("=== PROBE 1423a: ADDRESS FAMILY SPACE ===")

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
-- socket() is BSD 97 (see docs/sysent-names-13.60.csv); the resolve() path is
-- filtered, so it is called through a make_syscall clone.
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

local NAMES = {
    [1]="AF_UNIX",[2]="AF_INET",[3]="AF_IMPLINK",[4]="AF_PUP",[5]="AF_CHAOS",
    [6]="AF_NS",[7]="AF_ISO",[8]="AF_ECMA",[9]="AF_DATAKIT",[10]="AF_CCITT",
    [11]="AF_SNA",[12]="AF_DECnet",[13]="AF_DLI",[14]="AF_LAT",[15]="AF_HYLINK",
    [16]="AF_APPLETALK",[17]="AF_ROUTE",[18]="AF_LINK",[19]="AF_COIP",[20]="AF_CNT",
    [23]="AF_IPX",[24]="AF_SIP",[28]="AF_NATM",[30]="AF_NETGRAPH",[32]="AF_SYSTEM",
    [35]="AF_BLUETOOTH",[44]="AF_INET6",
}

print("")
print("[A] every family 0..45, type SOCK_STREAM(1)/DGRAM(2)/RAW(3), proto 0")
for af = 0, 45 do
    local line = string.format("  %2d %-13s", af, NAMES[af] or "")
    for _, st in ipairs({ 1, 2, 3 }) do
        local fd, err = try(af, st, 0)
        if fd == nil then
            line = line .. "  t" .. st .. "=EXC"
        elseif fd == -1 then
            line = line .. string.format("  t%d=-1", st)
        else
            line = line .. string.format("  t%d=fd%d", st, fd)
        end
    end
    print(line)
end

print("")
print("[B] family-specific protocol values")
local spec = {
    { 30, 3, 1,  "NG_CONTROL" },
    { 30, 3, 2,  "NG_DATA" },
    { 30, 3, 3,  "NG_CONTROL|NG_DATA" },
    { 32, 3, 1,  "SYSPROTO_EVENT" },
    { 32, 3, 2,  "SYSPROTO_CONTROL" },
    { 32, 2, 2,  "SYSPROTO_CONTROL dgram" },
    { 17, 3, 0,  "AF_ROUTE raw" },
    { 18, 2, 0,  "AF_LINK dgram" },
    { 18, 3, 0,  "AF_LINK raw" },
    { 23, 2, 0,  "AF_IPX dgram" },
    { 28, 2, 0,  "AF_NATM dgram" },
    { 2,  1, 132, "AF_INET SCTP" },
    { 44, 1, 132, "AF_INET6 SCTP" },
}
for _, s in ipairs(spec) do
    io.write(string.format("  socket(%d,%d,%d) %-26s ... ", s[1], s[2], s[3], s[4])); io.flush()
    local fd, err = try(s[1], s[2], s[3])
    if fd == nil then
        print("EXC")
    elseif fd == -1 then
        print("-1  " .. err)
    else
        print("fd=" .. fd)
    end
end

print("")
print("=== PROBE 1423a COMPLETE ===")
