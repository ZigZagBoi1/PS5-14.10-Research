-- CRASH_CLASS: MODERATE
-- PROBE 805a: walk CTL_NET for the PF_UNIX / PF_INET pcblist and stats nodes
--
-- tests 43e/53b covered CTL_KERN and PF_ROUTE.  FreeBSD's net.local.<proto>.pcblist
-- returns struct xsocket records whose so_pcb / xso_so fields are kernel pointers in
-- older branches, and pcblist nodes survived as read-only reports well after that.
-- Every successful node is scanned for a qword in 0xFFFF8000_00000000-0xFFFFFFFF_FFFFFFFF.
print("=== PROBE 805a: CTL_NET PCB / STATS SWEEP ===")
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
local function wr(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rdd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local getpid = make_syscall(20)
local sc_sysctl = make_syscall(202)
pcall(function() return getpid() end)
local BUFSZ = 0x4000
local buf = memory.alloc(BUFSZ)
local mib = memory.alloc(0x20)
local oldlenp = memory.alloc(16)
local function zero(p, n) for i = 0, n - 1, 4 do wr(p + i, 0) end end
local function scan(n)
    local hits = 0
    local first = nil
    for i = 0, n - 8, 8 do
        local lo, hi = rdd(buf + i), rdd(buf + i + 4)
        if lo and hi then
            if hi >= 0xFFFF8000 and not (hi == 0xFFFFFFFF and (lo == 0 or lo == 0xFFFFFFFF)) then
                hits = hits + 1
                if not first then first = string.format("%X:%08X%08X", i, hi, lo) end
            end
        end
    end
    return hits, first
end
local function call(label, n, a, b, c)
    zero(mib, 0x20)
    wr(mib, n)
    if a then wr(mib + 4, a) end
    if b then wr(mib + 8, b) end
    if c then wr(mib + 12, c) end
    zero(oldlenp, 16)
    wr(oldlenp, BUFSZ)
    local ok, rv = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(buf), uint64(oldlenp), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  %-34s pcall-fail", label))
        return "pcall"
    end
    local r = to_num(rv)
    local got = rdd(oldlenp + 4) or 0
    if r ~= 0 then
        print(string.format("  %-34s ret=%-3s", label, tostring(r)))
        return r
    end
    local hits, first = scan(got < BUFSZ and got or BUFSZ)
    print(string.format("  %-34s ret=0 len=%-5d kptr=%d %s", label, got, hits, first or ""))
    return 0
end
print("[A] CTL_NET top level")
call("net.0", 4, 0)
call("net.1 pfinet-like", 4, 1)
print("")
print("[B] PF_UNIX (1) subtree")
for node = 0, 6 do
    call("net.1." .. node, 4, 1, node)
    for sub = 0, 3 do
        call("net.1." .. node .. "." .. sub, 4, 1, node, sub)
    end
end
print("")
print("[C] PF_INET (2) and PF_INET6 (28) subtree")
for _, pf in ipairs({2, 28, 30, 36, 37}) do
    for node = 0, 4 do
        call(string.format("net.%d.%d", pf, node), 4, pf, node)
        for sub = 0, 2 do
            call(string.format("net.%d.%d.%d", pf, node, sub), 4, pf, node, sub)
        end
    end
end
print("")
print("[D] alive pid=" .. to_num(getpid()))
